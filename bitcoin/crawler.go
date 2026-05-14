package bitcoin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/btcsuite/btcd/wire"
	ma "github.com/multiformats/go-multiaddr"
	manet "github.com/multiformats/go-multiaddr/net"
	log "github.com/sirupsen/logrus"

	"github.com/dennis-tra/nebula-crawler/core"
	"github.com/dennis-tra/nebula-crawler/db"
	pgmodels "github.com/dennis-tra/nebula-crawler/db/models/pg"
)

const MaxCrawlRetriesAfterTimeout = 2 // magic

type CrawlerConfig struct {
	DialTimeout time.Duration
	LogErrors   bool
	Version     string
}

type Crawler struct {
	id           string
	cfg          *CrawlerConfig
	crawledPeers int
	done         chan struct{}
}

var _ core.Worker[PeerInfo, core.CrawlResult[PeerInfo]] = (*Crawler)(nil)

func (c *Crawler) Work(ctx context.Context, task PeerInfo) (core.CrawlResult[PeerInfo], error) {
	logEntry := log.WithFields(log.Fields{
		"crawlerID":  c.id,
		"remoteID":   task.ID().ShortString(),
		"crawlCount": c.crawledPeers,
	})
	defer logEntry.Debugln("Crawled peer")

	crawlStart := time.Now()

	// start crawling
	bitcoinResult := c.crawlBitcoin(ctx, task)

	properties := c.PeerProperties(&bitcoinResult)

	// keep track of all unknown connection errors
	if bitcoinResult.ConnectErrorStr == pgmodels.NetErrorUnknown && bitcoinResult.ConnectError != nil {
		properties["connect_error"] = bitcoinResult.ConnectError.Error()
	}

	// keep track of all unknown crawl errors
	if bitcoinResult.ErrorStr == pgmodels.NetErrorUnknown && bitcoinResult.Error != nil {
		properties["crawl_error"] = bitcoinResult.Error.Error()
	}

	data, err := json.Marshal(properties)
	if err != nil {
		log.WithError(err).WithField("properties", properties).Warnln("Could not marshal peer properties")
	}

	if len(bitcoinResult.ListenAddrs) > 0 {
		task.AddrInfo.Addr = bitcoinResult.ListenAddrs
	}

	cr := core.CrawlResult[PeerInfo]{
		CrawlerID:           c.id,
		Info:                task,
		CrawlStartTime:      crawlStart,
		RoutingTableFromAPI: false,
		RoutingTable:        bitcoinResult.RoutingTable,
		Agent:               bitcoinResult.Agent,
		Protocols:           bitcoinResult.Protocols,
		DialMaddrs:          task.Addrs(),
		ConnectMaddr:        bitcoinResult.ConnectMaddr,
		ListenMaddrs:        bitcoinResult.ListenAddrs,
		ConnectError:        bitcoinResult.ConnectError,
		ConnectErrorStr:     bitcoinResult.ConnectErrorStr,
		CrawlError:          bitcoinResult.Error,
		CrawlErrorStr:       bitcoinResult.ErrorStr,
		CrawlEndTime:        time.Now(),
		ConnectStartTime:    bitcoinResult.ConnectStartTime,
		ConnectEndTime:      bitcoinResult.ConnectEndTime,
		Properties:          data,
		LogErrors:           c.cfg.LogErrors,
	}

	// We've now crawled this peer, so increment
	c.crawledPeers++

	return cr, nil
}

func (c *Crawler) PeerProperties(result *BitcoinResult) map[string]any {
	return map[string]any{
		"services": result.Services.String(),
	}
}

type BitcoinResult struct {
	ConnectStartTime time.Time
	ConnectEndTime   time.Time
	ConnectError     error
	ConnectErrorStr  string
	ConnectMaddr     ma.Multiaddr
	Agent            string
	ProtocolVersion  int32
	Services         wire.ServiceFlag
	Protocols        []string
	ListenAddrs      []ma.Multiaddr
	Error            error
	ErrorStr         string // It looks like it is not even being used. We could remove it entirely.
	RoutingTable     *core.RoutingTable[PeerInfo]
}

func (c *Crawler) crawlBitcoin(ctx context.Context, pi PeerInfo) BitcoinResult {
	result := BitcoinResult{}
	neighbours := make([]PeerInfo, 0)

	addrs := pi.Addrs()

	var conn net.Conn
	result.ConnectStartTime = time.Now()
	conn, result.ConnectError = c.connect(ctx, addrs)

	if result.ConnectError != nil {
		result.ConnectErrorStr = db.NetError(result.ConnectError)

		result.RoutingTable = &core.RoutingTable[PeerInfo]{
			PeerID:    pi.ID(),
			Neighbors: neighbours,
			ErrorBits: uint16(0), // FIXME
			Error:     result.ConnectError,
		}
		result.Error = result.ConnectError
		result.ErrorStr = result.ConnectErrorStr
		result.ConnectEndTime = time.Now()

		return result
	}

	defer conn.Close()

	if err := conn.SetDeadline(time.Now().Add(180 * time.Second)); err != nil {
		log.WithError(err).Warnln("Could not set connection deadline")

		result.RoutingTable = &core.RoutingTable[PeerInfo]{
			PeerID:    pi.ID(),
			Neighbors: neighbours,
			ErrorBits: uint16(0), // FIXME
			Error:     err,
		}
		result.Error = err
		result.ErrorStr = err.Error()
		result.ConnectEndTime = time.Now()

		return result
	}

	// If we could successfully connect to the peer we actually crawl it.
	if conn != nil {

		tcpAddr, ok := conn.RemoteAddr().(*net.TCPAddr)

		if ok {
			// construct connect maddr if we have received a response
			var ipScheme string
			if p4 := tcpAddr.IP.To4(); len(p4) == net.IPv4len {
				ipScheme = "ip4"
			} else {
				ipScheme = "ip6"
			}

			maddrStr := strings.Join([]string{"", ipScheme, tcpAddr.IP.String(), tcpAddr.Network(), strconv.Itoa(tcpAddr.Port)}, "/")
			maddr, err := ma.NewMultiaddr(maddrStr)
			if err != nil {
				log.WithError(err).WithField("maddr", maddrStr).Warnln("Could not construct connect maddr")
			} else {
				result.ConnectMaddr = maddr
			}
		} else {
			log.WithField("addr", conn.RemoteAddr()).Warnln("Not a TCP address, cannot construct connect maddr")
		}

		nodeRes, err := c.Handshake(conn)
		result.Agent = nodeRes.UserAgent
		result.ProtocolVersion = nodeRes.ProtocolVersion
		result.Services = nodeRes.Services
		if nodeRes.ListenAddr != nil {
			result.ListenAddrs = []ma.Multiaddr{nodeRes.ListenAddr}
		}
		if err != nil {
			result.Error = fmt.Errorf("Handshake failed")
			result.ErrorStr = result.Error.Error()

			return result
		}

		err = c.WriteMessage(conn, wire.NewMsgGetAddr())
		if err != nil {
			result.Error = err
			result.ErrorStr = result.Error.Error()

			return result
		}

	Loop:
		for {
			// Read messages in a loop and handle the different message types accordingly
			msg, _, err := c.ReadMessage(conn)
			if err != nil {
				if errors.Is(err, wire.ErrUnknownMessage) {
					log.WithField("addr", pi.Addr).Debugln("Received unknown message, skipping")
					continue
				}

				result.Error = err
				result.ErrorStr = err.Error()
				break Loop
			}

			switch tmsg := msg.(type) {
			case *wire.MsgAddr:
				peers := processAddrs(tmsg.AddrList)
				neighbours = append(neighbours, peers...)
				if len(tmsg.AddrList) < wire.MaxAddrPerMsg {
					break Loop
				}
				if err = c.requestMoreAddrs(ctx, conn); err != nil {
					log.WithField("error", err).Errorf("Error when requesting peers")
					break Loop
				}
			case *wire.MsgAddrV2:
				peers := processAddrsV2(tmsg.AddrList)
				neighbours = append(neighbours, peers...)
				if len(tmsg.AddrList) < wire.MaxAddrPerMsg {
					break Loop
				}
				if err = c.requestMoreAddrs(ctx, conn); err != nil {
					log.WithField("error", err).Errorf("Error when requesting peers")
					break Loop
				}
			case *wire.MsgPing:
				if err = c.WriteMessage(conn, wire.NewMsgPong(tmsg.Nonce)); err != nil {
					log.Errorf("Pong msg err: %s", err)
					break Loop
				}
			default:
				if tmsg != nil {
					log.WithField("msg_type", tmsg.Command()).Debugf("Found other message from %s", pi.Addr)
				}
			}
		}

		if len(neighbours) > 0 {
			log.WithField("num_peers", len(neighbours)).WithField("addr", pi.Addr).Infoln("Found peers")
		} else {
			log.WithField("addr", pi.Addr).Infoln("Found no peers")
		}

	}

	result.RoutingTable = &core.RoutingTable[PeerInfo]{
		PeerID:    pi.ID(),
		Neighbors: neighbours,
		ErrorBits: uint16(0),
		Error:     result.Error,
	}

	if result.Error != nil {
		result.ErrorStr = db.NetError(result.Error)
	}

	return result
}

type BitcoinNodeResult struct {
	ProtocolVersion int32
	UserAgent       string
	Services        wire.ServiceFlag
	ListenAddr      ma.Multiaddr
	pver            int32
}

func (c *Crawler) Handshake(conn net.Conn) (BitcoinNodeResult, error) {
	result := BitcoinNodeResult{}
	if conn == nil {
		return result, fmt.Errorf("peer is not connected, can't handshake")
	}

	log.WithField("Address", conn.RemoteAddr()).Debug("Starting handshake.")

	nonce, err := wire.RandomUint64()
	if err != nil {
		return result, err
	}

	localAddr := wire.NewNetAddressIPPort(
		conn.LocalAddr().(*net.TCPAddr).IP,
		uint16(conn.LocalAddr().(*net.TCPAddr).Port),
		wire.SFNodeNetwork,
	)
	remoteAddr := wire.NewNetAddressIPPort(
		conn.RemoteAddr().(*net.TCPAddr).IP,
		uint16(conn.RemoteAddr().(*net.TCPAddr).Port),
		wire.SFNodeNetwork,
	)

	msgVersion := wire.NewMsgVersion(localAddr, remoteAddr, nonce, 0)

	msgVersion.ProtocolVersion = int32(wire.ProtocolVersion)
	msgVersion.Services = wire.SFNodeNetwork
	msgVersion.Timestamp = time.Now()
	msgVersion.UserAgent = "nebula/" + c.cfg.Version

	if err := c.WriteMessage(conn, msgVersion); err != nil {
		return result, err
	}

	// Read the response version.
	msg, _, err := c.ReadMessage(conn)
	if err != nil {
		return result, err
	}
	vmsg, ok := msg.(*wire.MsgVersion)
	if !ok {
		return result, fmt.Errorf("did not receive version message: %T", vmsg)
	}

	result.ProtocolVersion = vmsg.ProtocolVersion
	result.UserAgent = vmsg.UserAgent
	result.Services = vmsg.Services

	ip := vmsg.AddrMe.IP
	if ip != nil && !ip.IsUnspecified() {
		ipScheme := "ip6"
		if p4 := ip.To4(); p4 != nil {
			ipScheme = "ip4"
			ip = p4
		}
		maddrStr := fmt.Sprintf("/%s/%s/tcp/%d", ipScheme, ip.String(), vmsg.AddrMe.Port)
		if maddr, err := ma.NewMultiaddr(maddrStr); err == nil {
			result.ListenAddr = maddr
		}
	}

	// Negotiate protocol version.
	if uint32(vmsg.ProtocolVersion) < wire.ProtocolVersion {
		result.pver = vmsg.ProtocolVersion
	}
	log.Debugf("[%s] -> Version: %s", conn.RemoteAddr(), vmsg.UserAgent)

	// Normally we'd check if vmsg.Nonce == p.nonce but the crawler does not
	// accept external connections so we skip it.

	// Signal addrv2 support before verack as required by BIP 155.
	// https://bips.dev/155/
	if err := c.WriteMessage(conn, &wire.MsgSendAddrV2{}); err != nil {
		return result, err
	}

	// Send verack.
	if err := c.WriteMessage(conn, wire.NewMsgVerAck()); err != nil {
		return result, err
	}

	return result, nil
}

// requestMoreAddrs waits 30 seconds before sending a getaddr message. Bitcoin
// Core rate-limits getaddr responses and will drop requests that arrive too
// quickly on the same connection.
// https://github.com/bitcoin/bitcoin/blob/8396b7f2a3be4be7bb2ffc152f87b4cab95dd84e/src/net_processing.cpp#L160
func (c *Crawler) requestMoreAddrs(ctx context.Context, conn net.Conn) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(30 * time.Second):
	}
	return c.WriteMessage(conn, wire.NewMsgGetAddr())
}

// connect establishes a connection to the given peer, with one retry on timeout
func (c *Crawler) connect(ctx context.Context, addrs []ma.Multiaddr) (net.Conn, error) {
	if len(addrs) == 0 {
		return nil, nil
	}
	// Skip addresses that require protocols we don't support (e.g. Tor v3 requires a Tor proxy).
	if !manet.IsThinWaist(addrs[0]) {
		return nil, fmt.Errorf("unsupported protocol")
	}
	netAddr, err := manet.ToNetAddr(addrs[0])
	if err != nil {
		return nil, err
	}
	d := net.Dialer{Timeout: c.cfg.DialTimeout}
	conn, err := d.DialContext(ctx, netAddr.Network(), netAddr.String())

	// Retry only if we had a timeout.
	// If the connection is refused by the node retrying would just make the crawler slower.
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		conn, err = d.DialContext(ctx, netAddr.Network(), netAddr.String())
	}
	return conn, err
}

func (c *Crawler) WriteMessage(conn net.Conn, msg wire.Message) error {
	return wire.WriteMessage(conn, msg, wire.ProtocolVersion, wire.MainNet)
}

func (c *Crawler) ReadMessage(conn net.Conn) (wire.Message, []byte, error) {
	return wire.ReadMessage(conn, wire.ProtocolVersion, wire.MainNet)
}

func processAddrs(addrs []*wire.NetAddress) []PeerInfo {
	var peers []PeerInfo
	for _, addr := range addrs {
		ip := addr.IP
		ipScheme := "ip6"
		if p4 := ip.To4(); p4 != nil {
			ipScheme = "ip4"
			ip = p4
		}
		maStr := fmt.Sprintf("/%s/%s/tcp/%d", ipScheme, ip.String(), addr.Port)
		maddr, err := ma.NewMultiaddr(maStr)
		if err != nil {
			continue
		}
		peers = append(peers, PeerInfo{
			AddrInfo: AddrInfo{
				id:   maddr.String(),
				Addr: []ma.Multiaddr{maddr},
			},
		})
	}
	return peers
}

// processAddrsV2 converts BIP 155 addrv2 addresses to PeerInfo entries.
// IPv4, IPv6, and Tor v2 are handled via ToLegacy(). Tor v3 is handled
// natively using the onion3 multiaddr scheme.
// I2P, CJDNS, and Yggdrasil are not supported: btcd discards them during
// wire decoding (ErrSkippedNetworkID) so they never reach this function.
func processAddrsV2(addrs []*wire.NetAddressV2) []PeerInfo {
	var peers []PeerInfo
	for _, addr := range addrs {
		if addr == nil {
			continue
		}

		var maStr string
		if legacy := addr.ToLegacy(); legacy != nil {
			ip := legacy.IP
			ipScheme := "ip6"
			if p4 := ip.To4(); p4 != nil {
				ipScheme = "ip4"
				ip = p4
			}
			maStr = fmt.Sprintf("/%s/%s/tcp/%d", ipScheme, ip.String(), legacy.Port)
		} else if addr.IsTorV3() {
			// addr.Addr.String() returns "<base32>.onion"; strip the suffix for the onion3 multiaddr scheme
			host := strings.TrimSuffix(addr.Addr.String(), ".onion")
			maStr = fmt.Sprintf("/onion3/%s:%d", host, addr.Port)
		} else {
			continue
		}

		maddr, err := ma.NewMultiaddr(maStr)
		if err != nil {
			continue
		}
		peers = append(peers, PeerInfo{
			AddrInfo: AddrInfo{
				id:   maddr.String(),
				Addr: []ma.Multiaddr{maddr},
			},
		})
	}
	return peers
}
