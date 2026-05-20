package bitcoin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
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

	connectErrorStr := db.NetError(bitcoinResult.ConnectError)
	crawlErrorStr := db.NetError(bitcoinResult.Error)

	// keep track of all unknown connection errors
	if connectErrorStr == pgmodels.NetErrorUnknown && bitcoinResult.ConnectError != nil {
		properties["connect_error"] = bitcoinResult.ConnectError.Error()
	}

	// keep track of all unknown crawl errors
	if crawlErrorStr == pgmodels.NetErrorUnknown && bitcoinResult.Error != nil {
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
		ConnectErrorStr:     connectErrorStr,
		CrawlError:          bitcoinResult.Error,
		CrawlErrorStr:       crawlErrorStr,
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
	ConnectMaddr     ma.Multiaddr
	Agent            string
	ProtocolVersion  int32
	Services         wire.ServiceFlag
	Protocols        []string
	ListenAddrs      []ma.Multiaddr
	Error            error
	RoutingTable     *core.RoutingTable[PeerInfo]
}

func (c *Crawler) crawlBitcoin(ctx context.Context, pi PeerInfo) BitcoinResult {
	result := BitcoinResult{}
	neighbours := make([]PeerInfo, 0)

	addrs := pi.Addrs()

	// limit whole crawl of this peer to 3 minutes
	ctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()

	var conn net.Conn
	result.ConnectStartTime = time.Now()
	conn, result.ConnectError = c.connect(ctx, addrs)
	result.ConnectEndTime = time.Now()

	if result.ConnectError != nil {

		result.RoutingTable = &core.RoutingTable[PeerInfo]{
			PeerID:    pi.ID(),
			Neighbors: neighbours,
			ErrorBits: uint16(0), // FIXME
			Error:     result.ConnectError,
		}
		result.Error = result.ConnectError

		return result
	}

	defer conn.Close()

	// If we could successfully connect to the peer we actually crawl it.
	if conn != nil {

		maddr, err := manet.FromNetAddr(conn.RemoteAddr())
		if err != nil {
			log.WithError(err).WithField("addr", conn.RemoteAddr()).Warnln("Could not construct connect maddr")
		} else {
			result.ConnectMaddr = maddr
		}

		nodeRes, err := c.Handshake(ctx, conn)
		result.Agent = nodeRes.UserAgent
		result.ProtocolVersion = nodeRes.ProtocolVersion
		result.Services = nodeRes.Services
		if nodeRes.ListenAddr != nil {
			result.ListenAddrs = []ma.Multiaddr{nodeRes.ListenAddr}
		}
		if err != nil {
			result.Error = err
			return result
		}

		err = c.WriteMessage(ctx, conn, wire.NewMsgGetAddr())
		if err != nil {
			result.Error = err

			return result
		}

	Loop:
		for {
			// Read messages in a loop and handle the different message types accordingly
			msg, _, err := c.ReadMessage(ctx, conn)
			if err != nil {
				if errors.Is(err, wire.ErrUnknownMessage) {
					log.WithField("addr", pi.Addr).Debugln("Received unknown message, skipping")
					continue
				}

				result.Error = err
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
				if err = c.WriteMessage(ctx, conn, wire.NewMsgPong(tmsg.Nonce)); err != nil {
					continue
				}
			default:
				if tmsg != nil {
					log.WithField("msg_type", tmsg.Command()).Debugf("Found other message from %s", pi.Addr)
				}
			}
		}
	}

	result.RoutingTable = &core.RoutingTable[PeerInfo]{
		PeerID:    pi.ID(),
		Neighbors: neighbours,
		ErrorBits: uint16(0),
		Error:     result.Error,
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

func (c *Crawler) Handshake(ctx context.Context, conn net.Conn) (BitcoinNodeResult, error) {
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

	if err := c.WriteMessage(ctx, conn, msgVersion); err != nil {
		return result, err
	}

	// Read the response version.
	msg, _, err := c.ReadMessage(ctx, conn)
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
		if maddr, err := manet.FromNetAddr(&net.TCPAddr{IP: ip, Port: int(vmsg.AddrMe.Port)}); err == nil {
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
	if err := c.WriteMessage(ctx, conn, &wire.MsgSendAddrV2{}); err != nil {
		return result, err
	}

	// Send verack.
	if err := c.WriteMessage(ctx, conn, wire.NewMsgVerAck()); err != nil {
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
	return c.WriteMessage(ctx, conn, wire.NewMsgGetAddr())
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

func (c *Crawler) WriteMessage(ctx context.Context, conn net.Conn, msg wire.Message) error {
	return withContext(ctx, conn, func() error {
		_ = conn.SetWriteDeadline(time.Now().Add(c.cfg.DialTimeout))
		return wire.WriteMessage(conn, msg, wire.ProtocolVersion, wire.MainNet)
	})
}

func (c *Crawler) ReadMessage(ctx context.Context, conn net.Conn) (wire.Message, []byte, error) {
	var msg wire.Message
	var data []byte
	var ierr error
	err := withContext(ctx, conn, func() error {
		_ = conn.SetReadDeadline(time.Now().Add(c.cfg.DialTimeout))
		msg, data, ierr = wire.ReadMessage(conn, wire.ProtocolVersion, wire.MainNet)
		return ierr
	})
	return msg, data, err
}

// withContext executes the provided function 'fn'. If the context is canceled
// before 'fn' finishes, it forces the connection to time out to unblock I/O.
func withContext(ctx context.Context, conn net.Conn, fn func() error) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}

	done := make(chan struct{})
	defer close(done)

	go func() {
		select {
		case <-ctx.Done():
			// Context canceled or expired.
			// Force immediate timeout for all pending I/O
			_ = conn.SetDeadline(time.Unix(0, 1)) // only fails if the connection is already closed
		case <-done:
			// Handshake finished normally, just exit the goroutine.
			return
		}
	}()

	err := fn()

	// If the function failed, check if it was due to the context
	if err != nil && ctx.Err() != nil {
		return ctx.Err()
	}

	// Important: Reset the deadline so the connection remains usable
	_ = conn.SetDeadline(time.Time{})
	return err
}

func processAddrs(addrs []*wire.NetAddress) []PeerInfo {
	var peers []PeerInfo
	for _, addr := range addrs {
		if addr == nil {
			continue
		}
		maddr, err := manet.FromNetAddr(&net.TCPAddr{IP: addr.IP, Port: int(addr.Port)})
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
