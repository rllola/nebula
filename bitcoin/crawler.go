package bitcoin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/btcsuite/btcd/wire"
	ma "github.com/multiformats/go-multiaddr"
	manet "github.com/multiformats/go-multiaddr/net"
	log "github.com/sirupsen/logrus"
	"golang.org/x/net/proxy"

	"github.com/dennis-tra/nebula-crawler/core"
	"github.com/dennis-tra/nebula-crawler/db"
	pgmodels "github.com/dennis-tra/nebula-crawler/db/models/pg"
)

const MaxCrawlRetriesAfterTimeout = 2 // magic

const (
	// P_CJDNS is a project-local multiaddr protocol code for CJDNS transport.
	// CJDNS addresses are always IPv6 in the fc00::/8 range.
	P_CJDNS = 1010

	// P_YGGDRASIL is a project-local multiaddr protocol code for Yggdrasil transport.
	// Yggdrasil addresses are always IPv6 in the 200::/7 range.
	P_YGGDRASIL = 1011
)

func init() {
	for _, p := range []ma.Protocol{
		{
			Name:       "cjdns",
			Code:       P_CJDNS,
			VCode:      ma.CodeToVarint(P_CJDNS),
			Size:       128,
			Transcoder: ma.TranscoderIP6,
		},
		{
			Name:       "yggdrasil",
			Code:       P_YGGDRASIL,
			VCode:      ma.CodeToVarint(P_YGGDRASIL),
			Size:       128,
			Transcoder: ma.TranscoderIP6,
		},
	} {
		if err := ma.AddProtocol(p); err != nil {
			panic("bitcoin: failed to register multiaddr protocol " + p.Name + ": " + err.Error())
		}
	}
}

type CrawlerConfig struct {
	DialTimeout time.Duration
	LogErrors   bool
	Version     string
}

type Crawler struct {
	id        string
	cfg       *CrawlerConfig
	torDialer proxy.ContextDialer
	done      chan struct{}

	crawledPeers int
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
	props := map[string]any{}
	if r := result.RPCResult; r != nil {
		props["rpc_open"] = r.Error == nil
		props["rpc_status_code"] = r.StatusCode
	}
	return props
}

// save the available services announced as protocols
func serviceFlagsToProtocols(services wire.ServiceFlag) []string {
	known := []wire.ServiceFlag{
		wire.SFNodeNetwork,
		wire.SFNodeGetUTXO,
		wire.SFNodeBloom,
		wire.SFNodeWitness,
		wire.SFNodeXthin,
		wire.SFNodeBit5,
		wire.SFNodeCF,
		wire.SFNode2X,
		wire.SFNodeNetworkLimited,
		wire.SFNodeP2PV2,
	}
	var protocols []string
	for _, flag := range known {
		if services&flag != 0 {
			protocols = append(protocols, flag.String())
		}
	}
	return protocols
}

// RPCProbeResult holds the outcome of a Bitcoin JSON-RPC port probe.
// StatusCode is the HTTP response code (e.g. 401 = RPC enabled, auth required).
// Error is non-nil when the TCP connection or HTTP exchange itself failed.
type RPCProbeResult struct {
	StatusCode int
	Error      error
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
	RPCResult        *RPCProbeResult
}

func (c *Crawler) crawlBitcoin(ctx context.Context, pi PeerInfo) (result BitcoinResult) {
	neighbours := make([]PeerInfo, 0)

	addrs := pi.Addrs()

	// limit whole crawl of this peer to 3 minutes
	ctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()

	// Start RPC probe in parallel for plain IPv4/IPv6 TCP addresses only.
	// The probe runs for the lifetime of the crawl; we collect it via defer
	// so all return paths (connect error, handshake error, normal end) get it.
	var rpcCh <-chan *RPCProbeResult
	if len(addrs) > 0 {
		if netAddr, err := manet.ToNetAddr(addrs[0]); err == nil {
			if tcpAddr, ok := netAddr.(*net.TCPAddr); ok {
				rpcCh = probeRPC(ctx, tcpAddr.IP)
			}
		}
	}
	defer func() {
		if rpcCh != nil {
			result.RPCResult = <-rpcCh
		}
	}()

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
		return result
	}

	defer conn.Close()

	result.ConnectMaddr = addrs[0]

	nodeRes, err := c.Handshake(ctx, conn)
	result.Agent = nodeRes.UserAgent
	result.ProtocolVersion = nodeRes.ProtocolVersion
	result.Services = nodeRes.Services
	result.Protocols = serviceFlagsToProtocols(nodeRes.Services)
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
			c.requestMoreAddrs(ctx, conn)
		case *wire.MsgAddrV2:
			peers := processAddrsV2(tmsg.AddrList)
			neighbours = append(neighbours, peers...)
			if len(tmsg.AddrList) < wire.MaxAddrPerMsg {
				break Loop
			}
			c.requestMoreAddrs(ctx, conn)
		case *wire.MsgPing:
			if err = c.WriteMessage(ctx, conn, wire.NewMsgPong(tmsg.Nonce)); err != nil {
				result.Error = err
				break Loop
			}
		default:
			if tmsg != nil {
				log.WithField("msg_type", tmsg.Command()).Debugf("Found other message from %s", pi.Addr)
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
func (c *Crawler) requestMoreAddrs(ctx context.Context, conn net.Conn) {
	go func() {
		select {
		case <-ctx.Done():
			return
		case <-time.After(30 * time.Second):
		}
		c.WriteMessage(ctx, conn, wire.NewMsgGetAddr()) //nolint:errcheck
	}()
}

// connect establishes a connection to the given peer, with one retry on timeout
func (c *Crawler) connect(ctx context.Context, addrs []ma.Multiaddr) (net.Conn, error) {
	if len(addrs) == 0 {
		return nil, fmt.Errorf("no addresses to connect to")
	}

	// we only work single addresses for peers
	maddr := addrs[0]

	var (
		dialer  proxy.ContextDialer
		network string
		addr    string
	)

	if onionAddr, err := extractOnionAddress(maddr); err == nil {
		if c.torDialer == nil {
			return nil, fmt.Errorf("no transport for protocol: tor dialer not set")
		}

		// this is an onion address, use the tor SOCKS5 proxy dialer
		dialer = c.torDialer
		network = "tcp" // tor uses TCP
		addr = onionAddr
	} else if netAddr, err := manet.ToNetAddr(maddr); err == nil {
		dialer = &net.Dialer{Timeout: c.cfg.DialTimeout}
		network = netAddr.Network()
		addr = netAddr.String()
	} else {
		return nil, fmt.Errorf("unsupported address: %s", maddr)
	}

	return dialer.DialContext(ctx, network, addr)
}

func extractOnionAddress(maddr ma.Multiaddr) (string, error) {
	// Extract the /onion3 component ("publickey:port")
	onion3Value, err := maddr.ValueForProtocol(ma.P_ONION3)
	if err != nil {
		return "", fmt.Errorf("multiaddress does not contain an onion3 protocol: %w", err)
	}

	// /onion3 protocol strictly requires a port component
	parts := strings.Split(onion3Value, ":")
	if len(parts) != 2 {
		return "", fmt.Errorf("unexpected onion3 value structure: %s", onion3Value)
	}

	return fmt.Sprintf("%s.onion:%s", parts[0], parts[1]), nil
}

// probeRPC sends a Bitcoin JSON-RPC request to port 8332 of the given IP in a
// goroutine and returns a buffered channel the caller can receive from later.
func probeRPC(ctx context.Context, ip net.IP) <-chan *RPCProbeResult {
	ch := make(chan *RPCProbeResult, 1)
	go func() {
		result := &RPCProbeResult{}
		defer func() { ch <- result }()

		probeCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()

		url := "http://" + net.JoinHostPort(ip.String(), "8332") + "/"
		req, err := http.NewRequestWithContext(probeCtx, http.MethodPost, url,
			strings.NewReader(`{"jsonrpc":"1.1","method":"getnetworkinfo","params":[],"id":"nebula"}`))
		if err != nil {
			result.Error = err
			return
		}
		req.Header.Set("Content-Type", "application/json")

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			result.Error = err
			return
		}
		resp.Body.Close()
		result.StatusCode = resp.StatusCode
	}()
	return ch
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

// https://github.com/btcsuite/btcd/blob/b3cbf4f80ec6e0deef47b9a0b8af777572d3a2f7/wire/netaddressv2.go#L446
var networkID = map[string]string{
	string(rune(1)): "ipv4",
	string(rune(2)): "ipv6",
	string(rune(3)): "torv2",
	string(rune(4)): "torv3",
	string(rune(5)): "i2p",
	string(rune(6)): "cjdns",
	string(rune(7)): "yggdrasil",
}

// processAddrsV2 converts BIP 155 addrv2 addresses to PeerInfo entries.
// IPv4, IPv6, and Tor v2 are handled via ToLegacy(). Tor v3 uses /onion3/,
// I2P uses /garlic32/, CJDNS uses /ip6/.../cjdns/<port>, and Yggdrasil uses
// /ip6/.../yggdrasil/<port> with project-local protocol codes (see init).
func processAddrsV2(addrs []*wire.NetAddressV2) []PeerInfo {
	var peers []PeerInfo
	for _, addr := range addrs {
		var (
			maddr ma.Multiaddr
			err   error
		)
		if addr == nil {
			continue
		} else if addr.IsTorV3() {
			// addr.Addr.String() returns "<base32>.onion"; strip the suffix for the onion3 multiaddr scheme
			host := strings.TrimSuffix(addr.Addr.String(), ".onion")
			maddr, err = ma.NewMultiaddr(fmt.Sprintf("/onion3/%s:%d", host, addr.Port))
		} else if addr.IsI2P() {
			// addr.Addr.String() returns "<base32>.b32.i2p"; strip the suffix for the garlic32 multiaddr scheme
			host := strings.TrimSuffix(addr.Addr.String(), ".b32.i2p")
			maddr, err = ma.NewMultiaddr(fmt.Sprintf("/garlic32/%s", host))
		} else if addr.IsCJDNS() {
			maddr, err = ma.NewMultiaddr(fmt.Sprintf("/cjdns/%s/tcp/%d", addr.Addr.String(), addr.Port))
		} else if addr.IsYggdrasil() {
			maddr, err = ma.NewMultiaddr(fmt.Sprintf("/yggdrasil/%s/tcp/%d", addr.Addr.String(), addr.Port))
		} else {
			networkStr := networkID[addr.Addr.Network()]
			switch networkStr {
			case "ipv4", "ipv6":
				maddr, err = manet.FromNetAddr(&net.TCPAddr{IP: net.ParseIP(addr.Addr.String()), Port: int(addr.Port)})
			default:
				err = fmt.Errorf("unsupported network type: %s", networkStr)
			}
		}

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
