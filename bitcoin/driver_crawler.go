package bitcoin

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/btcsuite/btcd/wire"
	"github.com/libp2p/go-libp2p/core/peer"
	ma "github.com/multiformats/go-multiaddr"
	"github.com/multiformats/go-multihash"
	log "github.com/sirupsen/logrus"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/trace"
	"golang.org/x/net/proxy"

	"github.com/dennis-tra/nebula-crawler/core"
	"github.com/dennis-tra/nebula-crawler/db"
	"github.com/dennis-tra/nebula-crawler/utils"
)

type AddrInfo struct {
	id   string
	Addr []ma.Multiaddr
}
type PeerInfo struct {
	AddrInfo
}

var _ core.PeerInfo[PeerInfo] = (*PeerInfo)(nil)

func (p PeerInfo) ID() peer.ID {
	h := sha256.New()
	h.Write([]byte(p.AddrInfo.id))
	mh, _ := multihash.Encode(h.Sum(nil), multihash.SHA2_256) // method can't fail
	return peer.ID(mh)
}

func (p PeerInfo) Addrs() []ma.Multiaddr {
	return p.AddrInfo.Addr
}

func (p PeerInfo) Merge(other PeerInfo) PeerInfo {
	if p.AddrInfo.id != other.AddrInfo.id {
		panic("merge peer ID mismatch")
	}

	return PeerInfo{
		AddrInfo: AddrInfo{
			id:   p.AddrInfo.id,
			Addr: utils.MergeMaddrs(p.AddrInfo.Addr, other.AddrInfo.Addr),
		},
	}
}

func (p PeerInfo) DeduplicationKey() string {
	return p.AddrInfo.id
}

func (p PeerInfo) DiscoveryPrefix() uint64 {
	return binary.BigEndian.Uint64([]byte(p.id)[:8])
}

// LitecoinMainNet is the Litecoin mainnet magic bytes (BIP 155 network ID 6).
const LitecoinMainNet wire.BitcoinNet = 0xdbb6c0fb

type CrawlDriverConfig struct {
	Version        string
	DialTimeout    time.Duration
	BootstrapPeers []ma.Multiaddr
	TorProxyAddr   string
	MeterProvider  metric.MeterProvider
	TracerProvider trace.TracerProvider
	LogErrors      bool
	Net            wire.BitcoinNet
	RPCPort        string
}

func (cfg *CrawlDriverConfig) CrawlerConfig() *CrawlerConfig {
	return &CrawlerConfig{
		DialTimeout: cfg.DialTimeout,
		LogErrors:   cfg.LogErrors,
		Version:     cfg.Version,
		Net:         cfg.Net,
		RPCPort:     cfg.RPCPort,
	}
}

func (cfg *CrawlDriverConfig) WriterConfig() *core.CrawlWriterConfig {
	return &core.CrawlWriterConfig{}
}

type CrawlDriver struct {
	cfg          *CrawlDriverConfig
	dbc          db.Client
	tasksChan    chan PeerInfo
	crawlerCount int
	writerCount  int
	crawler      []*Crawler
	torDialer    proxy.ContextDialer
}

var _ core.Driver[PeerInfo, core.CrawlResult[PeerInfo]] = (*CrawlDriver)(nil)

func NewCrawlDriver(dbc db.Client, cfg *CrawlDriverConfig) (*CrawlDriver, error) {
	tasksChan := make(chan PeerInfo, len(cfg.BootstrapPeers))
	for _, addrInfo := range cfg.BootstrapPeers {
		tasksChan <- PeerInfo{
			AddrInfo: AddrInfo{
				id:   addrInfo.String(),
				Addr: []ma.Multiaddr{addrInfo},
			},
		}
	}
	close(tasksChan)

	var torDialer proxy.ContextDialer
	if cfg.TorProxyAddr == "" {
		log.Infoln("No Tor proxy address configured, dialing onion addresses is disabled.")
	} else {
		proxyDialer, err := proxy.SOCKS5("tcp", cfg.TorProxyAddr, nil, &net.Dialer{Timeout: cfg.DialTimeout})
		if err != nil {
			return nil, fmt.Errorf("creating tor dialer: %w", err)
		}
		torDialer = proxyDialer.(proxy.ContextDialer)
		log.WithField("proxyAddr", cfg.TorProxyAddr).Infoln("Tor proxy address configured, dialing onion addresses is enabled.")
	}

	return &CrawlDriver{
		cfg:       cfg,
		dbc:       dbc,
		torDialer: torDialer,
		tasksChan: tasksChan,
		crawler:   make([]*Crawler, 0),
	}, nil
}

// NewWorker is called multiple times but only log the configured buffer sizes once
var logOnce sync.Once

func (d *CrawlDriver) NewWorker() (core.Worker[PeerInfo, core.CrawlResult[PeerInfo]], error) {
	c := &Crawler{
		id:        fmt.Sprintf("crawler-%02d", d.crawlerCount),
		cfg:       d.cfg.CrawlerConfig(),
		torDialer: d.torDialer,
		done:      make(chan struct{}),
	}

	d.crawlerCount += 1

	d.crawler = append(d.crawler, c)

	log.Debugln("Started crawler worker", c.id)

	return c, nil
}

func (d *CrawlDriver) NewWriter() (core.Worker[core.CrawlResult[PeerInfo], core.WriteResult], error) {
	w := core.NewCrawlWriter[PeerInfo](fmt.Sprintf("writer-%02d", d.writerCount), d.dbc, d.cfg.WriterConfig())
	d.writerCount += 1
	return w, nil
}

func (d *CrawlDriver) Tasks() <-chan PeerInfo {
	return d.tasksChan
}

func (d *CrawlDriver) Close() {
}
