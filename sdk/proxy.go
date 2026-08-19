package sdk

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"

	"github.com/yawaflua/cloudflare-warp/core"
)

const (
	// DefaultEndpointPort is Cloudflare WARP's standard WireGuard port.
	DefaultEndpointPort uint16 = 2408
)

var (
	// ErrAlreadyStarted is returned when Run or Start is called twice.
	ErrAlreadyStarted = errors.New("WARP proxy already started")
	// ErrNotStarted is returned when Wait is called before Run or Start.
	ErrNotStarted = errors.New("WARP proxy is not started")
)

// Protocol selects the local proxy protocol.
type Protocol string

const (
	// SOCKS5 serves a SOCKS5 proxy. It is the default protocol.
	SOCKS5 Protocol = "socks5"
	// HTTP serves an HTTP CONNECT proxy.
	HTTP Protocol = "http"
)

// ProxyConfig describes one independent proxy and its WARP endpoint.
type ProxyConfig struct {
	// ListenIP is the local address accepting proxy connections. The default
	// is 127.0.0.1. Set 0.0.0.0 or :: only when remote access is intended.
	ListenIP netip.Addr
	// Port is the local SOCKS5 or HTTP proxy port. It must be non-zero.
	Port uint16
	// EndpointIP is the remote Cloudflare WARP server IP used by this proxy.
	EndpointIP netip.Addr
	// EndpointPort is the remote WARP UDP port. The default is 2408.
	EndpointPort uint16
	// DNS is used inside the WARP tunnel. The default is 1.1.1.1.
	DNS netip.Addr
	// Protocol selects SOCKS5 or HTTP. The zero value is SOCKS5.
	Protocol Protocol
}

type WARPInfo struct {
	IP          netip.Addr
	HTTP        string
	ServerPlace string
	Location    string
	Warp        WarpType
	TLS         string
}

type WarpType string

const (
	WarpTypeOn   WarpType = "on"
	WarpTypeOff  WarpType = "off"
	WarpTypePlus WarpType = "plus"
)

// Proxy is one WARP tunnel with one local proxy listener.
type Proxy struct {
	engine       *core.Engine
	cancel       context.CancelFunc
	bindAddr     netip.AddrPort
	endpoint     netip.AddrPort
	proxyConfig  ProxyConfig
	engineConfig core.Config

	mu       sync.RWMutex
	started  bool
	stopped  bool
	err      error
	done     chan struct{}
	doneOnce sync.Once
}

// NewProxy creates, but does not start, an independent WARP proxy.
func (c *Client) NewProxy(ctx context.Context, config ProxyConfig) (*Proxy, error) {
	if c == nil || c.identity == nil {
		return nil, errors.New("WARP client is not initialized")
	}
	if ctx == nil {
		return nil, errors.New("context is nil")
	}
	if config.Port == 0 {
		return nil, errors.New("proxy port must be non-zero")
	}
	if !config.EndpointIP.IsValid() {
		return nil, errors.New("WARP endpoint IP is required")
	}
	if config.Protocol != SOCKS5 && config.Protocol != HTTP {
		return nil, fmt.Errorf("unsupported proxy protocol: %s", config.Protocol)
	}

	if !config.ListenIP.IsValid() {
		config.ListenIP = netip.MustParseAddr("127.0.0.1")
	}
	if config.EndpointPort == 0 {
		config.EndpointPort = DefaultEndpointPort
	}
	if !config.DNS.IsValid() {
		config.DNS = netip.MustParseAddr("1.1.1.1")
	}

	bindAddr := netip.AddrPortFrom(config.ListenIP, config.Port)
	endpoint := netip.AddrPortFrom(config.EndpointIP, config.EndpointPort)
	engineConfig := core.Config{
		Endpoints:            []string{endpoint.String()},
		DnsAddr:              config.DNS,
		UserProvidedEndpoint: true,
		Identity:             c.identity,
	}
	if config.Protocol == SOCKS5 {
		engineConfig.SocksBindAddress = &bindAddr
	} else {
		engineConfig.HttpBindAddress = &bindAddr
	}

	proxyCtx, cancel := context.WithCancel(ctx)
	return &Proxy{
		engine:       core.NewEngine(proxyCtx, engineConfig),
		cancel:       cancel,
		bindAddr:     bindAddr,
		endpoint:     endpoint,
		done:         make(chan struct{}),
		proxyConfig:  config,
		engineConfig: engineConfig,
	}, nil
}

// Start launches the proxy in a background goroutine. Startup and runtime
// errors are returned by Wait. Use Run when the caller needs a blocking API.
func (p *Proxy) Start() error {
	if err := p.markStarted(); err != nil {
		return err
	}
	go p.execute()
	return nil
}

// Run starts the proxy and blocks until it stops or fails.
func (p *Proxy) Run() error {
	if err := p.markStarted(); err != nil {
		return err
	}
	p.execute()
	return p.result()
}

func (p *Proxy) markStarted() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.started {
		return ErrAlreadyStarted
	}
	p.started = true
	if p.stopped {
		return nil
	}
	return nil
}

func (p *Proxy) execute() {
	p.mu.RLock()
	stopped := p.stopped
	p.mu.RUnlock()
	if stopped {
		p.finish(nil)
		return
	}

	err := p.engine.Run()
	p.finish(err)
}

func (p *Proxy) finish(err error) {
	p.mu.Lock()
	p.err = err
	p.mu.Unlock()
	p.doneOnce.Do(func() { close(p.done) })
}

// Wait blocks until a proxy started with Start stops or fails. It is safe for
// multiple goroutines to call Wait.
func (p *Proxy) Wait() error {
	p.mu.RLock()
	started := p.started
	p.mu.RUnlock()
	if !started {
		return ErrNotStarted
	}
	<-p.done
	return p.result()
}

// WaitContext waits until the proxy exits or ctx is canceled.
func (p *Proxy) WaitContext(ctx context.Context) error {
	if ctx == nil {
		return errors.New("context is nil")
	}
	p.mu.RLock()
	started := p.started
	p.mu.RUnlock()
	if !started {
		return ErrNotStarted
	}
	select {
	case <-p.done:
		return p.result()
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (p *Proxy) result() error {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.err
}

// Stop gracefully stops this proxy without affecting other instances.
func (p *Proxy) Stop() {
	p.mu.Lock()
	p.stopped = true
	started := p.started
	p.mu.Unlock()
	p.cancel()
	p.engine.Stop()
	if !started {
		p.finish(nil)
	}
}

// Shutdown stops the proxy and waits for tunnel and listener shutdown. If ctx
// expires first, its error is returned while shutdown continues in background.
func (p *Proxy) Shutdown(ctx context.Context) error {
	if ctx == nil {
		return errors.New("context is nil")
	}
	p.Stop()
	select {
	case <-p.done:
		return p.result()
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Done is closed after the proxy stops or fails.
func (p *Proxy) Done() <-chan struct{} {
	return p.done
}

// Addr returns the local proxy listener address.
func (p *Proxy) Addr() netip.AddrPort {
	return p.bindAddr
}

// Endpoint returns the remote WARP endpoint used by this proxy.
func (p *Proxy) Endpoint() netip.AddrPort {
	return p.endpoint
}

func (p *Proxy) ProxyConfig() ProxyConfig {
	return p.proxyConfig
}

// Stopping the proxy is gonna cancel the context. If you want to restart the proxy, call Start() again from normal-lifecycle context.
func (p *Proxy) UpdateProxyConfig(ctx context.Context, newConfig ProxyConfig) (*Proxy, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p == nil || p.engineConfig.Identity == nil {
		return nil, errors.New("WARP client is not initialized")
	}
	if ctx == nil {
		return nil, errors.New("context is nil")
	}
	if newConfig.Port == 0 {
		return nil, errors.New("proxy port must be non-zero")
	}
	if !newConfig.EndpointIP.IsValid() {
		return nil, errors.New("WARP endpoint IP is required")
	}
	if newConfig.Protocol != SOCKS5 && newConfig.Protocol != HTTP {
		return nil, fmt.Errorf("unsupported proxy protocol: %s", newConfig.Protocol)
	}

	if !newConfig.ListenIP.IsValid() {
		newConfig.ListenIP = netip.MustParseAddr("127.0.0.1")
	}
	if newConfig.EndpointPort == 0 {
		newConfig.EndpointPort = DefaultEndpointPort
	}
	if !newConfig.DNS.IsValid() {
		newConfig.DNS = netip.MustParseAddr("1.1.1.1")
	}

	p.proxyConfig = newConfig
	bindAddr := netip.AddrPortFrom(newConfig.ListenIP, newConfig.Port)
	endpoint := netip.AddrPortFrom(newConfig.EndpointIP, newConfig.EndpointPort)
	engineConfig := core.Config{
		Endpoints:            []string{endpoint.String()},
		DnsAddr:              newConfig.DNS,
		UserProvidedEndpoint: true,
		Identity:             p.engineConfig.Identity,
	}
	if newConfig.Protocol == SOCKS5 {
		engineConfig.SocksBindAddress = &bindAddr
	} else {
		engineConfig.HttpBindAddress = &bindAddr
	}
	p.engine.UpdateConfig(engineConfig)
	return p, nil
}

func (p *Proxy) GetWARPInfo() (*WARPInfo, error) {
	client, err := proxyHTTPClient(fmt.Sprintf("%s://%s", p.proxyConfig.Protocol, p.bindAddr.String()))
	if err != nil {
		return nil, err
	}
	resp, err := client.Get("https://cloudflare.com/cdn-cgi/trace")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	warptrace := WARPInfo{}
	scanner := bufio.NewScanner(strings.NewReader(string(body)))
	for scanner.Scan() {
		key, value, ok := strings.Cut(scanner.Text(), "=")
		if !ok {
			continue
		}
		switch key {
		case "ip":
			warptrace.IP = netip.MustParseAddr(value)
		case "colo":
			warptrace.ServerPlace = value
		case "http":
			warptrace.HTTP = value
		case "loc":
			warptrace.Location = value
		case "tls":
			warptrace.TLS = value
		case "warp":
			warptrace.Warp = WarpType(value)
		}
	}
	return &warptrace, nil
}

func proxyHTTPClient(proxyURL string) (*http.Client, error) {
	parsed, err := url.Parse(strings.TrimSpace(proxyURL))
	if err != nil || parsed.Host == "" {
		return nil, fmt.Errorf("invalid proxy URL %q", proxyURL)
	}

	transport, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		return nil, fmt.Errorf("unsupported default HTTP transport")
	}
	transport = transport.Clone()

	switch strings.ToLower(parsed.Scheme) {
	case "http", "https":
		transport.Proxy = http.ProxyURL(parsed)
	case "socks", "socks5", "socks5h":
		if strings.EqualFold(parsed.Scheme, "socks") {
			parsed.Scheme = "socks5"
		}
		transport.Proxy = http.ProxyURL(parsed)
	default:
		return nil, fmt.Errorf("unsupported proxy scheme %q", parsed.Scheme)
	}

	return &http.Client{Transport: transport}, nil
}
