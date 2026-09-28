package singbox

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/lilendian0x00/xray-knife/v11/pkg/core/fragment"
	"github.com/lilendian0x00/xray-knife/v11/pkg/core/protocol"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter/certificate"
	"github.com/sagernet/sing-box/adapter/endpoint"
	"github.com/sagernet/sing-box/adapter/inbound"
	boxOutbound "github.com/sagernet/sing-box/adapter/outbound"
	boxService "github.com/sagernet/sing-box/adapter/service"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/dns"
	dnsTransport "github.com/sagernet/sing-box/dns/transport"
	"github.com/sagernet/sing-box/dns/transport/hosts"
	"github.com/sagernet/sing-box/dns/transport/local"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	boxHTTP "github.com/sagernet/sing-box/protocol/http"
	"github.com/sagernet/sing-box/protocol/hysteria"
	"github.com/sagernet/sing-box/protocol/hysteria2"
	"github.com/sagernet/sing-box/protocol/mixed"
	"github.com/sagernet/sing-box/protocol/shadowsocks"
	"github.com/sagernet/sing-box/protocol/socks"
	"github.com/sagernet/sing-box/protocol/ssh"
	"github.com/sagernet/sing-box/protocol/trojan"
	"github.com/sagernet/sing-box/protocol/tuic"
	"github.com/sagernet/sing-box/protocol/tun"
	"github.com/sagernet/sing-box/protocol/vless"
	"github.com/sagernet/sing-box/protocol/vmess"
	"github.com/sagernet/sing-box/protocol/wireguard"
	"github.com/sagernet/sing/common/json/badoption"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/service"
)

type Core struct {
	Inbound *option.Inbound
	// inboundErr holds a WithInbound failure until the first build, since a
	// ServiceOption cannot return an error.
	inboundErr error

	// Log
	Verbose bool
	Log     logger.ContextLogger

	AllowInsecure bool

	// BindInterface, when set, pins all outbound sing-box dials to the
	// named OS interface via RouteOptions.DefaultInterface.
	BindInterface string

	// Fragment, when it fragments TCP, splits the entry hop's TLS
	// ClientHello (see WithFragment).
	Fragment *fragment.Options
}

func (c *Core) Name() string {
	return "singbox"
}

type ServiceOption = func(c *Core)

func WithInbound(inbound protocol.Protocol) ServiceOption {
	return func(c *Core) {
		c.Inbound, c.inboundErr = craftInbound(inbound)
	}
}

func WithCustomLogLevel(logOptions option.LogOptions) ServiceOption {
	return func(c *Core) {
		l, _ := log.New(log.Options{
			Options: logOptions,
		})
		c.Log = l.Logger()
	}
}

// WithBindInterface configures the OS interface to bind outbound
// sing-box dials to. Empty string disables binding.
func WithBindInterface(iface string) ServiceOption {
	return func(c *Core) {
		c.BindInterface = iface
	}
}

// WithFragment fragments the TLS ClientHello of the entry hop (the one
// dialed from this machine) of every instance and client the core builds.
// sing-box splits at the SNI by itself, so only the mode and the interval
// of the options matter here; noises are xray-only and ignored. Outbounds
// without TCP TLS (shadowsocks, socks, QUIC protocols, wireguard) are left
// untouched; a REALITY entry hop fails to build, because sing-box cannot
// fragment its handshake (see FragmentSupported). Nil disables it.
func WithFragment(f *fragment.Options) ServiceOption {
	return func(c *Core) {
		c.Fragment = f.Clone()
	}
}

func NewSingboxService(verbose bool, allowInsecure bool, opts ...ServiceOption) *Core {
	s := &Core{
		Inbound:       nil,
		Verbose:       verbose,
		AllowInsecure: allowInsecure,
	}

	for _, opt := range opts {
		opt(s)
	}

	if s.Log == nil {
		l, _ := log.New(log.Options{
			Options: option.LogOptions{Disabled: true},
		})
		s.Log = l.Logger()
	}

	if verbose {
		l, _ := log.New(log.Options{
			Options: option.LogOptions{
				Disabled: false,
				Level:    "trace",
			},
		})
		s.Log = l.Logger()
	}

	return s
}

// applyBind injects the configured BindInterface into the option tree
// so every outbound dial is pinned to that OS interface.
func (c *Core) applyBind(opts *option.Options) {
	if c == nil || c.BindInterface == "" {
		return
	}
	if opts.Route == nil {
		opts.Route = &option.RouteOptions{}
	}
	opts.Route.DefaultInterface = c.BindInterface
}

// registries holds the sing-box registries this core fills. Tests add
// server-side inbounds to them before building a context.
type registries struct {
	inbound  *inbound.Registry
	outbound *boxOutbound.Registry
	endpoint *endpoint.Registry
	dns      *dns.TransportRegistry
}

// newRegistries registers every protocol xray-knife can drive with sing-box.
// WireGuard has been an endpoint rather than an outbound since sing-box 1.14,
// so it goes into the endpoint registry; the outbound manager still resolves
// endpoint tags, so detour/Final/Outbound(tag) keep working for it.
func newRegistries() registries {
	// Local listeners: socks/mixed/http for proxy and system mode, tun for
	// the tunnel modes, and the share-link protocols for "--inbound <link>".
	inboundRegistry := inbound.NewRegistry()
	socks.RegisterInbound(inboundRegistry)
	mixed.RegisterInbound(inboundRegistry)
	boxHTTP.RegisterInbound(inboundRegistry)
	tun.RegisterInbound(inboundRegistry)
	shadowsocks.RegisterInbound(inboundRegistry)
	trojan.RegisterInbound(inboundRegistry)
	vless.RegisterInbound(inboundRegistry)
	vmess.RegisterInbound(inboundRegistry)
	// QUIC protocols (hysteria, hysteria2, tuic) are registered directly
	// rather than through sing-box's with_quic-gated include package, so they
	// work in untagged builds too.
	outboundRegistry := boxOutbound.NewRegistry()
	boxHTTP.RegisterOutbound(outboundRegistry)
	hysteria.RegisterOutbound(outboundRegistry)
	hysteria2.RegisterOutbound(outboundRegistry)
	shadowsocks.RegisterOutbound(outboundRegistry)
	socks.RegisterOutbound(outboundRegistry)
	ssh.RegisterOutbound(outboundRegistry)
	trojan.RegisterOutbound(outboundRegistry)
	tuic.RegisterOutbound(outboundRegistry)
	vless.RegisterOutbound(outboundRegistry)
	vmess.RegisterOutbound(outboundRegistry)
	registerAnyTLS(outboundRegistry)
	endpointRegistry := endpoint.NewRegistry()
	wireguard.RegisterEndpoint(endpointRegistry)
	// sing-box 1.14 builds a "local" DNS server as the default fallback and
	// looks its transport up in this registry, so an empty registry fails
	// box.New with "transport type not found: local". Register the plain
	// transports (no build-tag-gated ones such as QUIC or DHCP).
	dnsRegistry := dns.NewTransportRegistry()
	dnsTransport.RegisterTCP(dnsRegistry)
	dnsTransport.RegisterUDP(dnsRegistry)
	dnsTransport.RegisterTLS(dnsRegistry)
	dnsTransport.RegisterHTTPS(dnsRegistry)
	hosts.RegisterTransport(dnsRegistry)
	local.RegisterTransport(dnsRegistry)
	return registries{inbound: inboundRegistry, outbound: outboundRegistry, endpoint: endpointRegistry, dns: dnsRegistry}
}

// context attaches the registries to ctx for box.New.
func (r registries) context(ctx context.Context) context.Context {
	ctx = service.ContextWithDefaultRegistry(ctx)
	return box.Context(ctx, r.inbound, r.outbound, r.endpoint, r.dns, boxService.NewRegistry(), certificate.NewRegistry())
}

// boxContext attaches this core's registries to ctx.
func boxContext(ctx context.Context) context.Context {
	return newRegistries().context(ctx)
}

// placeOutbounds files crafted outbounds into the right sing-box list:
// WireGuard options are endpoint options and must live in Endpoints, everything
// else in Outbounds. Tags are preserved so callers can keep addressing them.
func placeOutbounds(opts *option.Options, outbounds ...option.Outbound) {
	for _, out := range outbounds {
		if _, isEndpoint := out.Options.(*option.WireGuardEndpointOptions); isEndpoint {
			opts.Endpoints = append(opts.Endpoints, option.Endpoint{Type: out.Type, Tag: out.Tag, Options: out.Options})
			continue
		}
		opts.Outbounds = append(opts.Outbounds, out)
	}
}

// asProtocol narrows a generic protocol to one this core can craft,
// returning an error instead of panicking on protocols of another core.
func asProtocol(p protocol.Protocol) (Protocol, error) {
	out, ok := p.(Protocol)
	if !ok {
		return nil, fmt.Errorf("sing-box core cannot use %T", p)
	}
	return out, nil
}

func craftInbound(p protocol.Protocol) (*option.Inbound, error) {
	in, err := asProtocol(p)
	if err != nil {
		return nil, err
	}
	return in.CraftInboundOptions()
}

// craftOutbound crafts one outbound under tag. The entry hop (the one
// dialed directly from this machine) also gets the configured fragmentation.
func (c *Core) craftOutbound(p protocol.Protocol, tag string, entry bool) (option.Outbound, error) {
	out, err := asProtocol(p)
	if err != nil {
		return option.Outbound{}, err
	}
	opts, err := out.CraftOutboundOptions(c.AllowInsecure)
	if err != nil {
		return option.Outbound{}, err
	}
	opts.Tag = tag
	if entry {
		if err := applyFragment(opts, c.Fragment); err != nil {
			return option.Outbound{}, err
		}
	}
	return *opts, nil
}

// errFragmentREALITY is returned when --fragment is asked of a REALITY
// entry hop: sing-box 1.14's REALITY client does its own handshake and
// ignores the TLS fragment switches, so the config would silently be tested
// unfragmented.
var errFragmentREALITY = errors.New("sing-box does not fragment REALITY handshakes (use --core xray for --fragment)")

// fragmentSupport reports whether sing-box fragments out's handshake, and
// why not. fatal marks the case where asking for it must fail (REALITY)
// rather than be a harmless no-op (no TLS, QUIC).
func fragmentSupport(out *option.Outbound) (supported bool, reason error, fatal bool) {
	switch out.Options.(type) {
	case *option.Hysteria2OutboundOptions, *option.HysteriaOutboundOptions, *option.TUICOutboundOptions:
		return false, errors.New("QUIC: there is no TCP ClientHello to fragment"), false
	}
	wrapper, ok := out.Options.(option.OutboundTLSOptionsWrapper)
	if !ok {
		return false, errors.New("no TLS handshake to fragment"), false
	}
	tlsOpts := wrapper.TakeOutboundTLSOptions()
	if tlsOpts == nil || !tlsOpts.Enabled {
		return false, errors.New("no TLS handshake to fragment"), false
	}
	if tlsOpts.Reality != nil && tlsOpts.Reality.Enabled {
		return false, errFragmentREALITY, true
	}
	return true, nil, false
}

// FragmentSupported reports whether this core applies --fragment to p (a
// TLS-over-TCP outbound other than REALITY), and otherwise why not. It is
// build-independent, so callers such as the DPI finder can explain a
// skipped config (e.g. "use --core xray" for REALITY).
func FragmentSupported(p protocol.Protocol) (bool, string) {
	sp, err := asProtocol(p)
	if err != nil {
		return false, err.Error()
	}
	out, err := CraftOutboundOptionsFor(sp, false, true)
	if err != nil {
		return false, err.Error()
	}
	if ok, reason, _ := fragmentSupport(out); !ok {
		return false, reason.Error()
	}
	return true, ""
}

// applyFragment turns on sing-box's TLS ClientHello fragmentation for TCP
// TLS outbounds. "tlshello" maps to splitting the hello into TLS records as
// well as TCP segments (what xray's tlshello mode does); a packet range maps
// to TCP segmentation only. The fragment interval becomes the fallback delay
// sing-box waits between segments when it cannot observe the ACK. Outbounds
// with nothing to fragment are left alone; REALITY is an error.
func applyFragment(out *option.Outbound, f *fragment.Options) error {
	if !f.FragmentsTCP() {
		return nil
	}
	if ok, reason, fatal := fragmentSupport(out); !ok {
		if fatal {
			return reason
		}
		return nil
	}
	tlsOpts := out.Options.(option.OutboundTLSOptionsWrapper).TakeOutboundTLSOptions()
	tlsOpts.Fragment = true
	if strings.EqualFold(f.Packets, fragment.PacketsTLSHello) {
		tlsOpts.RecordFragment = true
	}
	if f.Interval.Max > 0 {
		tlsOpts.FragmentFallbackDelay = badoption.Duration(time.Duration(f.Interval.Max) * time.Millisecond)
	}
	return nil
}

func (c *Core) logOptions() *option.LogOptions {
	if c.Verbose {
		return &option.LogOptions{Level: "trace"}
	}
	return &option.LogOptions{Disabled: true}
}

// newBox builds a sing-box instance from opts with the core's logging and
// interface binding applied. Every instance this core makes goes through it.
func (c *Core) newBox(ctx context.Context, opts option.Options) (*box.Box, error) {
	if opts.Log == nil {
		opts.Log = c.logOptions()
	}
	c.applyBind(&opts)
	return box.New(box.Options{
		Options: opts,
		Context: boxContext(ctx),
	})
}

// withInbound adds the configured local inbound, if any.
func (c *Core) withInbound(opts *option.Options) error {
	if c.inboundErr != nil {
		return c.inboundErr
	}
	if c.Inbound != nil {
		opts.Inbounds = append(opts.Inbounds, *c.Inbound)
	}
	return nil
}

// preferIPv4 makes sing-box's resolver try A records first. WireGuard
// resolves destinations itself before dialing through the tunnel, and most
// share links give the tunnel an IPv4 address only.
func preferIPv4(opts *option.Options) {
	opts.DNS = &option.DNSOptions{RawDNSOptions: option.RawDNSOptions{
		DNSClientOptions: option.DNSClientOptions{Strategy: option.DomainStrategy(C.DomainStrategyPreferIPv4)},
	}}
}

type FakeInstance struct {
}

func (f *FakeInstance) Start() error {
	return nil
}

func (f *FakeInstance) Close() error {
	return nil
}

func (c *Core) SetInbound(inbound protocol.Protocol) error {
	in, err := craftInbound(inbound)
	if err != nil {
		return err
	}
	c.Inbound, c.inboundErr = in, nil
	return nil
}

func (c *Core) MakeInstance(ctx context.Context, outbound protocol.Protocol) (protocol.Instance, error) {
	out, err := c.craftOutbound(outbound, "", true)
	if err != nil {
		return nil, err
	}

	var opts option.Options
	placeOutbounds(&opts, out)
	if err := c.withInbound(&opts); err != nil {
		return nil, err
	}

	instance, err := c.newBox(ctx, opts)
	if err != nil {
		return nil, err
	}
	return instance, nil
}

const httpClientOutboundTag = "http_client_outbound"

func (c *Core) MakeHttpClient(ctx context.Context, outbound protocol.Protocol, maxDelay time.Duration) (*http.Client, protocol.Instance, error) {
	out, err := c.craftOutbound(outbound, httpClientOutboundTag, true)
	if err != nil {
		return nil, nil, err
	}

	var opts option.Options
	placeOutbounds(&opts, out)
	if len(opts.Endpoints) > 0 {
		preferIPv4(&opts)
	}
	return c.startHttpClient(ctx, opts, httpClientOutboundTag, maxDelay)
}

// startHttpClient starts an instance built from opts and returns an
// http.Client that dials through the outbound tagged tag.
func (c *Core) startHttpClient(ctx context.Context, opts option.Options, tag string, maxDelay time.Duration) (*http.Client, protocol.Instance, error) {
	instance, err := c.newBox(ctx, opts)
	if err != nil {
		return nil, nil, err
	}

	if err := instance.Start(); err != nil {
		instance.Close()
		return nil, nil, err
	}

	// Retrieve the outbound adapter from the router
	outboundAdapter, ok := instance.Outbound().Outbound(tag)
	if !ok {
		var available []string
		for _, o := range instance.Outbound().Outbounds() {
			available = append(available, fmt.Sprintf("%s(%s)", o.Tag(), o.Type()))
		}
		instance.Close()
		return nil, nil, fmt.Errorf("outbound adapter not found for tag: %s. Available: %v", tag, available)
	}

	// Domains are passed through as-is: proxy outbounds resolve them on the
	// server, and WireGuard resolves them with sing-box's DNS router, which
	// honours ctx and the bound interface.
	dial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		return outboundAdapter.DialContext(ctx, network, M.ParseSocksaddr(addr))
	}

	tr := &http.Transport{
		DisableKeepAlives: true,
		DialContext:       withEOFNormalization(dial),
	}

	return &http.Client{
		Transport: &resetRetry{base: tr},
		Timeout:   maxDelay,
	}, instance, nil
}
