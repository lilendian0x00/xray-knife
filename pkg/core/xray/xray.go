package xray

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/lilendian0x00/xray-knife/v11/pkg/core/fragment"
	"github.com/lilendian0x00/xray-knife/v11/pkg/core/protocol"
	"github.com/lilendian0x00/xray-knife/v11/pkg/netbind"

	"github.com/xtls/xray-core/app/dispatcher"
	applog "github.com/xtls/xray-core/app/log"
	"github.com/xtls/xray-core/app/proxyman"
	commlog "github.com/xtls/xray-core/common/log"
	xraynet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/infra/conf"

	// The following deps are necessary as they register handlers in their init functions.
	_ "github.com/xtls/xray-core/app/dispatcher"
	_ "github.com/xtls/xray-core/app/proxyman/inbound"
	_ "github.com/xtls/xray-core/app/proxyman/outbound"
)

// xray-core keeps one process-global log handler. Every NewXrayService
// used to replace it, so creating a quiet core silenced a verbose one.
// The handler is now installed once, and a verbose core wins for good.
var (
	logMu        sync.Mutex
	logInstalled bool
	logVerbose   bool
)

func installLogHandler(verbose bool) {
	logMu.Lock()
	defer logMu.Unlock()
	switch {
	case verbose && !logVerbose:
		commlog.RegisterHandler(commlog.NewLogger(commlog.CreateStderrLogWriter()))
		logVerbose, logInstalled = true, true
	case !verbose && !logInstalled:
		// Override xray-core's default stdout handler (set in common/log
		// init()) so deprecation warnings during config building don't
		// corrupt our output.
		commlog.RegisterHandler(&noOpHandler{})
		logInstalled = true
	}
}

var insecureWarning sync.Once

// warnInsecure tells the user once per process that xray-core ignores an
// insecure-TLS request (see transportSpec.applyOutboundSecurity).
func (c *Core) warnInsecure(p Protocol) {
	type insecureRequester interface{ wantsInsecure() bool }
	r, ok := p.(insecureRequester)
	if !ok || !(c.AllowInsecure || r.wantsInsecure()) {
		return
	}
	if ts, ok := p.(interface{ transport() transportSpec }); ok {
		spec := ts.transport()
		if spec.security() != "tls" || spec.PinnedPeerCertSha256 != "" {
			return
		}
	}
	insecureWarning.Do(func() {
		fmt.Fprintln(os.Stderr, "xray-knife: xray-core cannot skip TLS certificate verification; "+
			"allowInsecure/--insecure has no effect on the xray core. Use the automatic or sing-box core, "+
			"or pin the certificate with pcs=<sha256>.")
	})
}

// noOpHandler discards all log messages.
type noOpHandler struct{}

func (*noOpHandler) Handle(msg commlog.Message) {}

type Core struct {
	Inbound Protocol

	// Log
	Verbose  bool
	LogType  applog.LogType
	LogLevel commlog.Severity

	AllowInsecure bool

	// bindErr is why BindInterface is unusable (it does not exist); every
	// instance build reports it rather than silently dialing unbound.
	bindErr error

	// BindInterface, when set, pins the dials of every instance built by
	// this core to the named OS interface (e.g. "eth0") through the
	// outbound's sockopt.interface. It is per core: jobs with different
	// (or no) bindings in one process don't affect each other.
	BindInterface string

	// Fragment, when enabled, fragments the first hop's TLS handshake
	// (and sends UDP noise) to get past SNI-based DPI. It is applied as a
	// finalmask on that hop's own stream settings (see applyFragment).
	Fragment *fragment.Options
}

func (c *Core) Name() string {
	return "xray"
}

type ServiceOption = func(c *Core)

func WithCustomLogLevel(logType applog.LogType, LogLevel commlog.Severity) ServiceOption {
	return func(c *Core) {
		c.LogType = logType
		c.LogLevel = LogLevel
	}
}

func WithInbound(inbound Protocol) ServiceOption {
	return func(c *Core) {
		c.Inbound = inbound
	}
}

// WithBindInterface configures the OS interface to bind outbound dials
// to. Empty string disables binding.
func WithBindInterface(iface string) ServiceOption {
	return func(c *Core) {
		c.BindInterface = strings.TrimSpace(iface)
	}
}

// WithFragment enables TLS/TCP fragmentation and UDP noise on the first
// hop. A nil or disabled value turns it off.
func WithFragment(f *fragment.Options) ServiceOption {
	return func(c *Core) {
		if f.Enabled() {
			c.Fragment = f.Clone()
		} else {
			c.Fragment = nil
		}
	}
}

func NewXrayService(verbose bool, allowInsecure bool, opts ...ServiceOption) *Core {
	s := &Core{
		Inbound:       nil,
		Verbose:       verbose,
		LogType:       applog.LogType_None,
		LogLevel:      commlog.Severity_Unknown,
		AllowInsecure: allowInsecure,
	}

	if verbose {
		s.LogType = applog.LogType_Console
		s.LogLevel = commlog.Severity_Debug
	}
	installLogHandler(verbose)

	for _, opt := range opts {
		opt(s)
	}
	if s.BindInterface != "" {
		if _, err := netbind.New(s.BindInterface); err != nil {
			s.bindErr = err
		}
	}
	return s
}

// buildable reports a configuration problem that makes every instance of
// this core unusable.
func (c *Core) buildable() error {
	if c.bindErr != nil {
		return fmt.Errorf("bind interface: %w", c.bindErr)
	}
	return nil
}

// asProtocol converts a protocol created by CreateProtocol back to the
// xray type, rejecting protocols built by another core.
func asProtocol(p protocol.Protocol) (Protocol, error) {
	x, ok := p.(Protocol)
	if !ok {
		return nil, fmt.Errorf("xray core cannot run %T (it was created by another core)", p)
	}
	return x, nil
}

func (c *Core) SetInbound(inbound protocol.Protocol) error {
	p, err := asProtocol(inbound)
	if err != nil {
		return err
	}
	c.Inbound = p
	return nil
}

// usesUDP reports whether an outbound dials its server over UDP.
func usesUDP(ob *conf.OutboundDetourConfig) bool {
	switch strings.ToLower(ob.Protocol) {
	case "wireguard", "hysteria":
		return true
	}
	if ob.StreamSetting != nil && ob.StreamSetting.Network != nil {
		switch strings.ToLower(string(*ob.StreamSetting.Network)) {
		case "kcp", "mkcp", "hysteria":
			return true
		}
	}
	return false
}

// fragmentApplies reports whether fragmentation helps an entry hop: TCP
// fragments only matter over TCP, noise only over UDP.
func (c *Core) fragmentApplies(ob *conf.OutboundDetourConfig) bool {
	if !c.Fragment.Enabled() {
		return false
	}
	if usesUDP(ob) {
		return len(c.Fragment.Noises) > 0
	}
	return c.Fragment.FragmentsTCP()
}

// prepareEntry configures the outbound that dials the network directly
// (the single outbound of an instance, or hop 0 of a chain): it binds it
// to BindInterface and applies Fragment. server is the hop's server
// address; loopback, link-local and multicast servers are never bound
// (they are unreachable through a physical interface).
func (c *Core) prepareEntry(ob *conf.OutboundDetourConfig, server string) error {
	bind := c.BindInterface != "" && !localAddress(server)
	useFragment := c.fragmentApplies(ob)
	if !bind && !useFragment {
		return nil
	}
	if ob.StreamSetting == nil {
		ob.StreamSetting = &conf.StreamConfig{}
	}
	if bind {
		if ob.StreamSetting.SocketSettings == nil {
			ob.StreamSetting.SocketSettings = &conf.SocketConfig{}
		}
		inheritSockopt(ob.StreamSetting)
		ob.StreamSetting.SocketSettings.Interface = c.BindInterface
	}
	if !useFragment {
		return nil
	}
	return c.applyFragment(ob.StreamSetting, usesUDP(ob))
}

// inheritSockopt makes the stream's secondary connections use its sockopt
// (and so its bind interface or chain marker): the xhttp download leg
// ("penetrate") and ECH config lookups.
func inheritSockopt(s *conf.StreamConfig) {
	s.SocketSettings.Penetrate = true
	if s.TLSSettings != nil && s.TLSSettings.ECHSocketSettings == nil {
		s.TLSSettings.ECHSocketSettings = s.SocketSettings
	}
}

// localAddress reports whether host is a loopback, link-local, multicast
// or unspecified address (or "localhost"), which binding to an outside
// interface would make unreachable, as sing's bind control also skips.
func localAddress(host string) bool {
	host = unbracket(strings.TrimSpace(host))
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && (ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsMulticast() || ip.IsUnspecified())
}

// applyFragment adds Fragment to the stream's finalmask: a "fragment" TCP
// mask (the same packets/length/interval/maxSplit semantics as freedom's
// fragment, applied to the raw connection under TLS/REALITY) or a "noise"
// UDP mask. Being per stream, it needs no dialerProxy and so none of
// xray-core's process-global dialer state (see instances.go).
func (c *Core) applyFragment(s *conf.StreamConfig, udp bool) error {
	f := c.Fragment
	var mask conf.Mask
	if udp {
		items := make([]map[string]interface{}, 0, len(f.Noises))
		for _, n := range f.Noises {
			item := map[string]interface{}{"delay": n.Delay.String()}
			if n.Type == "rand" {
				item["rand"] = n.Packet
			} else {
				item["type"] = n.Type
				item["packet"] = n.Packet
			}
			items = append(items, item)
		}
		raw, err := json.Marshal(map[string]interface{}{"noise": items})
		if err != nil {
			return fmt.Errorf("marshal noise settings: %w", err)
		}
		msg := json.RawMessage(raw)
		mask = conf.Mask{Type: "noise", Settings: &msg}
	} else {
		settings := map[string]interface{}{
			"packets": f.Packets,
			"length":  f.Length.String(),
			"delay":   f.Interval.String(),
		}
		if !f.MaxSplit.IsZero() {
			settings["maxSplit"] = f.MaxSplit.String()
		}
		raw, err := json.Marshal(settings)
		if err != nil {
			return fmt.Errorf("marshal fragment settings: %w", err)
		}
		msg := json.RawMessage(raw)
		mask = conf.Mask{Type: "fragment", Settings: &msg}
	}
	if s.FinalMask == nil {
		s.FinalMask = &conf.FinalMask{}
	}
	// Masks apply outermost first, so appending keeps noise innermost:
	// its packets leave raw, not wrapped by e.g. Hysteria2's salamander.
	if udp {
		s.FinalMask.Udp = append(s.FinalMask.Udp, mask)
	} else {
		s.FinalMask.Tcp = append(s.FinalMask.Tcp, mask)
	}
	return nil
}

// newInstance builds an xray instance from outbound configs. The first
// outbound is the default route for inbound and core.Dial traffic.
//
// Outbound tags get a per-instance prefix, so chain hops reach the right
// handlers even with other instances in the process (see instances.go).
func (c *Core) newInstance(outbounds []*conf.OutboundDetourConfig) (*core.Instance, error) {
	id := instanceSeq.Add(1)
	renameTags(tagPrefix(id), outbounds)
	clientConfig, err := c.instanceConfig(outbounds)
	if err != nil {
		return nil, err
	}
	return newCoreInstance(id, clientConfig)
}

// instanceConfig assembles the core.Config shared by every instance this
// core builds: apps, the configured inbound and the given outbounds.
func (c *Core) instanceConfig(outbounds []*conf.OutboundDetourConfig) (*core.Config, error) {
	clientConfig := &core.Config{
		App: []*serial.TypedMessage{
			serial.ToTypedMessage(&dispatcher.Config{}),
			serial.ToTypedMessage(&proxyman.OutboundConfig{}),
		},
	}
	// The log app re-registers xray's global handler when an instance is
	// created. Leave it out for quiet cores so they don't silence a
	// verbose one; their messages go to whatever handler is installed.
	if c.LogType != applog.LogType_None {
		clientConfig.App = append([]*serial.TypedMessage{serial.ToTypedMessage(&applog.Config{
			ErrorLogType:  c.LogType,
			AccessLogType: c.LogType,
			ErrorLogLevel: c.LogLevel,
			EnableDnsLog:  false,
		})}, clientConfig.App...)
	}
	if c.Inbound != nil {
		clientConfig.App = append(clientConfig.App, serial.ToTypedMessage(&proxyman.InboundConfig{}))
		ibc, err := c.Inbound.BuildInboundDetourConfig()
		if err != nil {
			return nil, err
		}
		ibcBuilt, err := ibc.Build()
		if err != nil {
			return nil, err
		}
		clientConfig.Inbound = []*core.InboundHandlerConfig{ibcBuilt}
	}
	for _, ob := range outbounds {
		built, err := buildOutbound(ob)
		if err != nil {
			return nil, err
		}
		clientConfig.Outbound = append(clientConfig.Outbound, built)
	}
	return clientConfig, nil
}

// buildOutbound turns an outbound config into its handler config, naming
// the outbound in errors when it has a meaningful tag.
func buildOutbound(ob *conf.OutboundDetourConfig) (*core.OutboundHandlerConfig, error) {
	built, err := ob.Build()
	if err != nil {
		if tag := displayTag(ob.Tag); tag != "" && tag != "proxy" {
			return nil, fmt.Errorf("outbound %s: %w", tag, err)
		}
		return nil, err
	}
	return built, nil
}

func (c *Core) MakeInstance(ctx context.Context, outbound protocol.Protocol) (protocol.Instance, error) {
	if err := c.buildable(); err != nil {
		return nil, err
	}
	out, err := asProtocol(outbound)
	if err != nil {
		return nil, err
	}
	c.warnInsecure(out)
	ob, err := out.BuildOutboundDetourConfig(c.AllowInsecure)
	if err != nil {
		return nil, err
	}
	if err := c.prepareEntry(ob, out.ConvertToGeneralConfig().Address); err != nil {
		return nil, err
	}
	inst, err := c.newInstance([]*conf.OutboundDetourConfig{ob})
	if err != nil {
		return nil, err // not a typed-nil Instance
	}
	return inst, nil
}

// httpClientFor returns an http.Client whose dials enter the instance's
// default outbound.
func httpClientFor(inst *core.Instance, maxDelay time.Duration) *http.Client {
	tr := &http.Transport{
		DisableKeepAlives: true,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			dest, err := xraynet.ParseDestination(fmt.Sprintf("%s:%s", network, addr))
			if err != nil {
				return nil, err
			}
			return core.Dial(ctx, inst, dest)
		},
	}
	return &http.Client{
		Transport: tr,
		Timeout:   maxDelay,
	}
}

func (c *Core) MakeHttpClient(ctx context.Context, outbound protocol.Protocol, maxDelay time.Duration) (*http.Client, protocol.Instance, error) {
	instance, err := c.MakeInstance(ctx, outbound)
	if err != nil {
		return nil, nil, err
	}
	return httpClientFor(instance.(*core.Instance), maxDelay), instance, nil
}
