package core

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/lilendian0x00/xray-knife/v11/pkg/core/fragment"
	"github.com/lilendian0x00/xray-knife/v11/pkg/core/mtproto"
	"github.com/lilendian0x00/xray-knife/v11/pkg/core/protocol"
	"github.com/lilendian0x00/xray-knife/v11/pkg/core/singbox"
	"github.com/lilendian0x00/xray-knife/v11/pkg/core/xray"
)

type CoreType uint8

const (
	XrayCoreType CoreType = iota
	SingboxCoreType
	AutoCoreType
)

// Core interface that both xray-Core and sing-box must implement
type Core interface {
	Name() string
	MakeHttpClient(ctx context.Context, outbound protocol.Protocol, maxDelay time.Duration) (*http.Client, protocol.Instance, error)
	CreateProtocol(protocolType string) (protocol.Protocol, error)
	MakeInstance(ctx context.Context, outbound protocol.Protocol) (protocol.Instance, error)
	SetInbound(inbound protocol.Protocol) error
}

// FactoryOptions configures core construction. Zero value is equivalent
// to the legacy CoreFactory(coreType, false, false) call.
type FactoryOptions struct {
	InsecureTLS bool
	Verbose     bool
	// BindInterface pins all outbound dials of the constructed core to
	// the named OS interface (e.g. "eth0"). Empty disables binding.
	BindInterface string
	// Fragment splits the first hop's TLS handshake (and optionally sends
	// UDP noise) to get past SNI-based DPI. Nil disables it.
	Fragment *fragment.Options
}

// CoreFactory is the factory method to create concrete cores.
func CoreFactory(coreType CoreType, insecureTLS bool, verbose bool) Core {
	return CoreFactoryWith(coreType, FactoryOptions{InsecureTLS: insecureTLS, Verbose: verbose})
}

// CoreFactoryWith creates a core using the provided FactoryOptions.
func CoreFactoryWith(coreType CoreType, opts FactoryOptions) Core {
	switch coreType {
	case XrayCoreType:
		return newXray(opts)
	case SingboxCoreType:
		return newSingbox(opts)
	case AutoCoreType:
		return NewAutomaticCoreWith(opts)
	default:
		return nil
	}
}

func newXray(opts FactoryOptions) *xray.Core {
	return xray.NewXrayService(opts.Verbose, opts.InsecureTLS,
		xray.WithBindInterface(opts.BindInterface),
		xray.WithFragment(opts.Fragment))
}

func newSingbox(opts FactoryOptions) *singbox.Core {
	return singbox.NewSingboxService(opts.Verbose, opts.InsecureTLS,
		singbox.WithBindInterface(opts.BindInterface),
		singbox.WithFragment(opts.Fragment))
}

// AutomaticCore implementation of the Core interface
// Selects Core based on the config link
type AutomaticCore struct {
	xrayCore    Core
	singboxCore Core
	mtprotoCore Core
	insecure    bool
}

func (c *AutomaticCore) Name() string {
	return "Automatic"
}

func NewAutomaticCore(verbose bool, allowInsecure bool) Core {
	return NewAutomaticCoreWith(FactoryOptions{InsecureTLS: allowInsecure, Verbose: verbose})
}

// NewAutomaticCoreWith builds an AutomaticCore with the given options
// (e.g. a BindInterface or Fragment that should apply to both cores).
func NewAutomaticCoreWith(opts FactoryOptions) Core {
	return &AutomaticCore{
		xrayCore:    newXray(opts),
		singboxCore: newSingbox(opts),
		mtprotoCore: mtproto.NewCore(),
		insecure:    opts.InsecureTLS,
	}
}

// selectCoreForLink is a helper to determine which core to use based on the protocol scheme.
func (c *AutomaticCore) selectCoreForLink(configLink string) (Core, error) {
	configLink = xray.NormalizeLink(configLink)
	if mtproto.IsProxyLink(configLink) {
		return c.mtprotoCore, nil
	}
	// Read the scheme without url.Parse, which rejects remarks like "#100%".
	scheme, _, found := strings.Cut(configLink, "://")
	if !found {
		return nil, fmt.Errorf("not a share link (no scheme): %q", truncate(configLink, 32))
	}

	switch scheme {
	case protocol.Hysteria2Identifier, "hy2",
		// Only sing-box implements these.
		protocol.HysteriaIdentifier, protocol.TuicIdentifier, protocol.AnyTLSIdentifier, protocol.SSHIdentifier:
		return c.singboxCore, nil
	case protocol.HTTPIdentifier, protocol.HTTPSIdentifier:
		// t.me MTProto links are https too; they were routed above. Web
		// URLs (subscription addresses and the like) are not proxies.
		if !singbox.IsHTTPProxyLink(configLink) {
			// No link in the message: it may carry credentials.
			return nil, errors.New("not a proxy share link (an http(s) proxy needs host:port and no path)")
		}
		return c.singboxCore, nil
	case protocol.VmessIdentifier, protocol.VlessIdentifier, protocol.TrojanIdentifier, protocol.ShadowsocksIdentifier,
		protocol.SocksIdentifier, "socks5", "socks5h", protocol.WireguardIdentifier:
		return c.xrayCore, nil
	default:
		return nil, fmt.Errorf("unsupported protocol for automatic core: %s", scheme)
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// preferSingbox reports whether a link that would go to xray-core needs
// sing-box instead (see xray.SingboxReason).
func (c *AutomaticCore) preferSingbox(link string) bool {
	p, err := c.xrayCore.CreateProtocol(link)
	if err != nil {
		return false
	}
	if err := p.Parse(); err != nil {
		return false // let the xray parser report the problem
	}
	xp, ok := p.(xray.Protocol)
	return ok && xray.SingboxReason(xp, c.insecure) != ""
}

// CreateProtocol for AutomaticCore dispatches to the correct underlying core.
func (c *AutomaticCore) CreateProtocol(configLink string) (protocol.Protocol, error) {
	configLink = xray.NormalizeLink(configLink)
	selectedCore, err := c.selectCoreForLink(configLink)
	if err != nil {
		return nil, err
	}
	if selectedCore == c.xrayCore && c.preferSingbox(configLink) {
		selectedCore = c.singboxCore
	}
	return selectedCore.CreateProtocol(configLink)
}

// coreFor returns the core that created outbound. Protocols carry their
// core's concrete type, which is the only reliable signal once
// CreateProtocol has moved a link to sing-box.
func (c *AutomaticCore) coreFor(outbound protocol.Protocol) (Core, error) {
	switch outbound.(type) {
	case *mtproto.MTProto:
		return c.mtprotoCore, nil
	case xray.Protocol:
		return c.xrayCore, nil
	case singbox.Protocol:
		return c.singboxCore, nil
	}
	return c.selectCoreForLink(outbound.ConvertToGeneralConfig().OrigLink)
}

// MakeHttpClient dispatches to the correct underlying core.
func (c *AutomaticCore) MakeHttpClient(ctx context.Context, outbound protocol.Protocol, maxDelay time.Duration) (*http.Client, protocol.Instance, error) {
	selectedCore, err := c.coreFor(outbound)
	if err != nil {
		return nil, nil, err
	}
	return selectedCore.MakeHttpClient(ctx, outbound, maxDelay)
}

// MakeInstance dispatches to the correct underlying core.
func (c *AutomaticCore) MakeInstance(ctx context.Context, outbound protocol.Protocol) (protocol.Instance, error) {
	selectedCore, err := c.coreFor(outbound)
	if err != nil {
		return nil, err
	}
	return selectedCore.MakeInstance(ctx, outbound)
}

// SetInbound is not applicable for the AutomaticCore itself.
func (c *AutomaticCore) SetInbound(inbound protocol.Protocol) error {
	return errors.New("SetInbound is not supported on AutomaticCore")
}
