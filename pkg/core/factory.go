package core

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/lilendian0x00/xray-knife/v10/pkg/core/protocol"
	"github.com/lilendian0x00/xray-knife/v10/pkg/core/singbox"
	"github.com/lilendian0x00/xray-knife/v10/pkg/core/xray"
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
}

// CoreFactory is the factory method to create concrete cores.
func CoreFactory(coreType CoreType, insecureTLS bool, verbose bool) Core {
	return CoreFactoryWith(coreType, FactoryOptions{InsecureTLS: insecureTLS, Verbose: verbose})
}

// CoreFactoryWith creates a core using the provided FactoryOptions.
func CoreFactoryWith(coreType CoreType, opts FactoryOptions) Core {
	switch coreType {
	case XrayCoreType:
		return xray.NewXrayService(opts.Verbose, opts.InsecureTLS, xray.WithBindInterface(opts.BindInterface))
	case SingboxCoreType:
		return singbox.NewSingboxService(opts.Verbose, opts.InsecureTLS, singbox.WithBindInterface(opts.BindInterface))
	default:
		return nil
	}
}

// AutomaticCore implementation of the Core interface
// Selects Core based on the config link
type AutomaticCore struct {
	xrayCore    Core
	singboxCore Core
}

func (c *AutomaticCore) Name() string {
	return "Automatic"
}

func NewAutomaticCore(verbose bool, allowInsecure bool) Core {
	return NewAutomaticCoreWith(FactoryOptions{InsecureTLS: allowInsecure, Verbose: verbose})
}

// NewAutomaticCoreWith builds an AutomaticCore with the given options
// (e.g. a BindInterface that should apply to both xray and sing-box).
func NewAutomaticCoreWith(opts FactoryOptions) Core {
	return &AutomaticCore{
		xrayCore:    xray.NewXrayService(opts.Verbose, opts.InsecureTLS, xray.WithBindInterface(opts.BindInterface)),
		singboxCore: singbox.NewSingboxService(opts.Verbose, opts.InsecureTLS, singbox.WithBindInterface(opts.BindInterface)),
	}
}

// selectCoreForLink is a helper to determine which core to use based on the protocol scheme.
func (c *AutomaticCore) selectCoreForLink(configLink string) (Core, error) {
	uri, err := url.Parse(configLink)
	if err != nil {
		return nil, err
	}

	switch uri.Scheme {
	case protocol.Hysteria2Identifier, "hy2":
		return c.singboxCore, nil
	case protocol.VmessIdentifier, protocol.VlessIdentifier, protocol.TrojanIdentifier, protocol.ShadowsocksIdentifier, protocol.SocksIdentifier, protocol.WireguardIdentifier:
		return c.xrayCore, nil
	default:
		return nil, fmt.Errorf("unsupported protocol for automatic core: %s", uri.Scheme)
	}
}

// CreateProtocol for AutomaticCore dispatches to the correct underlying core.
func (c *AutomaticCore) CreateProtocol(configLink string) (protocol.Protocol, error) {
	selectedCore, err := c.selectCoreForLink(configLink)
	if err != nil {
		return nil, err
	}
	return selectedCore.CreateProtocol(configLink)
}

// MakeHttpClient dispatches to the correct underlying core.
func (c *AutomaticCore) MakeHttpClient(ctx context.Context, outbound protocol.Protocol, maxDelay time.Duration) (*http.Client, protocol.Instance, error) {
	generalConfig := outbound.ConvertToGeneralConfig()
	selectedCore, err := c.selectCoreForLink(generalConfig.OrigLink)
	if err != nil {
		return nil, nil, err
	}
	return selectedCore.MakeHttpClient(ctx, outbound, maxDelay)
}

// MakeInstance dispatches to the correct underlying core.
func (c *AutomaticCore) MakeInstance(ctx context.Context, outbound protocol.Protocol) (protocol.Instance, error) {
	generalConfig := outbound.ConvertToGeneralConfig()
	selectedCore, err := c.selectCoreForLink(generalConfig.OrigLink)
	if err != nil {
		return nil, err
	}
	return selectedCore.MakeInstance(ctx, outbound)
}

// SetInbound is not applicable for the AutomaticCore itself.
func (c *AutomaticCore) SetInbound(inbound protocol.Protocol) error {
	return errors.New("SetInbound is not supported on AutomaticCore")
}
