package core

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/lilendian0x00/xray-knife/v6/pkg/core/protocol"
	"github.com/lilendian0x00/xray-knife/v6/pkg/core/singbox"
	"github.com/lilendian0x00/xray-knife/v6/pkg/core/xray"
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

// CoreFactory is the factory method to create concrete cores.
func CoreFactory(coreType CoreType, insecureTLS bool, verbose bool) Core {
	switch coreType {
	case XrayCoreType:
		return xray.NewXrayService(verbose, insecureTLS)
	case SingboxCoreType:
		return singbox.NewSingboxService(verbose, insecureTLS)
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
	return &AutomaticCore{
		xrayCore:    xray.NewXrayService(verbose, allowInsecure),
		singboxCore: singbox.NewSingboxService(verbose, allowInsecure),
	}
}

// Defined Core for each protocol
var cproto = map[string]Core{
	protocol.VmessIdentifier:       xray.NewXrayService(false, false),
	protocol.VlessIdentifier:       xray.NewXrayService(false, false),
	protocol.ShadowsocksIdentifier: xray.NewXrayService(false, false),
	protocol.TrojanIdentifier:      xray.NewXrayService(false, false),
	protocol.SocksIdentifier:       xray.NewXrayService(false, false),
	protocol.WireguardIdentifier:   xray.NewXrayService(false, false),
	protocol.Hysteria2Identifier:   singbox.NewSingboxService(false, false),
	"hy2":                          singbox.NewSingboxService(false, false),
}

// CreateProtocol for AutomaticCore dispatches to the correct underlying core.
func (c *AutomaticCore) CreateProtocol(configLink string) (protocol.Protocol, error) {
	uri, err := url.Parse(configLink)
	if err != nil {
		return nil, err
	}

	var selectedCore Core
	switch uri.Scheme {
	case protocol.Hysteria2Identifier, "hy2":
		selectedCore = c.singboxCore
	case protocol.VmessIdentifier, protocol.VlessIdentifier, protocol.TrojanIdentifier, protocol.ShadowsocksIdentifier, protocol.SocksIdentifier, protocol.WireguardIdentifier:
		selectedCore = c.xrayCore
	default:
		return nil, fmt.Errorf("unsupported protocol for automatic core: %s", uri.Scheme)
	}

	return selectedCore.CreateProtocol(configLink)
}

// MakeHttpClient dispatches to the correct underlying core.
func (c *AutomaticCore) MakeHttpClient(ctx context.Context, outbound protocol.Protocol, maxDelay time.Duration) (*http.Client, protocol.Instance, error) {
	generalConfig := outbound.ConvertToGeneralConfig()
	uri, err := url.Parse(generalConfig.OrigLink)
	if err != nil {
		return nil, nil, err
	}
	selectedCore, ok := cproto[uri.Scheme]
	if !ok {
		return nil, nil, fmt.Errorf("unsupported protocol for automatic core: %s", uri.Scheme)
	}

	return selectedCore.MakeHttpClient(ctx, outbound, maxDelay)
}

// MakeInstance dispatches to the correct underlying core.
func (c *AutomaticCore) MakeInstance(ctx context.Context, outbound protocol.Protocol) (protocol.Instance, error) {
	generalConfig := outbound.ConvertToGeneralConfig()
	uri, err := url.Parse(generalConfig.OrigLink)
	if err != nil {
		return nil, err
	}
	selectedCore, ok := cproto[uri.Scheme]
	if !ok {
		return nil, fmt.Errorf("unsupported protocol for automatic core: %s", uri.Scheme)
	}
	return selectedCore.MakeInstance(ctx, outbound)
}

// SetInbound is not applicable for the AutomaticCore itself.
func (c *AutomaticCore) SetInbound(inbound protocol.Protocol) error {
	return errors.New("SetInbound is not supported on AutomaticCore")
}
