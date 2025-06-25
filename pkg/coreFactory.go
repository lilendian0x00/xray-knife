package pkg

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/lilendian0x00/xray-knife/v4/pkg/protocol"
	"github.com/lilendian0x00/xray-knife/v4/pkg/singbox"
	"github.com/lilendian0x00/xray-knife/v4/pkg/xray"
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
	MakeHttpClient(outbound protocol.Protocol, maxDelay time.Duration) (*http.Client, protocol.Instance, error)
	CreateProtocol(protocolType string) (protocol.Protocol, error)

	MakeInstance(outbound protocol.Protocol) (protocol.Instance, error)
	SetInbound(inbound protocol.Protocol) error
}

// CoreFactory is the factory method to create cores
func CoreFactory(coreType CoreType, insecureTLS bool, verbose bool) Core {
	switch coreType {
	case XrayCoreType:
		return xray.NewXrayService(verbose, insecureTLS)
	case SingboxCoreType:
		return singbox.NewSingboxService(verbose, insecureTLS)
	//case AutoCoreType:
	//	return NewAutomaticCore(false, false)
	default:
		return nil
	}
}

// AutomaticCore implementation of the Core interface
// Selects Core based on the config link
type AutomaticCore struct {
	xrayCore    *xray.Core
	singboxCore *singbox.Core
}

func (c *AutomaticCore) Name() string {
	return "Automatic"
}

func NewAutomaticCore(verbose bool, allowInsecure bool) *AutomaticCore {
	return &AutomaticCore{
		xrayCore:    xray.NewXrayService(verbose, allowInsecure),
		singboxCore: singbox.NewSingboxService(verbose, allowInsecure),
	}
}

// Defined Core for each protocol
var cproto = map[string]string{
	protocol.VmessIdentifier:       "xray",
	protocol.VlessIdentifier:       "xray",
	protocol.ShadowsocksIdentifier: "xray",
	protocol.TrojanIdentifier:      "xray",
	protocol.SocksIdentifier:       "xray",
	protocol.WireguardIdentifier:   "xray",
	protocol.Hysteria2Identifier:   "singbox",
	"hy2":                          "singbox",
}

func (c *AutomaticCore) CreateProtocol(configLink string) (protocol.Protocol, error) {
	uri, err := url.Parse(configLink)
	if err != nil {
		return nil, err
	}

	coreType, ok := cproto[uri.Scheme]
	if !ok {
		return nil, fmt.Errorf("invalid %s protocol", coreType)
	}

	if coreType == "" {
		return nil, errors.New("unsupported protocol")
	}

	var protocol protocol.Protocol

	switch coreType {
	case "xray":
		protocol, err = c.xrayCore.CreateProtocol(configLink)
	case "singbox":
		protocol, err = c.singboxCore.CreateProtocol(configLink)
		// default: // TODO: What?
		// return c.singboxCore.CreateProtocol(configLink)
	}
	if err != nil {
		return nil, err
	}

	err = protocol.Parse()
	if err != nil {
		return nil, err
	}

	return protocol, err
}

//func (c *AutomaticCore) MakeHttpClient(outbound protocol.Protocol) (*http.Client, protocol.Instance, error) {
//	return outbound.
//}
