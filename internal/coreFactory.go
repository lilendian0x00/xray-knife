package internal

import (
	"github.com/lilendian0x00/xray-knife/internal/protocol"
	"github.com/lilendian0x00/xray-knife/internal/singbox"
	"github.com/lilendian0x00/xray-knife/internal/xray"
	"net/http"
	"time"
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
func CoreFactory(coreType CoreType) Core {
	switch coreType {
	case XrayCoreType:
		return xray.NewXrayService(false, false)
	case SingboxCoreType:
		return singbox.NewSingboxService(false, false)
	//case AutoCoreType:
	//	return NewAutomaticCore(false, false)
	default:
		return nil
	}
}

// AutomaticCore implementation of the Core interface
// Selects Core based on the config link
//type AutomaticCore struct {
//	xrayCore 		*xray.Core
//	singboxCore 	*singbox.Core
//}
//
//
//func (c *AutomaticCore) Name() string {
//	return "Automatic"
//}
//
//func NewAutomaticCore(verbose bool, allowInsecure bool) *AutomaticCore {
//	return &AutomaticCore{
//		xrayCore: xray.NewXrayService(verbose, allowInsecure),
//		singboxCore: singbox.NewSingboxService(verbose, allowInsecure),
//	}
//}
//
//
//// Defined Core for each protocol
//var cproto = map[string]string{
//	protocol.VmessIdentifier:       "xray",
//	protocol.VlessIdentifier:       "xray",
//	protocol.ShadowsocksIdentifier: "xray",
//	protocol.TrojanIdentifier:      "xray",
//	protocol.SocksIdentifier:       "xray",
//	protocol.WireguardIdentifier:   "xray",
//	protocol.Hysteria2Identifier:   "singbox",
//}
//
//func (c *AutomaticCore) CreateProtocol(configLink string) (protocol.Protocol, error) {
//	// Parse url
//	uri, err := url.Parse(configLink)
//	if err != nil {
//		return nil, err
//	}
//
//	coreType, ok := cproto[uri.Scheme]
//	if !ok {
//		return nil, errors.New(fmt.Sprintf("invalid %s protocol", coreType))
//	}
//
//	switch coreType {
//	case "xray":
//		return c.xrayCore.CreateProtocol(configLink)
//	case "singbox":
//		return c.singboxCore.CreateProtocol(configLink)
//	default: // TODO: What?
//		return c.singboxCore.CreateProtocol(configLink)
//	}
//}

//func (c *AutomaticCore) MakeHttpClient(outbound protocol.Protocol) (*http.Client, protocol.Instance, error) {
//	return outbound.
//}
