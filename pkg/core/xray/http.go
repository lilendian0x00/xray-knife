package xray

import (
	"fmt"
	"net"

	"github.com/xtls/xray-core/infra/conf"

	"github.com/lilendian0x00/xray-knife/v11/pkg/core/protocol"
)

// Http is a minimal HTTP proxy protocol used for system proxy mode inbound.
type Http struct {
	Remark  string
	Address string
	Port    string
}

func (h *Http) Name() string { return "http" }

func (h *Http) Parse() error { return nil }

func (h *Http) BuildOutboundDetourConfig(allowInsecure bool) (*conf.OutboundDetourConfig, error) {
	return nil, fmt.Errorf("HTTP outbound is not supported")
}

func (h *Http) BuildInboundDetourConfig() (*conf.InboundDetourConfig, error) {
	p := conf.TransportProtocol("tcp")
	settings := map[string]interface{}{"allowTransparent": false}
	return inboundDetour(h.Name(), h.Address, h.Port, settings, &conf.StreamConfig{Network: &p})
}

func (h *Http) DetailsStr() string {
	return fmt.Sprintf("Protocol: http\nRemark: %s\nAddress: %s\nPort: %s\n", h.Remark, h.Address, h.Port)
}

func (h *Http) GetLink() string {
	return "http://" + net.JoinHostPort(h.Address, h.Port)
}

func (h *Http) ConvertToGeneralConfig() protocol.GeneralConfig {
	return protocol.GeneralConfig{
		Protocol: "http",
		Remark:   h.Remark,
		Address:  h.Address,
		Port:     h.Port,
		Network:  "tcp",
		OrigLink: h.GetLink(),
	}
}
