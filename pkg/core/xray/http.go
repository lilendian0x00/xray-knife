package xray

import (
	"encoding/json"
	"fmt"
	"net"
	"strconv"

	net2 "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/infra/conf"

	"github.com/lilendian0x00/xray-knife/v9/pkg/core/protocol"
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
	in := &conf.InboundDetourConfig{
		Protocol: h.Name(),
		Tag:      h.Name(),
		Settings: nil,
		StreamSetting: &conf.StreamConfig{
			Network: &p,
		},
		ListenOn: &conf.Address{},
	}

	uint32Value, err := strconv.ParseUint(h.Port, 10, 32)
	if err != nil {
		return nil, fmt.Errorf("error converting port string to uint32: %w", err)
	}

	listenAddr := h.Address
	if net.ParseIP(listenAddr) == nil {
		listenAddr = "0.0.0.0"
	}
	in.ListenOn.Address = net2.ParseAddress(listenAddr)
	in.PortList = &conf.PortList{Range: []conf.PortRange{
		{From: uint32(uint32Value), To: uint32(uint32Value)},
	}}

	oset := json.RawMessage([]byte(`{
	  "allowTransparent": false
	}`))
	in.Settings = &oset

	return in, nil
}

func (h *Http) DetailsStr() string {
	return fmt.Sprintf("Protocol: http\nRemark: %s\nAddress: %s\nPort: %s\n", h.Remark, h.Address, h.Port)
}

func (h *Http) GetLink() string {
	return fmt.Sprintf("http://%s:%s", h.Address, h.Port)
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
