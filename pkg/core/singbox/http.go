package singbox

import (
	"context"
	"fmt"
	"net"

	"github.com/lilendian0x00/xray-knife/v11/pkg/core/protocol"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/logger"
)

// Http is the inbound used in system proxy mode.
// sing-box calls it "mixed" because it handles both HTTP and SOCKS5.
type Http struct {
	Remark  string
	Address string
	Port    string
}

func (h *Http) Name() string { return "mixed" }

func (h *Http) Parse() error { return nil }

func (h *Http) DetailsStr() string {
	return fmt.Sprintf("Protocol: http\nRemark: %s\nAddress: %s\nPort: %s\n", h.Remark, h.Address, h.Port)
}

func (h *Http) GetLink() string {
	return "http://" + net.JoinHostPort(serverHost(h.Address), h.Port)
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

func (h *Http) CraftInboundOptions() (*option.Inbound, error) {
	listen, err := listenOptions(h.Address, h.Port)
	if err != nil {
		return nil, err
	}
	opts := option.HTTPMixedInboundOptions{ListenOptions: listen}

	return &option.Inbound{
		Type:    h.Name(),
		Options: &opts,
	}, nil
}

func (h *Http) CraftOutboundOptions(allowInsecure bool) (*option.Outbound, error) {
	return nil, fmt.Errorf("HTTP outbound is not supported")
}

func (h *Http) CraftOutbound(ctx context.Context, l logger.ContextLogger, allowInsecure bool) (adapter.Outbound, error) {
	return nil, fmt.Errorf("HTTP outbound is not supported")
}
