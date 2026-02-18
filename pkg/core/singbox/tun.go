package singbox

import (
	"context"
	"fmt"

	"github.com/lilendian0x00/xray-knife/v9/pkg/core/protocol"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/logger"
)

type Tun struct {
	// Name of the TUN interface that sing‑box should create.
	InterfaceName string

	// IPv4 address (CIDR notation) assigned to the interface, e.g. "10.66.66.2/24".
	Inet4Address string
	// Optional IPv6 address, e.g. "fdfe:dcba:9876::2/64".
	Inet6Address string

	// MTU for the device. 9000 by default in Sing‑box upstream.
	MTU uint32

	// Whether Sing‑box should automatically add route(s) for 0.0.0.0/0 and ::/0 via the device.
	AutoRoute bool
	// Whether the added routes should be STRICT (highest priority / lowest metric).
	StrictRoute bool

	// Whether layer‑4 sniffing is enabled on packets that enter the stack from this TUN.
	Sniff bool

	// Which network stack implementation to use: "system" or "gvisor".
	// Leave empty for the default ("system").  Added here so callers can tweak it.
	Stack string

	// Optional human readable remark – we expose it mainly for symmetry with other inbounds.
	Remark string
}

// -----------------------------------------------------------------------------
// Protocol interface stubs
// -----------------------------------------------------------------------------

func (t *Tun) Name() string {
	return "tun"
}

// Parse is a no‑op because Tun is constructed programmatically, not from a URL.
func (t *Tun) Parse() error { return nil }

func (t *Tun) DetailsStr() string {
	return fmt.Sprintf("%s (iface=%s, v4=%s, mtu=%d, autoroute=%v)", t.Name(), t.InterfaceName, t.Inet4Address, t.MTU, t.AutoRoute)
}

func (t *Tun) GetLink() string {
	return t.InterfaceName
}

func (t *Tun) ConvertToGeneralConfig() protocol.GeneralConfig {
	return protocol.GeneralConfig{Protocol: t.Name(), Remark: t.Remark}
}

// CraftInboundOptions converts the Tun struct into the concrete option.Inbound
// structure expected by Sing‑box core.
func (t *Tun) CraftInboundOptions() *option.Inbound {

	opts := option.TunInboundOptions{
		InterfaceName: t.InterfaceName,
		MTU:           t.MTU,
		AutoRoute:     t.AutoRoute,
		StrictRoute:   t.StrictRoute,
		Stack:         t.Stack,
	}

	return &option.Inbound{
		Type:    t.Name(),
		Tag:     "TUN_INBOUND",
		Options: &opts,
	}
}

func (t *Tun) CraftOutboundOptions(bool) (*option.Outbound, error) {
	return nil, fmt.Errorf("%s: outbound not supported", t.Name())
}

func (t *Tun) CraftOutbound(context.Context, logger.ContextLogger, bool) (adapter.Outbound, error) {
	return nil, fmt.Errorf("%s: outbound not supported", t.Name())
}
