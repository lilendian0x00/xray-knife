package singbox

import (
	"context"
	"fmt"
	"net/netip"

	"github.com/lilendian0x00/xray-knife/v10/pkg/core/protocol"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
	"github.com/sagernet/sing/common/logger"
)

// Tun is a programmatic wrapper around sing-box's option.TunInboundOptions.
// It is inbound-only and constructed in code (no URL form).
type Tun struct {
	// InterfaceName is the name sing-box assigns to the TUN device.
	InterfaceName string

	// Address is the list of IPv4/IPv6 prefixes assigned to the interface,
	// e.g. []netip.Prefix{netip.MustParsePrefix("10.66.66.2/24")}.
	// Replaces the legacy Inet4Address / Inet6Address fields removed at
	// sing-box 1.13 final.
	Address []netip.Prefix

	// MTU for the device. 9000 is the sing-box upstream default.
	MTU uint32

	// AutoRoute makes sing-box add a 0.0.0.0/0 + ::/0 default route via
	// the device.
	AutoRoute bool

	// StrictRoute makes the added routes the highest priority.
	StrictRoute bool

	// RouteExcludeAddress lists prefixes that must NOT be captured by the
	// TUN routes (typical use: exclude the upstream proxy IP).
	RouteExcludeAddress []netip.Prefix

	// Stack selects the network stack implementation: "system" or "gvisor".
	// Empty defaults to "system".
	Stack string

	// Remark is a human-readable description, mirroring other inbounds.
	Remark string
}

func (t *Tun) Name() string { return "tun" }

// Parse is a no-op: Tun has no URL representation.
func (t *Tun) Parse() error { return nil }

func (t *Tun) DetailsStr() string {
	return fmt.Sprintf("%s (iface=%s, addr=%v, mtu=%d, autoroute=%v, stack=%s)",
		t.Name(), t.InterfaceName, t.Address, t.MTU, t.AutoRoute, t.Stack)
}

func (t *Tun) GetLink() string { return t.InterfaceName }

func (t *Tun) ConvertToGeneralConfig() protocol.GeneralConfig {
	return protocol.GeneralConfig{Protocol: t.Name(), Remark: t.Remark}
}

// CraftInboundOptions converts Tun into the concrete option.Inbound expected
// by sing-box core. Note: traffic sniffing must be configured via a route
// rule with action "sniff" — the InboundOptions.Sniff* fields were removed
// in sing-box 1.13 final.
func (t *Tun) CraftInboundOptions() *option.Inbound {
	opts := option.TunInboundOptions{
		InterfaceName: t.InterfaceName,
		MTU:           t.MTU,
		Address:       badoption.Listable[netip.Prefix](t.Address),
		AutoRoute:     t.AutoRoute,
		StrictRoute:   t.StrictRoute,
		Stack:         t.Stack,
	}
	if len(t.RouteExcludeAddress) > 0 {
		opts.RouteExcludeAddress = badoption.Listable[netip.Prefix](t.RouteExcludeAddress)
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
