// Package hosttun runs a sing-box TUN inbound in the root network
// namespace. Captures the host's outbound traffic and routes it through
// the local SOCKS proxy.
//
// DANGER: host-tun replaces the default route. Without careful
// exclusions it WILL kill the active SSH session. See excludes.go.
package hosttun

// Config holds settings for the host-tun setup.
type Config struct {
	// TunName is the TUN interface name. Defaults to "xkt0".
	TunName string
	// TunAddr is the address/CIDR assigned to the TUN device.
	// Defaults to "198.18.0.1/30" (RFC 2544 testing range, avoids
	// collision with most LANs).
	TunAddr string
	// TunAddr6 is the IPv6 address/CIDR assigned to the TUN device.
	// Defaults to a ULA /126. Without an IPv6 address sing-tun installs
	// no IPv6 routes, so on a dual-stack host every IPv6 connection
	// would bypass the tunnel. Empty disables IPv6 capture (the caller
	// is then responsible for blocking IPv6 egress).
	TunAddr6 string
	// TunMTU is the MTU of the TUN device. Defaults to 1500.
	TunMTU uint32

	// RouteTableIndex / RouteRuleIndex are the iproute2 table and the
	// first rule priority sing-tun uses. sing-box defaults to 2022/9000,
	// the same values every other sing-box or mihomo TUN on the host
	// uses, and its teardown deletes every rule in [RuleIndex,
	// RuleIndex+10] — so sharing the defaults would wipe another VPN's
	// rules on exit. Zero lets Start pick a free slot.
	RouteTableIndex int
	RouteRuleIndex  int
	// BypassPriority is the rule priority, just above sing-tun's block,
	// of the "to <upstream> lookup main" rules that keep the active
	// proxy servers off the TUN (see Bypass). Set by Start.
	BypassPriority int

	// ProxyAddr / ProxyPort point at the local SOCKS listener.
	// Typically 127.0.0.1 and the proxy's listen port.
	ProxyAddr string
	ProxyPort uint16
	SocksUser string
	SocksPass string

	// PhysIface is the physical interface used as DefaultInterface
	// for sing-box's routing. Without this, the SOCKS dialer (which
	// must dial 127.0.0.1) and the upstream proxy dial can land on
	// the TUN itself, causing a loop. Required.
	PhysIface string

	// DNS / DNSType are the DNS resolver and transport used inside
	// the tunnel. Defaults: "1.1.1.1" / "udp".
	DNS     string
	DNSType string

	// RouteExcludeCIDRs are destination prefixes excluded from TUN
	// capture for the whole run (LAN, SSH peers, user excludes).
	// Populated by BuildExcludes(); the proxy servers in use are kept off
	// the TUN separately, per rotation, by Bypass.
	RouteExcludeCIDRs []string
	// StrictRoute makes address families without a TUN address
	// unreachable instead of bypassing the tunnel (kill switch).
	StrictRoute bool

	// DirectCIDRs are captured by the TUN only so DNS sent to them is
	// hijacked; any other traffic to them leaves directly on PhysIface
	// (see Excludes.Direct).
	DirectCIDRs []string
}

// DefaultTunAddr6 is the default IPv6 TUN address: a /126 from a ULA
// prefix, so it never collides with a routable LAN prefix.
const DefaultTunAddr6 = "fdfe:dcba:9876::1/126"

// DefaultConfig returns a Config with sensible defaults.
func DefaultConfig(proxyPort uint16) Config {
	return Config{
		TunName:   "xkt0",
		TunAddr:   "198.18.0.1/30",
		TunAddr6:  DefaultTunAddr6,
		TunMTU:    1500,
		ProxyAddr: "127.0.0.1",
		ProxyPort: proxyPort,
		DNS:       "1.1.1.1",
		DNSType:   "udp",
	}
}
