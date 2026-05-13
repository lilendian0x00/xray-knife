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
	// TunMTU is the MTU of the TUN device. Defaults to 1500.
	TunMTU uint32

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
	// capture. Populated by buildExcludes() — callers may add more.
	RouteExcludeCIDRs []string
}

// DefaultConfig returns a Config with sensible defaults.
func DefaultConfig(proxyPort uint16) Config {
	return Config{
		TunName:   "xkt0",
		TunAddr:   "198.18.0.1/30",
		TunMTU:    1500,
		ProxyAddr: "127.0.0.1",
		ProxyPort: proxyPort,
		DNS:       "1.1.1.1",
		DNSType:   "udp",
	}
}
