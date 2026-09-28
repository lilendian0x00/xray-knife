package netns

import (
	"errors"
	"fmt"
	"net/netip"
	"regexp"
)

const (
	netnsRunDir = "/var/run/netns"
	netnsEtcDir = "/etc/netns"
)

// Config holds settings for the network namespace tunnel setup.
//
// The namespace holds nothing but loopback and a TUN device. The sing-box
// instance that owns the TUN runs in the host namespace (sing-tun enters
// the target namespace only to create, configure and remove the device),
// so its SOCKS dial reaches the proxy listener on the host loopback and
// no veth pair is needed. With no other link in the namespace, traffic
// cannot fail open to the host when the TUN goes away.
type Config struct {
	Name      string // namespace name
	TunName   string // TUN device name inside ns
	TunAddr   string // TUN address CIDR, e.g. "10.10.0.1/30"
	TunMTU    uint32 // TUN MTU
	ProxyAddr string // proxy listener address as dialed from the host namespace
	ProxyPort uint16 // proxy listener port
	SocksUser string // SOCKS auth username for the host proxy
	SocksPass string // SOCKS auth password for the host proxy
	// DNS is the remote DNS server used for hijacked queries inside the
	// tunnel. Defaults to "1.1.1.1". May be "ip", "ip:port", or for
	// type=https a URL host with optional /path.
	DNS string
	// DNSType selects the DNS transport: udp, tcp, tls, https.
	// Defaults to "udp".
	DNSType string
}

// DefaultConfig returns a Config with sensible defaults. proxyPort is the
// port of the proxy's SOCKS listener on the host loopback.
func DefaultConfig(proxyPort uint16) Config {
	return Config{
		TunName:   "tun0",
		TunAddr:   "10.10.0.1/30",
		TunMTU:    1500,
		ProxyAddr: "127.0.0.1",
		ProxyPort: proxyPort,
		DNS:       "1.1.1.1",
		DNSType:   "udp",
	}
}

// nameRE matches what `ip netns` accepts as a namespace name and keeps it
// a single path element under /var/run/netns and /etc/netns.
var nameRE = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}$`)

// ValidateName rejects namespace names that are not a plain file name
// (e.g. "../../etc"), since the name is joined under /var/run/netns and
// /etc/netns.
func ValidateName(name string) error {
	if !nameRE.MatchString(name) || name == "." || name == ".." {
		return fmt.Errorf("invalid namespace name %q: use up to 64 letters, digits, '_', '-' or '.'", name)
	}
	return nil
}

// resolverAddr returns the address written to the namespace's
// resolv.conf: the TUN peer address. Any UDP/53 packet entering the TUN
// is hijacked by the tunnel's DNS, so the exact address only has to be
// routed into the TUN.
func (c Config) resolverAddr() (string, error) {
	p, err := netip.ParsePrefix(c.TunAddr)
	if err != nil {
		return "", fmt.Errorf("invalid TUN address %q: %w", c.TunAddr, err)
	}
	next := p.Addr().Next()
	if !next.IsValid() || !p.Contains(next) {
		return "", errors.New("TUN prefix has no room for a resolver address")
	}
	return next.String(), nil
}
