package netns

// Config holds settings for the network namespace tunnel setup.
type Config struct {
	Name      string // namespace name (empty = auto-generated)
	VethHost  string // host-side veth name
	VethNS    string // namespace-side veth name
	HostIP    string // host-side IP
	NSIP      string // namespace-side IP
	Subnet    string // CIDR prefix length, e.g. "/30"
	TunName   string // TUN device name inside ns
	TunAddr   string // TUN address CIDR, e.g. "10.10.0.1/24"
	TunMTU    uint32 // TUN MTU
	ProxyAddr string // host proxy address as seen from ns
	ProxyPort uint16 // host proxy port
	SocksUser string // SOCKS auth username for the host proxy
	SocksPass string // SOCKS auth password for the host proxy
}

// DefaultConfig returns a Config with sensible defaults.
// proxyPort is the port of the host SOCKS proxy.
func DefaultConfig(proxyPort uint16) Config {
	return Config{
		VethHost:  "xk-veth-h",
		VethNS:    "xk-veth-ns",
		HostIP:    "10.200.1.1",
		NSIP:      "10.200.1.2",
		Subnet:    "/30",
		TunName:   "tun0",
		TunAddr:   "10.10.0.1/24",
		TunMTU:    1500,
		ProxyAddr: "10.200.1.1",
		ProxyPort: proxyPort,
	}
}
