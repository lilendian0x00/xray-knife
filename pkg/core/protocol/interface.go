package protocol

const (
	VmessIdentifier       = "vmess"
	VlessIdentifier       = "vless"
	TrojanIdentifier      = "trojan"
	ShadowsocksIdentifier = "ss"
	WireguardIdentifier   = "wireguard"
	SocksIdentifier       = "socks"
	Hysteria2Identifier   = "hysteria2"
	TunIdentifier         = "tun"
)
const (
	VmessPattern       = `vmess:\/\/[a-zA-Z0-9+/=]+`
	VlessPattern       = `vless:\/\/[a-zA-Z0-9-]+@[a-zA-Z0-9.-]+:[0-9]+(\?([a-zA-Z0-9%=&.-]+))?#?.*`
	TrojanPattern      = `trojan:\/\/[a-zA-Z0-9-_.@]+@[a-zA-Z0-9.-]+:[0-9]+(\?([a-zA-Z0-9%=&.-]+))?#?.*`
	ShadowsocksPattern = ``
)

type Instance interface {
	Start() error
	Close() error
}

type Protocol interface {
	Parse() error
	DetailsStr() string
	GetLink() string
	ConvertToGeneralConfig() GeneralConfig
}

type GeneralConfig struct {
	Protocol       string
	Address        string
	Security       string
	Aid            string
	Host           string
	ID             string
	Network        string
	Path           string
	Port           string
	Remark         string
	TLS            string
	SNI            string
	ALPN           string
	TlsFingerprint string
	Authority      string
	ServiceName    string
	Mode           string
	Type           string
	OrigLink       string
}
