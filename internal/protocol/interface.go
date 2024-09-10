package protocol

const (
	VmessIdentifier       = "vmess"
	VlessIdentifier       = "vless"
	TrojanIdentifier      = "trojan"
	ShadowsocksIdentifier = "ss"
	WireguardIdentifier   = "wireguard"
	SocksIdentifier       = "socks"
	Hysteria2Identifier   = "hysteria2"
)

type Instance interface {
	Start() error
	Close() error
}

type Protocol interface {
	Parse() error
	DetailsStr() string
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
	ServiceName    string
	Mode           string
	Type           string
	OrigLink       string
}
