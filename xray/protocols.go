package xray

import "github.com/xtls/xray-core/infra/conf"

type Protocol interface {
	Parse(configLink string) error
	BuildOutboundDetourConfig(allowInsecure bool) (*conf.OutboundDetourConfig, error)
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

type Vmess struct {
	Version        interface{} `json:"v"`
	Address        string      `json:"add"`
	Aid            interface{} `json:"aid"` // AlterID
	Port           interface{} `json:"port"`
	Security       string      `json:"scy"`
	Host           string      `json:"host"`
	ID             string      `json:"id"`
	Network        string      `json:"net"`
	Path           string      `json:"path"`
	Remark         string      `json:"ps"` // Config's name
	TLS            string      `json:"tls"`
	AllowInsecure  interface{} `json:"allowinsecure"`
	SNI            string      `json:"sni"`  // Server name indication
	ALPN           string      `json:"alpn"` // Application-Layer Protocol Negotiation
	TlsFingerprint string      `json:"fp"`   // TLS fingerprint
	Type           string      `json:"type"` // Used for HTTP Obfuscation
	OrigLink       string      `json:"-"`    // Original link
}

type Vless struct {
	LinkVersion    string `json:"-"`
	ID             string `json:"id"`  // UUID
	Address        string `json:"add"` // HOST:PORT
	Encryption     string `json:"encryption"`
	Flow           string `json:"flow"`
	Security       string `json:"security"` // reality or tls
	PublicKey      string `json:"pbk"`
	ShortIds       string `json:"sid"`        // Mandatory, the shortId list available to the client, which can be used to distinguish different clients
	SpiderX        string `json:"spx"`        // Reality path
	HeaderType     string `json:"headerType"` // TCP HTTP Obfuscation
	Host           string `json:"host"`       // HTTP, WS
	Path           string `json:"path"`
	Port           string `json:"port"`
	SNI            string `json:"sni"`         // Server name indication
	ALPN           string `json:"alpn"`        // Application-Layer Protocol Negotiation
	TlsFingerprint string `json:"fp"`          // TLS fingerprint
	Type           string `json:"type"`        // Network
	Remark         string `json:"ps"`          // Config's name
	ServiceName    string `json:"serviceName"` // GRPC
	Mode           string `json:"mode"`        // GRPC
	OrigLink       string `json:"-"`           // Original link
}

type Shadowsocks struct {
	Address    string
	Port       string
	Encryption string
	Password   string
	Remark     string
	OrigLink   string // Original link
}

type Trojan struct {
	LinkVersion    string `json:"-"`
	Password       string // Password
	Address        string `json:"add"` // HOST:PORT
	Flow           string `json:"flow"`
	Security       string `json:"security"`   // tls
	HeaderType     string `json:"headerType"` // TCP HTTP Obfuscation
	Host           string `json:"host"`       // HTTP, WS
	Path           string `json:"path"`
	Port           string `json:"port"`
	SNI            string `json:"sni"`           // Server name indication
	ALPN           string `json:"alpn"`          // Application-Layer Protocol Negotiation
	TlsFingerprint string `json:"fp"`            // TLS fingerprint
	AllowInsecure  string `json:"allowInsecure"` // Insecure TLS
	Type           string `json:"type"`          // Network
	Remark         string // Config's name
	ServiceName    string `json:"serviceName"` // GRPC
	Mode           string `json:"mode"`        // GRPC
	OrigLink       string `json:"-"`           // Original link
}
