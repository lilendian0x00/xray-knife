package xray

import "github.com/xtls/xray-core/infra/conf"

type Protocol interface {
	Parse(configLink string) error
	BuildOutboundDetourConfig() (*conf.OutboundDetourConfig, error)
	DetailsStr() string
	ConvertToGeneralConfig() (GeneralConfig, error)
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
	Version        string `json:"v"`
	Address        string `json:"add"`
	Aid            string `json:"aid"` // AlterID
	Port           string `json:"port"`
	Security       string `json:"scy"`
	Host           string `json:"host"`
	ID             string `json:"id"`
	Network        string `json:"net"`
	Path           string `json:"path"`
	Remark         string `json:"ps"` // Config's name
	TLS            string `json:"tls"`
	SNI            string `json:"sni"`  // Server name indication
	ALPN           string `json:"alpn"` // Application-Layer Protocol Negotiation
	TlsFingerprint string `json:"fp"`   // TLS fingerprint
	Type           string `json:"type"` // Used for HTTP Obfuscation
	OrigLink       string `json:"-"`    // Original link
}

type Vless struct {
	LinkVersion    string `json:"-"`
	ID             string `json:"id"`  // UUID
	Address        string `json:"add"` // IP:PORT
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
	Type           string `json:"type"`        // Used for HTTP Obfuscation
	Remark         string `json:"ps"`          // Config's name
	ServiceName    string `json:"serviceName"` // GRPC
	Mode           string `json:"mode"`        // GRPC
	OrigLink       string `json:"-"`           // Original link
}
