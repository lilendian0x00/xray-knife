package xray

import (
	"github.com/lilendian0x00/xray-knife/v6/pkg/core/protocol"

	"github.com/xtls/xray-core/infra/conf"
)

type Protocol interface {
	Parse() error
	BuildOutboundDetourConfig(allowInsecure bool) (*conf.OutboundDetourConfig, error)
	BuildInboundDetourConfig() (*conf.InboundDetourConfig, error)
	DetailsStr() string
	GetLink() string
	ConvertToGeneralConfig() protocol.GeneralConfig
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
	Type           string      `json:"type"` // XHTTP - Used for HTTP Obfuscation

	//// It's also possible for Vmess to have REALITY...
	//PublicKey string `json:"pbk"`
	//ShortIds  string `json:"sid"` // Mandatory, the shortId list available to the client, which can be used to distinguish different clients
	//SpiderX   string `json:"spx"` // Reality path
	CertFile string `json:"-"`
	KeyFile  string `json:"-"`

	OrigLink string `json:"-"` // Original link
}

type Vless struct {
	LinkVersion    string `json:"-"`
	ID             string `json:"id"`  // UUID
	Address        string `json:"add"` // HOST:PORT
	Encryption     string `json:"encryption"`
	Flow           string `json:"flow"`
	QuicSecurity   string `json:"quicSecurity"`
	Key            string `json:"key"`      // Quic key
	Security       string `json:"security"` // reality or tls
	PublicKey      string `json:"pbk"`
	ShortIds       string `json:"sid"`        // Mandatory, the shortId list available to the client, which can be used to distinguish different clients
	SpiderX        string `json:"spx"`        // Reality path
	HeaderType     string `json:"headerType"` // TCP HTTP Obfuscation
	Host           string `json:"host"`       // HTTP, WS
	Path           string `json:"path"`
	Port           string `json:"port"`
	SNI            string `json:"sni"`           // Server name indication
	ALPN           string `json:"alpn"`          // Application-Layer Protocol Negotiation
	TlsFingerprint string `json:"fp"`            // TLS fingerprint
	AllowInsecure  string `json:"allowInsecure"` // Insecure TLS
	Type           string `json:"type"`          // Network (XHTTP, ...)
	Remark         string `json:"ps"`            // Config's name
	Authority      string `json:"authority"`     // GRPC
	ServiceName    string `json:"serviceName"`   // GRPC
	Mode           string `json:"mode"`          // XHTTP - GRPC
	Extra          string `json:"extra"`         // XHTTP - EXTRA
	CertFile       string `json:"-"`
	KeyFile        string `json:"-"`
	OrigLink       string `json:"-"` // Original link
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
	QuicSecurity   string `json:"quicSecurity"`
	Key            string `json:"key"`        // Quic key
	Security       string `json:"security"`   // tls
	HeaderType     string `json:"headerType"` // TCP HTTP Obfuscation
	Host           string `json:"host"`       // HTTP, WS
	Path           string `json:"path"`
	Port           string `json:"port"`
	SNI            string `json:"sni"`           // Server name indication
	ALPN           string `json:"alpn"`          // Application-Layer Protocol Negotiation
	TlsFingerprint string `json:"fp"`            // TLS fingerprint
	AllowInsecure  string `json:"allowInsecure"` // Insecure TLS
	Type           string `json:"type"`          // Network (XHTTP, ...)
	Remark         string // Config's name
	Authority      string `json:"authority"`   // GRPC
	ServiceName    string `json:"serviceName"` // GRPC
	Mode           string `json:"mode"`        // XHTTP, GRPC

	// Yes, Trojan can have reality too xD
	PublicKey string `json:"pbk"`
	ShortIds  string `json:"sid"` // Mandatory, the shortId list available to the client, which can be used to distinguish different clients
	SpiderX   string `json:"spx"` // Reality path

	OrigLink string `json:"-"` // Original link
}

type Wireguard struct {
	Remark       string
	PublicKey    string `json:"publickey"`
	SecretKey    string `json:"secretkey"`
	PreSharedKey string `json:"presharedkey"`
	Endpoint     string
	LocalAddress string `json:"address"` // Local address IPv4/IPv6 seperated by commas
	Mtu          int32  `json:"mtu"`

	OrigLink string `json:"-"` // Original link
}

type Socks struct {
	Remark   string
	Address  string // HOST:PORT
	Port     string
	Username string // Username
	Password string // Password
	OrigLink string // Original link
}

type Hysteria2 struct {
	Remark        string
	Address       string
	Port          string
	Password      string
	ObfusType     string
	ObfusPassword string
	SNI           string
	Insecure      interface{}
	OrigLink      string // Original link
}
