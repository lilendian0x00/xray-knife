package singbox

import (
	"context"

	"github.com/lilendian0x00/xray-knife/v4/pkg/protocol"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/logger"
)

type Protocol interface {
	Parse() error
	DetailsStr() string
	GetLink() string
	ConvertToGeneralConfig() protocol.GeneralConfig
	CraftOutboundOptions(allowInsecure bool) (*option.Outbound, error)
	CraftInboundOptions() *option.Inbound
	CraftOutbound(ctx context.Context, l logger.ContextLogger, allowInsecure bool) (adapter.Outbound, error)
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

	//// It's also possible for Vmess to have REALITY...
	//PublicKey string `json:"pbk"`
	//ShortIds  string `json:"sid"` // Mandatory, the shortId list available to the client, which can be used to distinguish different clients
	//SpiderX   string `json:"spx"` // Reality path

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
	Type           string `json:"type"`          // Network
	Remark         string `json:"ps"`            // Config's name
	ServiceName    string `json:"serviceName"`   // GRPC
	Mode           string `json:"mode"`          // GRPC
	OrigLink       string `json:"-"`             // Original link
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
	Type           string `json:"type"`          // Network
	Remark         string // Config's name
	ServiceName    string `json:"serviceName"` // GRPC
	Mode           string `json:"mode"`        // GRPC

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
	Endpoint     string
	Reserved     string `json:"reserved"`
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
	ObfusType     string `json:"obfs"`
	ObfusPassword string `json:"obfs-password"`
	SNI           string `json:"sni"`
	Insecure      string `json:"insecure"`
	OrigLink      string // Original link
}
