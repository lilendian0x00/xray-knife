package singbox

import (
	"context"

	"github.com/lilendian0x00/xray-knife/v11/pkg/core/protocol"

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
	CraftInboundOptions() (*option.Inbound, error)
	CraftOutbound(ctx context.Context, l logger.ContextLogger, allowInsecure bool) (adapter.Outbound, error)
	Name() string
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
	// Plugin is a SIP003 plugin sing-box implements natively
	// ("obfs-local" or "v2ray-plugin"); PluginOptions are its "k=v;k=v" args.
	Plugin        string
	PluginOptions string
	OrigLink      string // Original link
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
	PreSharedKey string `json:"presharedkey"`
	Keepalive    int32  `json:"keepalive"` // Persistent keepalive, seconds

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

// Tuic is a TUIC v5 link (see tuic.go for the accepted parameters).
type Tuic struct {
	Remark            string
	Address           string
	Port              string
	UUID              string
	Password          string
	CongestionControl string
	UDPRelayMode      string
	ALPN              string
	SNI               string
	DisableSNI        bool
	Insecure          bool
	ZeroRTT           bool
	OrigLink          string
}

// AnyTLS is an AnyTLS link (see anytls.go).
type AnyTLS struct {
	Remark         string
	Address        string
	Port           string
	Password       string
	Security       string // "tls" or "reality"
	SNI            string
	ALPN           string
	TlsFingerprint string
	Insecure       bool
	PublicKey      string // REALITY
	ShortID        string // REALITY
	OrigLink       string
}

// Hysteria is a Hysteria v1 link (see hysteria.go).
type Hysteria struct {
	Remark       string
	Address      string
	Port         string
	Auth         string
	SNI          string
	ALPN         string
	Insecure     bool
	UpMbps       int
	DownMbps     int
	ObfsPassword string // xplus
	ServerPorts  []string
	OrigLink     string
}

// SSH is an SSH tunnel link (see ssh.go).
type SSH struct {
	Remark               string
	Address              string
	Port                 string
	User                 string
	Password             string
	PrivateKey           string // PEM
	PrivateKeyPassphrase string
	HostKeys             []string // authorized_keys format; empty accepts any host key
	OrigLink             string

	passphrases []string     // decodings of pkp, tried in order
	key         *sshKeyCache // decrypted PrivateKey, filled on first Craft
}

type Hysteria2 struct {
	Remark        string
	Address       string
	Port          string
	Password      string
	ObfusType     string `json:"obfs"`
	ObfusPassword string `json:"obfs-password"`
	SNI           string `json:"sni"`
	ALPN          string `json:"alpn"`
	Insecure      string `json:"insecure"`
	// PinSHA256 is the link's certificate pin. It is kept for display and
	// dedup only: sing-box can pin a public key but not a certificate hash.
	PinSHA256 string `json:"pinSHA256"`
	// ServerPorts are port-hopping ranges in sing-box's "start:end" form.
	ServerPorts []string
	OrigLink    string // Original link
}
