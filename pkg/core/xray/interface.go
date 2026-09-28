package xray

import (
	"github.com/lilendian0x00/xray-knife/v11/pkg/core/protocol"

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

	// PinnedPeerCertSha256 pins the server certificate (share-link "pcs"):
	// comma-separated SHA-256 hex, colons allowed. Maps to xray-core's
	// tlsSettings.pinnedPeerCertSha256.
	PinnedPeerCertSha256 string `json:"pcs,omitempty"`
	// VerifyPeerCertByName ("vcn") verifies the server certificate against
	// these names instead of the SNI (xray tlsSettings.verifyPeerCertByName).
	VerifyPeerCertByName string `json:"vcn,omitempty"`
	// ECHConfigList ("ech") enables Encrypted Client Hello.
	ECHConfigList string `json:"ech,omitempty"`

	//// It's also possible for Vmess to have REALITY...
	//PublicKey string `json:"pbk"`
	//ShortIds  string `json:"sid"` // Mandatory, the shortId list available to the client, which can be used to distinguish different clients
	//SpiderX   string `json:"spx"` // Reality path
	CertFile string `json:"-"`
	KeyFile  string `json:"-"`

	OrigLink string `json:"-"` // Original link
}

type Vless struct {
	LinkVersion          string `json:"-"`
	ID                   string `json:"id"`  // UUID
	Address              string `json:"add"` // HOST:PORT
	Encryption           string `json:"encryption"`
	Flow                 string `json:"flow"`
	QuicSecurity         string `json:"quicSecurity"`
	Key                  string `json:"key"`      // Quic key
	Security             string `json:"security"` // reality or tls
	PublicKey            string `json:"pbk"`
	ShortIds             string `json:"sid"`        // Mandatory, the shortId list available to the client, which can be used to distinguish different clients
	SpiderX              string `json:"spx"`        // Reality path
	Mldsa65Verify        string `json:"pqv"`        // REALITY post-quantum ML-DSA-65 verification key
	HeaderType           string `json:"headerType"` // TCP HTTP Obfuscation
	Host                 string `json:"host"`       // HTTP, WS
	Path                 string `json:"path"`
	Port                 string `json:"port"`
	SNI                  string `json:"sni"`           // Server name indication
	ALPN                 string `json:"alpn"`          // Application-Layer Protocol Negotiation
	TlsFingerprint       string `json:"fp"`            // TLS fingerprint
	AllowInsecure        string `json:"allowInsecure"` // Insecure TLS
	PinnedPeerCertSha256 string `json:"pcs"`           // TLS cert SHA-256 pin(s), comma-separated (xray pinnedPeerCertSha256)
	VerifyPeerCertByName string `json:"vcn"`           // Names to verify the cert against (xray verifyPeerCertByName)
	ECHConfigList        string `json:"ech"`           // Encrypted Client Hello config list
	Type                 string `json:"type"`          // Network (XHTTP, ...)
	Remark               string `json:"ps"`            // Config's name
	Authority            string `json:"authority"`     // GRPC
	ServiceName          string `json:"serviceName"`   // GRPC
	Mode                 string `json:"mode"`          // XHTTP - GRPC
	Extra                string `json:"extra"`         // XHTTP - EXTRA
	CertFile             string `json:"-"`
	KeyFile              string `json:"-"`
	OrigLink             string `json:"-"` // Original link
}

type Shadowsocks struct {
	Address    string
	Port       string
	Encryption string
	Password   string
	Plugin     string // SIP003 plugin ("obfs-local;obfs=http;..."), unsupported by xray-core
	Remark     string
	OrigLink   string // Original link
}

type Trojan struct {
	LinkVersion          string `json:"-"`
	Password             string // Password
	Address              string `json:"add"` // HOST:PORT
	Flow                 string `json:"flow"`
	QuicSecurity         string `json:"quicSecurity"`
	Key                  string `json:"key"`        // Quic key
	Security             string `json:"security"`   // tls
	HeaderType           string `json:"headerType"` // TCP HTTP Obfuscation
	Host                 string `json:"host"`       // HTTP, WS
	Path                 string `json:"path"`
	Port                 string `json:"port"`
	SNI                  string `json:"sni"`           // Server name indication
	ALPN                 string `json:"alpn"`          // Application-Layer Protocol Negotiation
	TlsFingerprint       string `json:"fp"`            // TLS fingerprint
	AllowInsecure        string `json:"allowInsecure"` // Insecure TLS
	PinnedPeerCertSha256 string `json:"pcs"`           // TLS cert SHA-256 pin(s), comma-separated (xray pinnedPeerCertSha256)
	VerifyPeerCertByName string `json:"vcn"`           // Names to verify the cert against (xray verifyPeerCertByName)
	ECHConfigList        string `json:"ech"`           // Encrypted Client Hello config list
	Type                 string `json:"type"`          // Network (XHTTP, ...)
	Remark               string // Config's name
	Authority            string `json:"authority"`   // GRPC
	ServiceName          string `json:"serviceName"` // GRPC
	Mode                 string `json:"mode"`        // XHTTP, GRPC

	// Yes, Trojan can have reality too xD
	PublicKey     string `json:"pbk"`
	ShortIds      string `json:"sid"` // Mandatory, the shortId list available to the client, which can be used to distinguish different clients
	SpiderX       string `json:"spx"` // Reality path
	Mldsa65Verify string `json:"pqv"` // REALITY post-quantum ML-DSA-65 verification key

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
	KeepAlive    int32  `json:"keepalive"`  // Persistent keepalive (seconds)
	AllowedIPs   string `json:"allowedips"` // Comma-separated allowed IP CIDRs
	Reserved     string `json:"reserved"`   // Reserved bytes: "a,b,c" or base64 (e.g. WARP)

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
	PinSHA256     string // Server certificate SHA-256 pin ("pinSHA256")
	Ports         string // Port-hopping spec ("443,20000-30000"); xray uses Port only
	OrigLink      string // Original link
}
