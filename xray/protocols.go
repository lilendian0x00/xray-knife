package xray

import (
	"errors"
	"fmt"
	"strings"

	"github.com/fatih/color"
	"github.com/xtls/xray-core/infra/conf"
)

const (
	vmessIdentifier       = "vmess://"
	vlessIdentifier       = "vless://"
	trojanIdentifier      = "trojan://"
	ShadowsocksIdentifier = "ss://"
	wireguardIdentifier   = "wireguard://"
	socksIdentifier       = "socks://"
)

type Protocol interface {
	Parse(configLink string) error
	BuildOutboundDetourConfig(allowInsecure bool) (*conf.OutboundDetourConfig, error)
	BuildInboundDetourConfig() (*conf.InboundDetourConfig, error)
	DetailsStr() string
	DetailsMap() map[string]string
	ConvertToGeneralConfig() GeneralConfig
}

func detailsToStr(details [][2]string) string {
	result := ""
	for _, d := range details {
		result += fmt.Sprintf("%s: %s\n", color.RedString(d[0]), d[1])
	}

	return result
}

func detailsToMap(details [][2]string) map[string]string {
	result := make(map[string]string, len(details))
	for _, d := range details {
		result[d[0]] = d[1]
	}

	return result
}

func CreateProtocol(configLink string) (Protocol, error) {
	switch {
	case strings.HasPrefix(configLink, vmessIdentifier):
		return NewVmess(), nil
	case strings.HasPrefix(configLink, vlessIdentifier):
		return NewVless(), nil
	case strings.HasPrefix(configLink, ShadowsocksIdentifier):
		return NewShadowsocks(), nil
	case strings.HasPrefix(configLink, trojanIdentifier):
		return NewTrojan(), nil
	case strings.HasPrefix(configLink, socksIdentifier):
		return NewSocks(), nil
	case strings.HasPrefix(configLink, wireguardIdentifier):
		return NewWireguard(), nil
	default:
		return nil, errors.New("invalid protocol type")
	}
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

	// // It's also possible for Vmess to have REALITY...
	// PublicKey string `json:"pbk"`
	// ShortIds  string `json:"sid"` // Mandatory, the shortId list available to the client, which can be used to distinguish different clients
	// SpiderX   string `json:"spx"` // Reality path

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
	SNI            string `json:"sni"`         // Server name indication
	ALPN           string `json:"alpn"`        // Application-Layer Protocol Negotiation
	TlsFingerprint string `json:"fp"`          // TLS fingerprint
	Type           string `json:"type"`        // Network
	Remark         string `json:"ps"`          // Config's name
	Authority      string `json:"authority"`   // GRPC
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
	Authority      string `json:"authority"`   // GRPC
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
	LocalAddress string `json:"address"` // Local address IPv4/IPv6 seperated by commas
	Mtu          int32  `json:"mtu"`
}

type Socks struct {
	Remark   string
	Address  string // HOST:PORT
	Port     string
	Username string // Username
	Password string // Password
	OrigLink string // Original link
}
