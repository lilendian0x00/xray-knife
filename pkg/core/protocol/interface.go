package protocol

import (
	"context"
	"time"
)

const (
	VmessIdentifier       = "vmess"
	VlessIdentifier       = "vless"
	TrojanIdentifier      = "trojan"
	ShadowsocksIdentifier = "ss"
	WireguardIdentifier   = "wireguard"
	SocksIdentifier       = "socks"
	Hysteria2Identifier   = "hysteria2"
	TunIdentifier         = "tun"
	MTProtoIdentifier     = "mtproto"
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

// Prober The examiner uses it in place
// of Core.MakeHttpClient.
type Prober interface {
	Probe(ctx context.Context, opts ProbeOptions) (ProbeResult, error)
}

// ProbeOptions controls a single Probe call.
type ProbeOptions struct {
	Timeout       time.Duration
	BindInterface string
}

// ProbeResult reports timings measured from the start of the probe
type ProbeResult struct {
	ConnectTime time.Duration
	TTFB        time.Duration
	Delay       time.Duration
	Detail      string // note such as "faketls, dc2 resPQ ok".
}
