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
	// sing-box-only protocols.
	TuicIdentifier     = "tuic"
	AnyTLSIdentifier   = "anytls"
	HysteriaIdentifier = "hysteria" // Hysteria v1
	SSHIdentifier      = "ssh"
	HTTPIdentifier     = "http"  // HTTP proxy outbound links
	HTTPSIdentifier    = "https" // HTTP proxy over TLS
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

// Relayer is implemented by a protocol that can tell whether it carries
// general traffic. A protocol without it does.
type Relayer interface {
	Relays() bool
}

// Relays reports whether p can be a general outbound: a proxy, a chain
// hop, a scan target, an exported config. MTProto proxies only relay
// Telegram traffic, so they cannot.
func Relays(p Protocol) bool {
	r, ok := p.(Relayer)
	return !ok || r.Relays()
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

// MaxProbeSamples caps the round trips one Probe call may measure.
const MaxProbeSamples = 32

// Prober The examiner uses it in place
// of Core.MakeHttpClient.
type Prober interface {
	Probe(ctx context.Context, opts ProbeOptions) (ProbeResult, error)
}

// ProbeOptions controls a single Probe call.
type ProbeOptions struct {
	// Timeout covers the whole call. Dial, handshake and every sample share it.
	Timeout       time.Duration
	BindInterface string
	// Samples is how many round trips to measure on the probe's one connection.
	// 0 means 1, otherwise 1..MaxProbeSamples. Extra samples are best effort.
	Samples int
}

// ProbeResult reports timings measured from the start of the probe. ConnectTime,
// TTFB and Delay cover the first exchange only.
type ProbeResult struct {
	ConnectTime time.Duration
	TTFB        time.Duration
	Delay       time.Duration
	Detail      string // note such as "faketls, dc2 resPQ ok".
	// RTTs is one entry per validated exchange, excluding setup. Nil when the
	// prober measures none.
	RTTs []time.Duration
}
