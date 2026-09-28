package xray

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"github.com/lilendian0x00/xray-knife/v11/pkg/core/protocol"

	"github.com/fatih/color"
	"github.com/xtls/xray-core/infra/conf"
)

// parseReserved converts a WireGuard "reserved" link value into bytes.
// Accepts a comma-separated list of ints (e.g. "1,2,3", as used by WARP) or
// a base64 string. Returns nil when it can't parse.
func parseReserved(s string) []byte {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	if strings.Contains(s, ",") {
		parts := strings.Split(s, ",")
		b := make([]byte, 0, len(parts))
		for _, p := range parts {
			n, err := strconv.Atoi(strings.TrimSpace(p))
			if err != nil || n < 0 || n > 255 {
				return nil
			}
			b = append(b, byte(n))
		}
		return b
	}
	if dec, err := base64.StdEncoding.DecodeString(s); err == nil {
		return dec
	}
	if dec, err := base64.RawURLEncoding.DecodeString(s); err == nil {
		return dec
	}
	return nil
}

func NewWireguard(link string) Protocol {
	return &Wireguard{OrigLink: link}
}

func (w *Wireguard) Name() string {
	return "wireguard"
}

func (w *Wireguard) Parse() error {
	if !strings.HasPrefix(w.OrigLink, protocol.WireguardIdentifier+"://") {
		return fmt.Errorf("wireguard unreconized: %s", w.OrigLink)
	}

	// Split by hand rather than with url.Parse: WireGuard keys are
	// standard base64, and an unencoded "/" in the private key would end
	// the URL authority early. Keys also keep a literal "+".
	base, remark := splitRemark(w.OrigLink)
	body := strings.TrimPrefix(base, protocol.WireguardIdentifier+"://")
	body, rawQuery, _ := strings.Cut(body, "?")
	at := strings.LastIndex(body, "@")
	if at < 0 {
		return errors.New("wireguard link has no private key")
	}
	w.SecretKey = lenientUnescape(body[:at])
	w.Endpoint = strings.TrimSuffix(body[at+1:], "/")
	w.Remark = remark

	query := rawQueryValues(rawQuery)
	// Parameter names are matched case-insensitively, in the order given
	// (the first spelling that is present wins), independent of map order.
	keys := make([]string, 0, len(query))
	for key := range query {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	get := func(names ...string) string {
		for _, name := range names {
			for _, key := range keys {
				if values := query[key]; strings.EqualFold(key, name) && len(values) > 0 {
					return strings.TrimSpace(values[0])
				}
			}
		}
		return ""
	}
	atoi := func(s string) int32 {
		n, _ := strconv.ParseInt(s, 10, 32)
		return int32(n)
	}

	if sk := get("secretkey", "privatekey"); sk != "" {
		w.SecretKey = sk
	}
	w.PublicKey = get("publickey", "peer_public_key")
	w.PreSharedKey = get("presharedkey", "psk", "pre_shared_key")
	w.LocalAddress = get("address", "ip")
	w.Mtu = atoi(get("mtu"))
	w.KeepAlive = atoi(get("keepalive", "persistent_keepalive_interval"))
	w.AllowedIPs = get("allowedips")
	w.Reserved = get("reserved")

	if w.SecretKey == "" {
		return errors.New("wireguard link has no private key")
	}
	if _, _, err := net.SplitHostPort(w.Endpoint); err != nil {
		return fmt.Errorf("invalid wireguard endpoint %q: %w", w.Endpoint, err)
	}
	return nil
}

// localAddresses returns the interface addresses as CIDRs; a bare IP gets
// a host prefix (/32 or /128).
func (w *Wireguard) localAddresses() ([]string, error) {
	var out []string
	for _, a := range splitList(w.LocalAddress) {
		if !strings.Contains(a, "/") {
			ip := net.ParseIP(unbracket(a))
			if ip == nil {
				return nil, fmt.Errorf("invalid wireguard address %q", a)
			}
			if ip.To4() != nil {
				a = ip.String() + "/32"
			} else {
				a = ip.String() + "/128"
			}
		}
		out = append(out, a)
	}
	if len(out) == 0 {
		return nil, errors.New("wireguard link has no local address (address=...)")
	}
	return out, nil
}

func (w *Wireguard) DetailsStr() string {
	info := fmt.Sprintf("%s: %s\n%s: %s\n%s: %s\n%s: %d\n%s: %s\n%s: %v\n%s: %s\n",
		color.RedString("Protocol"), w.Name(),
		color.RedString("Remark"), w.Remark,
		color.RedString("Endpoint"), w.Endpoint,
		color.RedString("MTU"), w.Mtu,
		color.RedString("Local Addresses"), w.LocalAddress,
		color.RedString("Public Key"), w.PublicKey,
		color.RedString("Secret Key"), w.SecretKey,
	)

	return info
}

// GetLink generates a WireGuard config link from the struct's fields.
func (w *Wireguard) GetLink() string {
	if w.OrigLink != "" {
		return w.OrigLink
	} else {
		baseURL := url.URL{
			Scheme: "wireguard",
			User:   url.User(w.SecretKey),
			Host:   w.Endpoint,
		}

		params := url.Values{}
		addQueryParam := func(key, value string) {
			if value != "" {
				params.Add(key, value)
			}
		}
		addQueryParamInt := func(key string, value int32) {
			if value != 0 {
				params.Add(key, strconv.FormatInt(int64(value), 10))
			}
		}

		addQueryParam("publickey", w.PublicKey)
		addQueryParam("presharedkey", w.PreSharedKey)
		addQueryParam("address", w.LocalAddress)
		addQueryParamInt("mtu", w.Mtu)
		addQueryParamInt("keepalive", w.KeepAlive)
		addQueryParam("allowedips", w.AllowedIPs)
		addQueryParam("reserved", w.Reserved)

		baseURL.RawQuery = params.Encode()

		if w.Remark != "" {
			baseURL.Fragment = w.Remark
		}

		return baseURL.String()
	}
}

func (w *Wireguard) ConvertToGeneralConfig() (g protocol.GeneralConfig) {
	g.Protocol = w.Name()
	g.Address, g.Port, _ = net.SplitHostPort(w.Endpoint)
	g.Remark = w.Remark
	g.Network = "udp"
	g.OrigLink = w.GetLink()

	return g
}

type Peer struct {
	Endpoint     string   `json:"endpoint"`
	PublicKey    string   `json:"publicKey"`
	PreSharedKey string   `json:"preSharedKey"`
	KeepAlive    uint32   `json:"keepAlive,omitempty"`
	AllowedIPs   []string `json:"allowedIPs,omitempty"`
}

type Config struct {
	SecretKey string   `json:"secretKey"`
	Address   []string `json:"address"`
	Peers     []Peer   `json:"peers"`
	MTU       int      `json:"mtu"`
	Reserved  []byte   `json:"reserved,omitempty"`
}

func (w *Wireguard) BuildOutboundDetourConfig(allowInsecure bool) (*conf.OutboundDetourConfig, error) {
	addresses, err := w.localAddresses()
	if err != nil {
		return nil, err
	}

	peer := Peer{
		Endpoint:     w.Endpoint,
		PublicKey:    w.PublicKey,
		PreSharedKey: w.PreSharedKey,
	}
	if w.KeepAlive > 0 {
		peer.KeepAlive = uint32(w.KeepAlive)
	}
	peer.AllowedIPs = splitList(w.AllowedIPs)

	cfg := Config{
		SecretKey: w.SecretKey,
		Address:   addresses,
		Peers:     []Peer{peer},
		MTU:       int(w.Mtu),
	}
	if w.Reserved != "" {
		r := parseReserved(w.Reserved)
		if len(r) != 3 {
			return nil, fmt.Errorf("invalid wireguard reserved %q: want 3 bytes", w.Reserved)
		}
		cfg.Reserved = r
	}

	jsonData, err := json.Marshal(cfg)
	if err != nil {
		return nil, err
	}
	rawMSG := json.RawMessage(jsonData)
	return &conf.OutboundDetourConfig{
		Tag:      "proxy",
		Protocol: w.Name(),
		Settings: &rawMSG,
	}, nil
}

func (w *Wireguard) BuildInboundDetourConfig() (*conf.InboundDetourConfig, error) {
	return nil, fmt.Errorf("creating a WireGuard inbound from a client link is not supported")
}
