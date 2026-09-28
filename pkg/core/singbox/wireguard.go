package singbox

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"reflect"
	"strconv"
	"strings"

	"github.com/lilendian0x00/xray-knife/v11/pkg/core/protocol"

	"github.com/fatih/color"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	sing_wireguard "github.com/sagernet/sing-box/protocol/wireguard"
	"github.com/sagernet/sing/common/json/badoption"
	"github.com/sagernet/sing/common/logger"
	"github.com/sagernet/sing/service"
)

func NewWireguard(link string) Protocol {
	return &Wireguard{OrigLink: link}
}

func (w *Wireguard) Name() string {
	return protocol.WireguardIdentifier
}

func (w *Wireguard) Parse() error {
	if !strings.HasPrefix(w.OrigLink, protocol.WireguardIdentifier+"://") {
		return fmt.Errorf("wireguard unreconized: %s", w.OrigLink)
	}

	// Split by hand rather than with url.Parse: WireGuard keys are standard
	// base64, and an unencoded '/' in the private key would end the URL
	// authority early (Craft then fails on a bogus host). A literal '+' in
	// a key is part of the key, not an encoded space.
	body := strings.TrimPrefix(w.OrigLink, protocol.WireguardIdentifier+"://")
	body, frag, _ := strings.Cut(body, "#")
	body, rawQuery, _ := strings.Cut(body, "?")
	body = strings.TrimSuffix(body, "/")
	at := strings.LastIndex(body, "@")
	if at < 0 {
		return errors.New("wireguard link has no private key")
	}
	w.SecretKey = unescapeLenient(body[:at])
	w.Endpoint = body[at+1:]
	if _, _, err := net.SplitHostPort(w.Endpoint); err != nil {
		return fmt.Errorf("invalid wireguard endpoint %q: %w", w.Endpoint, err)
	}
	remark := unescapeLenient(frag)

	// Lenient like url.URL.Query: a malformed pair is dropped, not fatal.
	query, _ := url.ParseQuery(strings.ReplaceAll(rawQuery, "+", "%2B"))

	// Get the type of the struct
	t := reflect.TypeOf(*w)

	// Get the number of fields in the struct
	numFields := t.NumField()

	// Iterate over each field of the struct
	for i := 0; i < numFields; i++ {
		field := t.Field(i)
		tag := field.Tag.Get("json")

		// If the query value exists for the field, set it
		if values, ok := query[tag]; ok {
			value := values[0]
			v := reflect.ValueOf(w).Elem().FieldByName(field.Name)

			switch v.Type().String() {
			case "string":
				v.SetString(value)
			case "int32":
				intValue, err := strconv.ParseInt(value, 10, 32)
				if err != nil {
					return fmt.Errorf("failed to parse int32 value: %w", err)
				}
				v.SetInt(intValue)

			}
		}
	}

	w.Remark = remark

	return nil
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

func (w *Wireguard) GetLink() string {
	return w.OrigLink
}

func (w *Wireguard) ConvertToGeneralConfig() (g protocol.GeneralConfig) {
	g.Protocol = w.Name()
	if host, port, err := net.SplitHostPort(w.Endpoint); err == nil {
		g.Address, g.Port = host, port
	} else {
		g.Address = w.Endpoint
	}
	g.ID = w.PublicKey
	g.Network = "udp"
	g.Remark = w.Remark
	g.OrigLink = w.GetLink()

	return g
}

func (w *Wireguard) CraftInboundOptions() (*option.Inbound, error) {
	return nil, fmt.Errorf("%s: inbound not supported", w.Name())
}

// parseReserved decodes the 3 WireGuard reserved bytes from "1,2,3" or
// base64, returning nil when the value is not valid.
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

// parseLocalAddresses parses the comma-separated tunnel addresses. A bare IP
// gets a host prefix (/32 or /128), as most clients assume.
func parseLocalAddresses(s string) ([]netip.Prefix, error) {
	var prefixes []netip.Prefix
	for _, v := range splitList(s) {
		if !strings.Contains(v, "/") {
			ip, err := netip.ParseAddr(v)
			if err != nil {
				return nil, fmt.Errorf("invalid wireguard address %q", v)
			}
			prefixes = append(prefixes, netip.PrefixFrom(ip, ip.BitLen()))
			continue
		}
		prefix, err := netip.ParsePrefix(v)
		if err != nil {
			return nil, fmt.Errorf("invalid wireguard address %q", v)
		}
		prefixes = append(prefixes, prefix)
	}
	if len(prefixes) == 0 {
		return nil, errors.New("wireguard link has no address= (the tunnel's local IP)")
	}
	return prefixes, nil
}

// CraftOutboundOptions builds sing-box WireGuard options. Since sing-box 1.14
// WireGuard is an endpoint, not an outbound: the returned option.Outbound
// carries *option.WireGuardEndpointOptions and placeOutbounds files it under
// Options.Endpoints. The single server in the link becomes the sole peer.
func (w *Wireguard) CraftOutboundOptions(allowInsecure bool) (*option.Outbound, error) {
	address, portS, err := net.SplitHostPort(w.Endpoint)
	if err != nil {
		return nil, err
	}

	port, err := parsePort(portS)
	if err != nil {
		return nil, err
	}

	reserved := []uint8{0, 0, 0}
	if w.Reserved != "" {
		reserved = parseReserved(w.Reserved)
		if len(reserved) != 3 {
			return nil, fmt.Errorf("invalid wireguard reserved %q: want 3 bytes", w.Reserved)
		}
	}

	addresses, err := parseLocalAddresses(w.LocalAddress)
	if err != nil {
		return nil, err
	}

	peer := option.WireGuardPeer{
		Address:      address,
		Port:         port,
		PublicKey:    w.PublicKey,
		PreSharedKey: w.PreSharedKey,
		Reserved:     reserved,
	}
	if w.Keepalive > 0 && w.Keepalive <= 65535 {
		peer.PersistentKeepaliveInterval = uint16(w.Keepalive)
	}
	// The legacy single-peer outbound routed everything through the peer
	// implicitly; the endpoint form needs the allowed IPs spelled out.
	peer.AllowedIPs = badoption.Listable[netip.Prefix]{
		netip.MustParsePrefix("0.0.0.0/0"),
		netip.MustParsePrefix("::/0"),
	}

	opts := option.WireGuardEndpointOptions{
		MTU:        uint32(w.Mtu),
		PrivateKey: w.SecretKey,
		Peers:      []option.WireGuardPeer{peer},
		Address:    addresses,
	}

	return &option.Outbound{
		Type:    w.Name(),
		Options: &opts,
	}, nil
}

func (w *Wireguard) CraftOutbound(ctx context.Context, l logger.ContextLogger, allowInsecure bool) (adapter.Outbound, error) {

	options, err := w.CraftOutboundOptions(allowInsecure)
	if err != nil {
		return nil, err
	}

	router := service.FromContext[adapter.Router](ctx)

	wgOptions, ok := options.Options.(*option.WireGuardEndpointOptions)
	if !ok {
		return nil, fmt.Errorf("wireguard: unexpected options type %T", options.Options)
	}
	// An endpoint is also an adapter.Outbound, so callers can dial through it.
	out, err := sing_wireguard.NewEndpoint(ctx, router, l, "out_wireguard", *wgOptions)
	if err != nil {
		return nil, fmt.Errorf("failed creating wireguard outbound: %w", err)
	}

	return out, nil
}
