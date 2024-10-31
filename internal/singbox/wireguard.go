package singbox

import (
	"context"
	"errors"
	"fmt"
	"github.com/fatih/color"
	"github.com/lilendian0x00/xray-knife/internal/protocol"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/outbound"
	"github.com/sagernet/sing/common/logger"
	"net"
	"net/netip"
	"net/url"
	"reflect"
	"strconv"
	"strings"
)

func NewWireguard(link string) Protocol {
	return &Wireguard{OrigLink: link}
}

func (w *Wireguard) Name() string {
	return protocol.WireguardIdentifier
}

func (w *Wireguard) Parse() error {
	if !strings.HasPrefix(w.OrigLink, protocol.WireguardIdentifier) {
		return fmt.Errorf("wireguard unreconized: %s", w.OrigLink)
	}

	uri, err := url.Parse(w.OrigLink)
	if err != nil {
		return err
	}

	unescapedSecretKey, err0 := url.PathUnescape(uri.User.String())
	if err0 != nil {
		return err0
	}

	w.SecretKey = unescapedSecretKey

	w.Endpoint = uri.Host

	// Get the type of the struct
	t := reflect.TypeOf(*w)

	// Get the number of fields in the struct
	numFields := t.NumField()

	// Iterate over each field of the struct
	for i := 0; i < numFields; i++ {
		field := t.Field(i)
		tag := field.Tag.Get("json")

		// If the query value exists for the field, set it
		if values, ok := uri.Query()[tag]; ok {
			value := values[0]
			v := reflect.ValueOf(w).Elem().FieldByName(field.Name)

			switch v.Type().String() {
			case "string":
				v.SetString(value)
			case "int32":
				var intValue int
				fmt.Sscanf(value, "%d", &intValue)
				v.SetInt(int64(intValue))

			}
		}
	}

	w.Remark, err = url.PathUnescape(uri.Fragment)
	if err != nil {
		w.Remark = uri.Fragment
	}

	return nil
}

func (w *Wireguard) DetailsStr() string {
	info := fmt.Sprintf("%s: %s\n%s: %s\n%s: %s\n%s: %d\n%s: %s\n%s: %v\n%s: %s\n", w.Name(),
		color.RedString("Protocol"),
		color.RedString("Remark"), w.Remark,
		color.RedString("Endpoint"), w.Endpoint,
		color.RedString("MTU"), w.Mtu,
		color.RedString("Local Addresses"), w.LocalAddress,
		color.RedString("Public Key"), w.PublicKey,
		color.RedString("Secret Key"), w.SecretKey,
	)

	return info
}

func (w *Wireguard) ConvertToGeneralConfig() (g protocol.GeneralConfig) {
	g.Protocol = w.Name()
	g.Address = w.Endpoint

	return g
}

func (w *Wireguard) CraftInboundOptions() *option.Inbound {
	return &option.Inbound{
		Type: w.Name(),
	}
}

func (w *Wireguard) CraftOutboundOptions(allowInsecure bool) (*option.Outbound, error) {
	Address, portS, err := net.SplitHostPort(w.Endpoint)
	if err != nil {
		return nil, err
	}

	port, _ := strconv.Atoi(portS)

	opts := option.WireGuardOutboundOptions{
		DialerOptions: option.DialerOptions{},
		ServerOptions: option.ServerOptions{
			Server:     Address,
			ServerPort: uint16(port),
		},
		LocalAddress:  option.Listable[netip.Prefix]{},
		PeerPublicKey: w.PublicKey,
		PreSharedKey:  w.SecretKey,
		Reserved:      nil,
		MTU:           uint32(w.Mtu),
	}

	localAddresses := strings.Split(w.LocalAddress, ",")

	// Parsing local addresses
	for i, v := range localAddresses {
		prefix, err := netip.ParsePrefix(v)
		if err != nil {
			return nil, err
		}
		opts.LocalAddress[i] = prefix
	}

	return &option.Outbound{
		Type:             w.Name(),
		WireGuardOptions: opts,
	}, nil
}

func (w *Wireguard) CraftOutbound(ctx context.Context, l logger.ContextLogger, allowInsecure bool) (adapter.Outbound, error) {

	options, err := w.CraftOutboundOptions(allowInsecure)
	if err != nil {
		return nil, err
	}

	out, err := outbound.New(ctx, adapter.RouterFromContext(ctx), l, "out_wireguard", *options)
	if err != nil {
		return nil, errors.New(fmt.Sprintf("failed creating wireguard outbound: %v", err))
	}

	return out, nil
}
