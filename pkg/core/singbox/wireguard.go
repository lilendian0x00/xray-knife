package singbox

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"reflect"
	"strconv"
	"strings"

	"github.com/lilendian0x00/xray-knife/v7/pkg/core/protocol"

	"github.com/fatih/color"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/outbound"
	"github.com/sagernet/sing/common/logger"
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
				intValue, err := strconv.ParseInt(value, 10, 32)
				if err != nil {
					return fmt.Errorf("failed to parse int32 value: %w", err)
				}
				v.SetInt(intValue)

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

	port, err := strconv.ParseUint(portS, 10, 16)
	if err != nil {
		return nil, errors.New("invalid port number")
	}

	var reserved = []uint8{0, 0, 0}
	if w.Reserved != "" {
		reservedList := strings.Split(w.Reserved, ",")
		for i, v := range reservedList {
			num, err := strconv.ParseUint(v, 10, 8)
			if err != nil {
				fmt.Println(err)
				return nil, errors.New("invalid reserved value")
			}
			reserved[i] = uint8(num)
		}
	}

	opts := option.WireGuardOutboundOptions{
		DialerOptions: option.DialerOptions{},
		ServerOptions: option.ServerOptions{
			Server:     Address,
			ServerPort: uint16(port),
		},
		LocalAddress: option.Listable[netip.Prefix]{},
		//Peers: []option.WireGuardPeer{
		//	{
		//		ServerOptions: option.ServerOptions{
		//			Server:     Address,
		//			ServerPort: uint16(port),
		//		},
		//		PublicKey:    w.PublicKey,
		//		PreSharedKey: "",                            // Changed from SecretKey to PreSharedKey
		//		AllowedIPs:   []string{"0.0.0.0/0", "::/0"}, // Added IPv6 support
		//		Reserved:     reserved,
		//	},
		//},
		PeerPublicKey: w.PublicKey,
		PrivateKey:    w.SecretKey,
		//PreSharedKey: w.SecretKey,
		Reserved: reserved,
		MTU:      uint32(w.Mtu),
	}

	localAddresses := strings.Split(w.LocalAddress, ",")

	//opts.LocalAddress = make(option.Listable[netip.Prefix], len(localAddresses))

	// Parsing local addresses
	for _, v := range localAddresses {
		prefix, err := netip.ParsePrefix(v)
		if err != nil {
			return nil, err
		}
		opts.LocalAddress = append(opts.LocalAddress, prefix)
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

	router := adapter.RouterFromContext(ctx)

	out, err := outbound.New(ctx, router, l, "out_wireguard", *options)
	if err != nil {
		return nil, errors.New(fmt.Sprintf("failed creating wireguard outbound: %v", err))
	}

	return out, nil
}
