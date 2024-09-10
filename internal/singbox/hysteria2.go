package singbox

import (
	"context"
	"fmt"
	"github.com/fatih/color"
	"github.com/lilendian0x00/xray-knife/internal/protocol"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/outbound"
	"github.com/sagernet/sing/common/logger"
	"net"
	"net/url"
	"reflect"
	"strconv"
)

func NewHysteria2(link string) Protocol {
	return &Hysteria2{OrigLink: link}
}

func (h *Hysteria2) Name() string {
	return protocol.Hysteria2Identifier
}

func (h *Hysteria2) Parse() error {
	uri, err := url.Parse(h.OrigLink)
	if err != nil {
		return err
	}

	h.Password = uri.User.String()

	h.Address, h.Port, err = net.SplitHostPort(uri.Host)
	if err != nil {
		return err
	}

	//if utils.IsIPv6(h.Address) {
	//	v.Address = "[" + v.Address + "]"
	//}

	// Get the type of the struct
	t := reflect.TypeOf(*h)

	// Get the number of fields in the struct
	numFields := t.NumField()

	// Iterate over each field of the struct
	for i := 0; i < numFields; i++ {
		field := t.Field(i)
		tag := field.Tag.Get("json")

		// If the query value exists for the field, set it
		if values, ok := uri.Query()[tag]; ok {
			value := values[0]
			v := reflect.ValueOf(h).Elem().FieldByName(field.Name)

			switch v.Type().String() {
			case "string":
				v.SetString(value)
			case "int":
				var intValue int
				fmt.Sscanf(value, "%d", &intValue)
				v.SetInt(int64(intValue))
			}
		}
	}

	h.Remark, err = url.PathUnescape(uri.Fragment)
	if err != nil {
		h.Remark = uri.Fragment
	}

	return nil
}

func (h *Hysteria2) DetailsStr() string {
	info := fmt.Sprintf("%s: %s\n%s: %s\n%s: %s\n%s: %s\n%s: %v\n%s: %s\n",
		color.RedString("Protocol"), h.Name(),
		color.RedString("Remark"), h.Remark,
		color.RedString("Address"), h.Address,
		color.RedString("Port"), h.Port,
		color.RedString("Password"), h.Password,
		color.RedString("SNI"), h.SNI)

	if h.Insecure != nil {
		info += fmt.Sprintf("%s: %v\n",
			color.RedString("Obfuscation Type"), h.Insecure)
	}

	if h.ObfusType != "" {
		info += fmt.Sprintf("%s: %s\n%s: %s\n",
			color.RedString("Obfuscation Type"), h.ObfusType,
			color.RedString("Obfuscation Password"), h.ObfusPassword)
	}
	return info
}

func (h *Hysteria2) ConvertToGeneralConfig() (g protocol.GeneralConfig) {
	g.Protocol = h.Name()
	g.Address = h.Address
	g.Port = h.Port
	g.Remark = h.Remark

	g.OrigLink = h.OrigLink

	return g
}

func (h *Hysteria2) CraftOutboundOptions() (*option.Outbound, error) {
	port, _ := strconv.Atoi(h.Port)
	var insecure = false

	if h.Insecure != nil {
		v, ok := h.Insecure.(int)
		if ok {
			if v == 1 {
				insecure = true
			}
		}

		vv, ok := h.Insecure.(bool)
		if ok {
			if vv {
				insecure = true
			}
		}
	}

	opts := option.Hysteria2OutboundOptions{
		DialerOptions: option.DialerOptions{},
		ServerOptions: option.ServerOptions{
			Server:     h.Address,
			ServerPort: uint16(port),
		},
		Obfs: &option.Hysteria2Obfs{
			Type:     h.ObfusType,
			Password: h.ObfusPassword,
		},
		Password: h.Password,
		OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{
			TLS: &option.OutboundTLSOptions{
				Enabled:    true,
				ServerName: h.SNI,
				Insecure:   insecure,
			},
		},
	}

	return &option.Outbound{
		Type:             h.Name(),
		Hysteria2Options: opts,
	}, nil
}

func (h *Hysteria2) CraftInboundOptions() *option.Inbound {
	return &option.Inbound{
		Type: h.Name(),
	}
}

func (h *Hysteria2) CraftOutbound(ctx context.Context, l logger.ContextLogger) (adapter.Outbound, error) {
	options, err := h.CraftOutboundOptions()
	if err != nil {
		return nil, err
	}

	out, err := outbound.New(ctx, adapter.RouterFromContext(ctx), l, "out_hysteria2", *options)
	if err != nil {
		return nil, err
	}

	//out, err := outbound.NewHysteria2(ctx, adapter.RouterFromContext(ctx), l, "out_hysteria2", h.CraftOptions())
	//if err != nil {
	//	return nil, errors.New(fmt.Sprintf("failed creating hysteria2 outbound: %v", err))
	//}

	return out, nil
}
