package singbox

import (
	"context"
	"fmt"
	"net"
	"reflect"
	"strings"

	"github.com/lilendian0x00/xray-knife/v11/pkg/core/protocol"

	"github.com/fatih/color"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	sing_vless "github.com/sagernet/sing-box/protocol/vless"
	"github.com/sagernet/sing/common/logger"
	"github.com/sagernet/sing/service"
)

func NewVless(link string) Protocol {
	return &Vless{OrigLink: link}
}

func (v *Vless) Name() string {
	return protocol.VlessIdentifier
}

func (v *Vless) Parse() error {
	if !strings.HasPrefix(v.OrigLink, protocol.VlessIdentifier) {
		return fmt.Errorf("vless unreconized: %s", v.OrigLink)
	}

	uri, remark, err := parseShareLink(v.OrigLink)
	if err != nil {
		return err
	}

	v.ID = userInfoSecret(uri.User)

	v.Address, v.Port, err = net.SplitHostPort(uri.Host)
	if err != nil {
		return err
	}

	// Get the type of the struct
	t := reflect.TypeOf(*v)

	// Get the number of fields in the struct
	numFields := t.NumField()

	query := uri.Query()
	// Iterate over each field of the struct
	for i := 0; i < numFields; i++ {
		field := t.Field(i)
		tag := field.Tag.Get("json")

		// If the query value exists for the field, set it
		if values, ok := query[tag]; ok {
			value := values[0]
			v := reflect.ValueOf(v).Elem().FieldByName(field.Name)

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

	v.Remark = remark

	if v.HeaderType == "http" || v.Type == "ws" || v.Type == "h2" {
		if v.Path == "" {
			v.Path = "/"
		}
	}

	return nil
}

func (v *Vless) DetailsStr() string {
	copyV := *v
	if copyV.Flow == "" || copyV.Type == "grpc" {
		copyV.Flow = "none"
	}
	info := fmt.Sprintf("%s: %s\n%s: %s\n%s: %s\n%s: %s\n%s: %v\n%s: %s\n%s: %s\n",
		color.RedString("Protocol"), v.Name(),
		color.RedString("Remark"), v.Remark,
		color.RedString("Network"), v.Type,
		color.RedString("Address"), v.Address,
		color.RedString("Port"), v.Port,
		color.RedString("UUID"), v.ID,
		color.RedString("Flow"), copyV.Flow)
	if copyV.Type == "" {

	} else if copyV.HeaderType == "http" || copyV.Type == "httpupgrade" || copyV.Type == "ws" || copyV.Type == "h2" || copyV.Type == "splithttp" {
		info += fmt.Sprintf("%s: %s\n%s: %s\n",
			color.RedString("Host"), copyV.Host,
			color.RedString("Path"), copyV.Path)
	} else if copyV.Type == "kcp" {
		info += fmt.Sprintf("%s: %s\n", color.RedString("KCP Seed"), copyV.Path)
	} else if copyV.Type == "grpc" {
		if copyV.ServiceName == "" {
			copyV.ServiceName = "none"
		}
		info += fmt.Sprintf("%s: %s\n", color.RedString("ServiceName"), copyV.ServiceName)
	}

	if copyV.Security == "reality" {
		info += fmt.Sprintf("%s: reality\n", color.RedString("TLS"))
		if copyV.SpiderX == "" {
			copyV.SpiderX = "none"
		}
		info += fmt.Sprintf("%s: %s\n%s: %s\n%s: %s\n%s: %s\n%s: %s\n",
			color.RedString("Public key"), copyV.PublicKey,
			color.RedString("SNI"), copyV.SNI,
			color.RedString("ShortID"), copyV.ShortIds,
			color.RedString("SpiderX"), copyV.SpiderX,
			color.RedString("Fingerprint"), copyV.TlsFingerprint,
		)
	} else if copyV.Security == "tls" {
		info += fmt.Sprintf("%s: tls\n", color.RedString("TLS"))
		if len(copyV.SNI) == 0 {
			if copyV.Host != "" {
				copyV.SNI = copyV.Host
			} else {
				copyV.SNI = "none"
			}
		}
		if len(copyV.ALPN) == 0 {
			copyV.ALPN = "none"
		}
		if copyV.TlsFingerprint == "" {
			copyV.TlsFingerprint = "none"
		}
		info += fmt.Sprintf("%s: %s\n%s: %s\n%s: %s\n",
			color.RedString("SNI"), copyV.SNI,
			color.RedString("ALPN"), copyV.ALPN,
			color.RedString("Fingerprint"), copyV.TlsFingerprint)

		if v.AllowInsecure != "" {
			info += fmt.Sprintf("%s: %v\n",
				color.RedString("Insecure"), v.AllowInsecure)
		}
	} else {
		info += fmt.Sprintf("%s: none\n", color.RedString("TLS"))
	}
	return info
}

func (v *Vless) GetLink() string {
	return v.OrigLink
}

func (v *Vless) ConvertToGeneralConfig() (g protocol.GeneralConfig) {
	g.Protocol = v.Name()
	g.Address = v.Address
	g.Host = v.Host
	g.ID = v.ID
	g.Path = v.Path
	g.Port = v.Port
	g.Remark = v.Remark
	if v.Security == "" {
		g.TLS = "none"
	} else {
		g.TLS = v.Security
	}
	g.SNI = v.SNI
	g.ALPN = v.ALPN
	g.TlsFingerprint = v.TlsFingerprint
	g.ServiceName = v.ServiceName
	g.Mode = v.Mode
	g.Type = v.Type
	g.OrigLink = v.GetLink()

	return g
}

func (v *Vless) transport() v2rayTransport {
	return v2rayTransport{Network: v.Type, HeaderType: v.HeaderType, Host: v.Host, Path: v.Path, ServiceName: v.ServiceName}
}

func (v *Vless) CraftInboundOptions() (*option.Inbound, error) {
	listen, err := listenOptions(v.Address, v.Port)
	if err != nil {
		return nil, err
	}

	// TODO: Inbound TLS requires certificates, which are not available from a client link.
	// Therefore, TLS is not configured for the inbound.
	transport, err := buildTransport(v.transport())
	if err != nil {
		return nil, err
	}

	opts := option.VLESSInboundOptions{
		ListenOptions: listen,
		Users: []option.VLESSUser{
			{
				Name: "user", // sing-box requires a name
				UUID: v.ID,
				Flow: v.Flow,
			},
		},
		Transport: transport,
	}

	return &option.Inbound{
		Type:    v.Name(),
		Tag:     "vless-in",
		Options: &opts,
	}, nil
}

func (v *Vless) CraftOutboundOptions(allowInsecure bool) (*option.Outbound, error) {
	return v.craftOutbound(allowInsecure, utlsAvailable)
}

func (v *Vless) craftOutbound(allowInsecure, utls bool) (*option.Outbound, error) {
	port, err := parsePort(v.Port)
	if err != nil {
		return nil, err
	}

	tlsOpts, transport, err := buildStream(tlsParams{
		UTLS:          utls,
		Security:      v.Security,
		SNI:           v.SNI,
		ALPN:          v.ALPN,
		Fingerprint:   v.TlsFingerprint,
		AllowInsecure: v.AllowInsecure,
		PublicKey:     v.PublicKey,
		ShortID:       v.ShortIds,
	}, v.transport(), allowInsecure)
	if err != nil {
		return nil, err
	}

	opts := option.VLESSOutboundOptions{
		ServerOptions: option.ServerOptions{
			Server:     serverHost(v.Address),
			ServerPort: port,
		},
		UUID:                        v.ID,
		Transport:                   transport,
		OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{TLS: tlsOpts},
		Flow:                        v.Flow,
	}

	return &option.Outbound{
		Type:    v.Name(),
		Options: &opts,
	}, nil
}

func (v *Vless) CraftOutbound(ctx context.Context, l logger.ContextLogger, allowInsecure bool) (adapter.Outbound, error) {

	options, err := v.CraftOutboundOptions(allowInsecure)
	if err != nil {
		return nil, err
	}

	vlessOptions, ok := options.Options.(*option.VLESSOutboundOptions)
	if !ok {
		return nil, fmt.Errorf("vless: unexpected options type %T", options.Options)
	}
	out, err := sing_vless.NewOutbound(ctx, service.FromContext[adapter.Router](ctx), l, "out_vless", *vlessOptions)
	if err != nil {
		return nil, fmt.Errorf("failed creating vless outbound: %w", err)
	}

	return out, nil
}
