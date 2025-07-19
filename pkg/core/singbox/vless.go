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

	"github.com/lilendian0x00/xray-knife/v6/pkg/core/protocol"
	"github.com/lilendian0x00/xray-knife/v6/utils"

	"github.com/fatih/color"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/outbound"
	"github.com/sagernet/sing/common/logger"
	"github.com/xtls/xray-core/infra/conf"
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

	uri, err := url.Parse(v.OrigLink)
	if err != nil {
		return err
	}

	v.ID = uri.User.String()

	v.Address, v.Port, err = net.SplitHostPort(uri.Host)
	if err != nil {
		return err
	}

	if utils.IsIPv6(v.Address) {
		v.Address = "[" + v.Address + "]"
	}

	// Get the type of the struct
	t := reflect.TypeOf(*v)

	// Get the number of fields in the struct
	numFields := t.NumField()

	// Iterate over each field of the struct
	for i := 0; i < numFields; i++ {
		field := t.Field(i)
		tag := field.Tag.Get("json")

		// If the query value exists for the field, set it
		if values, ok := uri.Query()[tag]; ok {
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

	v.Remark, err = url.PathUnescape(uri.Fragment)
	if err != nil {
		v.Remark = uri.Fragment
	}
	//portUint, err := strconv.ParseUint(address[1], 10, 16)
	//if err != nil {
	//	fmt.Fprintf(os.Stderr, "%v", err)
	//	os.Exit(1)
	//}
	//v.Port = uint16(portUint)

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

func (v *Vless) CraftInboundOptions() *option.Inbound {
	port, _ := strconv.Atoi(v.Port)
	addr, _ := netip.ParseAddr(v.Address)

	// TODO: Inbound TLS requires certificates, which are not available from a client link.
	// Therefore, TLS is not configured for the inbound.

	var transport = &option.V2RayTransportOptions{
		Type: v.Type,
	}

	switch v.Type {
	case "ws":
		transport.WebsocketOptions = option.V2RayWebsocketOptions{
			Path: v.Path,
		}
	case "grpc":
		if len(v.ServiceName) > 0 && v.ServiceName[0] == '/' {
			v.ServiceName = v.ServiceName[1:]
		}
		transport.GRPCOptions = option.V2RayGRPCOptions{
			ServiceName: v.ServiceName,
		}
	}

	opts := option.VLESSInboundOptions{
		ListenOptions: option.ListenOptions{
			Listen:     option.NewListenAddress(addr),
			ListenPort: uint16(port),
		},
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
		Type:         v.Name(),
		Tag:          "vless-in",
		VLESSOptions: opts,
	}
}

func (v *Vless) CraftOutboundOptions(allowInsecure bool) (*option.Outbound, error) {
	port, _ := strconv.Atoi(v.Port)

	tls := false
	var alpn []string
	var fingerprint string
	var insecure = allowInsecure

	if v.Security == "tls" || v.Security == "reality" {
		tls = true

		alpn = []string{"http/1.1"}
		if v.ALPN != "" && v.ALPN != "none" {
			alpn = strings.Split(v.ALPN, ",")
		}

		fingerprint = "chrome"
		if v.TlsFingerprint != "" && v.TlsFingerprint != "none" {
			fingerprint = v.TlsFingerprint
		}

		if v.AllowInsecure != "" {
			if v.AllowInsecure == "1" || v.AllowInsecure == "true" {
				insecure = true
			}
		}
	}

	var transport = &option.V2RayTransportOptions{
		Type: v.Type,
	}

	switch v.Type {
	case "tcp":
		return nil, errors.New("tcp transport not supported")
	case "ws":
		transport.WebsocketOptions = option.V2RayWebsocketOptions{
			Path:                v.Path,
			Headers:             option.HTTPHeader{},
			MaxEarlyData:        0,
			EarlyDataHeaderName: "",
		}
		transport.WebsocketOptions.Headers["host"] = option.Listable[string]{v.Host}
		transport.WebsocketOptions.Headers["User-Agent"] = option.Listable[string]{"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.131 Safari/537.36"}

		break
	case "http":
		transport.HTTPOptions = option.V2RayHTTPOptions{
			Host:        nil,
			Path:        v.Path,
			Method:      "GET",
			Headers:     nil,
			IdleTimeout: 0,
			PingTimeout: 0,
		}
		if v.Host != "" {
			h := conf.StringList(strings.Split(v.Host, ","))
			transport.HTTPOptions.Host = option.Listable[string](h)
		}
		break
	case "httpupgrade":
		transport.HTTPUpgradeOptions = option.V2RayHTTPUpgradeOptions{
			Host: v.Host,
			Path: v.Path,
		}
		break
	case "grpc":
		// v.Mode Gun & Multi
		if len(v.ServiceName) > 0 {
			if v.ServiceName[0] == '/' {
				v.ServiceName = v.ServiceName[1:]
			}
		}
		transport.GRPCOptions = option.V2RayGRPCOptions{
			ServiceName: v.ServiceName,
		}
		break
	case "quic":
		transport.QUICOptions = option.V2RayQUICOptions{}
		break
	}

	opts := option.VLESSOutboundOptions{
		DialerOptions: option.DialerOptions{},
		ServerOptions: option.ServerOptions{
			Server:     v.Address,
			ServerPort: uint16(port),
		},
		UUID:      v.ID,
		Transport: transport,
		OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{
			TLS: &option.OutboundTLSOptions{
				Enabled:    tls,
				ServerName: v.SNI,
				ALPN:       alpn,
				UTLS: &option.OutboundUTLSOptions{
					Enabled:     true,
					Fingerprint: fingerprint,
				},
				Insecure: insecure,
			},
		},
		Flow: v.Flow,
	}
	if v.Security == "reality" {
		opts.TLS.Reality = &option.OutboundRealityOptions{
			Enabled:   true,
			PublicKey: v.PublicKey,
			ShortID:   v.ShortIds,
		}
	}

	return &option.Outbound{
		Type:         v.Name(),
		VLESSOptions: opts,
	}, nil
}

func (v *Vless) CraftOutbound(ctx context.Context, l logger.ContextLogger, allowInsecure bool) (adapter.Outbound, error) {

	options, err := v.CraftOutboundOptions(allowInsecure)
	if err != nil {
		return nil, err
	}

	out, err := outbound.New(ctx, adapter.RouterFromContext(ctx), l, "out_vless", *options)
	if err != nil {
		return nil, errors.New(fmt.Sprintf("failed creating vless outbound: %v", err))
	}

	return out, nil
}
