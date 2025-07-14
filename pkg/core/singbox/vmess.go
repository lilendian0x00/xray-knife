package singbox

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"

	"github.com/lilendian0x00/xray-knife/v5/pkg/core/protocol"
	"github.com/lilendian0x00/xray-knife/v5/utils"

	"github.com/fatih/color"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/outbound"
	"github.com/sagernet/sing/common/logger"
	"github.com/xtls/xray-core/infra/conf"
)

func NewVmess(link string) Protocol {
	return &Vmess{OrigLink: link}
}

func (v *Vmess) Name() string {
	return protocol.VmessIdentifier
}

func method1(v *Vmess, link string) error {
	b64encoded := link[8:]
	decoded, err := utils.Base64Decode(b64encoded)
	if err != nil {
		return err
	}
	if err = json.Unmarshal(decoded, v); err != nil {
		return err
	}

	if utils.IsIPv6(v.Address) {
		v.Address = "[" + v.Address + "]"
	}
	return nil
}

// Example:
// vmess://YXV0bzpjYmI0OTM1OC00NGQxLTQ4MmYtYWExNC02ODA3NzNlNWNjMzdAc25hcHBmb29kLmlyOjQ0Mw?remarks=sth&obfsParam=huhierg.com&path=/&obfs=websocket&tls=1&peer=gdfgreg.com&alterId=0
func method2(v *Vmess, link string) error {
	uri, err := url.Parse(link)
	if err != nil {
		return err
	}
	decoded, err := utils.Base64Decode(uri.Host)
	if err != nil {
		return err
	}
	link = protocol.VmessIdentifier + "://" + string(decoded) + "?" + uri.RawQuery

	uri, err = url.Parse(link)
	if err != nil {
		return err
	}

	v.Security = uri.User.Username()
	v.ID, _ = uri.User.Password()

	v.Address, v.Port, err = net.SplitHostPort(uri.Host)
	if err != nil {
		return err
	}

	if utils.IsIPv6(v.Address) {
		v.Address = "[" + v.Address + "]"
	}
	//parseUint, err := strconv.ParseUint(suhp[2], 10, 16)
	//if err != nil {
	//	return err
	//}

	v.Aid = "0"

	queryValues := uri.Query()
	if value := queryValues.Get("remarks"); value != "" {
		v.Remark = value
	}

	if value := queryValues.Get("path"); value != "" {
		v.Path = value
	}

	if value := queryValues.Get("tls"); value == "1" {
		v.TLS = "tls"
	}

	if value := queryValues.Get("obfs"); value != "" {
		switch value {
		case "websocket":
			v.Network = "ws"
			v.Type = "none"
		case "none":
			v.Network = "tcp"
			v.Type = "none"
		}
	}
	if value := queryValues.Get("obfsParam"); value != "" {
		v.Host = value
	}
	if value := queryValues.Get("peer"); value != "" {
		v.SNI = value
	} else {
		if v.TLS == "tls" {
			v.SNI = v.Host
		}
	}

	return nil
}

//func method3(v *Vmess, link string) error {
//
//}

func (v *Vmess) Parse() error {
	if !strings.HasPrefix(v.OrigLink, protocol.VmessIdentifier) {
		return fmt.Errorf("vmess unreconized: %s", v.OrigLink)
	}

	var err error = nil

	if err = method1(v, v.OrigLink); err != nil {
		if err = method2(v, v.OrigLink); err != nil {
			return err
		}
	}

	if v.Type == "http" || v.Network == "ws" || v.Network == "h2" {
		if v.Path == "" {
			v.Path = "/"
		}
	}

	return err
}

func (v *Vmess) DetailsStr() string {
	copyV := *v
	info := fmt.Sprintf("%s: %s\n%s: %s\n%s: %s\n%s: %s\n%s: %v\n%s: %s\n",
		color.RedString("Protocol"), v.Name(),
		color.RedString("Remark"), copyV.Remark,
		color.RedString("Network"), copyV.Network,
		color.RedString("Address"), copyV.Address,
		color.RedString("Port"), copyV.Port,
		color.RedString("UUID"), copyV.ID)

	if copyV.Network == "" {

	} else if copyV.Type == "http" || copyV.Network == "httpupgrade" || copyV.Network == "ws" || copyV.Network == "h2" {
		if copyV.Type == "" {
			copyV.Type = "none"
		}
		if copyV.Host == "" {
			copyV.Host = "none"
		}
		if copyV.Path == "" {
			copyV.Path = "none"
		}

		info += fmt.Sprintf("%s: %s\n%s: %s\n%s: %s\n",
			color.RedString("Type"), copyV.Type,
			color.RedString("Host"), copyV.Host,
			color.RedString("Path"), copyV.Path)
	} else if copyV.Network == "kcp" {
		info += fmt.Sprintf("%s: %s\n", color.RedString("KCP Seed"), copyV.Path)
	} else if copyV.Network == "grpc" {
		if copyV.Host == "" {
			copyV.Host = "none"
		}
		info += fmt.Sprintf("%s: %s\n", color.RedString("ServiceName"), copyV.Path)
	}

	if len(copyV.TLS) != 0 && copyV.TLS != "none" {
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
		if len(copyV.TlsFingerprint) == 0 {
			copyV.TlsFingerprint = "none"
		}
		info += fmt.Sprintf("%s: tls\n%s: %s\n%s: %s\n%s: %s\n",
			color.RedString("TLS"),
			color.RedString("SNI"), copyV.SNI,
			color.RedString("ALPN"), copyV.ALPN,
			color.RedString("Fingerprint"), copyV.TlsFingerprint)
	}
	return info
}

func (v *Vmess) GetLink() string {
	return v.OrigLink
}

func (v *Vmess) ConvertToGeneralConfig() (g protocol.GeneralConfig) {
	g.Protocol = v.Name()
	g.Address = v.Address
	g.Aid = fmt.Sprintf("%v", v.Aid)
	g.Host = v.Host
	g.ID = v.ID
	g.Network = v.Network
	g.Path = v.Path
	g.Port = fmt.Sprintf("%v", v.Port)
	g.Remark = v.Remark
	if v.TLS == "" {
		g.TLS = "none"
	} else {
		g.TLS = v.TLS
	}
	g.TLS = v.TLS
	g.SNI = v.SNI
	g.ALPN = v.ALPN
	g.TlsFingerprint = v.TlsFingerprint
	g.Type = v.Type
	g.OrigLink = v.GetLink()

	return g
}

func (v *Vmess) CraftInboundOptions() *option.Inbound {
	var port int
	switch p := v.Port.(type) {
	case float64:
		port = int(p)
	case int:
		port = p
	case string:
		intPort, err := strconv.Atoi(p)
		if err == nil {
			port = intPort
		}
	}

	addr, _ := netip.ParseAddr(v.Address)

	var aid int = 0
	if v.Aid != nil {
		switch aidT := v.Aid.(type) {
		case int:
			aid = aidT
		case float64:
			aid = int(aidT)
		case string:
			aid, _ = strconv.Atoi(aidT)
		}
	}

	var transport = &option.V2RayTransportOptions{
		Type: v.Network,
	}

	switch v.Network {
	case "ws":
		transport.WebsocketOptions = option.V2RayWebsocketOptions{
			Path: v.Path,
		}
	case "grpc":
		if len(v.Path) > 0 && v.Path[0] == '/' {
			v.Path = v.Path[1:]
		}
		transport.GRPCOptions = option.V2RayGRPCOptions{
			ServiceName: v.Path,
		}
	}

	opts := option.VMessInboundOptions{
		ListenOptions: option.ListenOptions{
			Listen:     option.NewListenAddress(addr),
			ListenPort: uint16(port),
		},
		Users: []option.VMessUser{
			{
				Name:    "user",
				UUID:    v.ID,
				AlterId: aid,
			},
		},
		Transport: transport,
	}

	return &option.Inbound{
		Type:         v.Name(),
		Tag:          "vmess-in",
		VMessOptions: opts,
	}
}

func (v *Vmess) CraftOutboundOptions(allowInsecure bool) (*option.Outbound, error) {
	// Port type checker
	var port int
	switch t := v.Port.(type) {
	case float64:
		port = int(t)
	case int:
		port = t
	case string:
		p, err := strconv.Atoi(t)
		if err != nil {
			return nil, fmt.Errorf("invalid port %q: %w", v, err)
		}
		port = p
	default:
		return nil, fmt.Errorf("invalid port %q: unknown port number", v)
	}

	var aid int = 0
	if v.Aid != nil {
		switch aidT := v.Aid.(type) {
		case int:
			aid = aidT
		case float64:
			aid = int(aidT)
		case string:
			aid, _ = strconv.Atoi(aidT)
		default:
			return nil, errors.New("invalid type of aid")
		}
	}

	tls := false
	var alpn []string
	var fingerprint string
	var insecure = allowInsecure

	if v.TLS == "tls" {
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
		Type: v.Network,
	}

	switch v.Network {
	case "tcp":
		break
	case "ws":
		transport.WebsocketOptions = option.V2RayWebsocketOptions{
			Path:    v.Path,
			Headers: option.HTTPHeader{},
		}
		transport.WebsocketOptions.Headers["Host"] = option.Listable[string]{v.Host}
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
			Host:    v.Host,
			Path:    v.Path,
			Headers: nil,
		}
		break
	case "grpc":
		// v.Mode Gun & Multi
		if len(v.Path) > 0 {
			if v.Path[0] == '/' {
				v.Path = v.Path[1:]
			}
		}

		transport.GRPCOptions = option.V2RayGRPCOptions{
			ServiceName: v.Path,
		}
		break
	case "quic":
		transport.QUICOptions = option.V2RayQUICOptions{}
		break
	}

	opts := option.VMessOutboundOptions{
		DialerOptions: option.DialerOptions{},
		ServerOptions: option.ServerOptions{
			Server:     v.Address,
			ServerPort: uint16(port),
		},
		UUID:      v.ID,
		Security:  v.Security,
		Transport: transport,
		AlterId:   aid,
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
	}

	return &option.Outbound{
		Type:         v.Name(),
		VMessOptions: opts,
	}, nil
}

func (v *Vmess) CraftOutbound(ctx context.Context, l logger.ContextLogger, allowInsecure bool) (adapter.Outbound, error) {

	options, err := v.CraftOutboundOptions(allowInsecure)
	if err != nil {
		return nil, err
	}

	out, err := outbound.New(ctx, adapter.RouterFromContext(ctx), l, "out_vmess", *options)
	if err != nil {
		return nil, errors.New(fmt.Sprintf("failed creating vmess outbound: %v", err))
	}

	return out, nil
}
