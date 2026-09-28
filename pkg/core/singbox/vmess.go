package singbox

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	"github.com/lilendian0x00/xray-knife/v11/pkg/core/protocol"
	"github.com/lilendian0x00/xray-knife/v11/utils"

	"github.com/fatih/color"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	sing_vmess "github.com/sagernet/sing-box/protocol/vmess"
	"github.com/sagernet/sing/common/logger"
	"github.com/sagernet/sing/service"
)

func NewVmess(link string) Protocol {
	return &Vmess{OrigLink: link}
}

func (v *Vmess) Name() string {
	return protocol.VmessIdentifier
}

func method1(v *Vmess, link string) error {
	b64encoded, ok := strings.CutPrefix(link, protocol.VmessIdentifier+"://")
	if !ok {
		return errors.New("missing vmess:// prefix")
	}
	// The remark some exporters append after the base64 blob is not part of it.
	b64encoded, _, _ = strings.Cut(b64encoded, "#")
	decoded, err := utils.Base64Decode(b64encoded)
	if err != nil {
		return err
	}
	if err = json.Unmarshal(decoded, v); err != nil {
		return err
	}
	v.Address = serverHost(v.Address)
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

	if err1 := method1(v, v.OrigLink); err1 != nil {
		if err2 := method2(v, v.OrigLink); err2 != nil {
			// Neither error quotes the link, so the UUID stays out of reasons and logs.
			return fmt.Errorf("invalid vmess link: not base64 JSON (%v) nor base64 userinfo (%v)", err1, err2)
		}
	}

	if v.Type == "http" || v.Network == "ws" || v.Network == "h2" {
		if v.Path == "" {
			v.Path = "/"
		}
	}

	return nil
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
	g.SNI = v.SNI
	g.ALPN = v.ALPN
	g.TlsFingerprint = v.TlsFingerprint
	g.Type = v.Type
	g.OrigLink = v.GetLink()

	return g
}

// port returns the numeric port; the JSON form carries it as a number or a
// string.
func (v *Vmess) port() (uint16, error) {
	switch p := v.Port.(type) {
	case float64:
		if p < 1 || p > 65535 || p != float64(int(p)) {
			return 0, fmt.Errorf("invalid port %v", p)
		}
		return uint16(p), nil
	case int:
		if p < 1 || p > 65535 {
			return 0, fmt.Errorf("invalid port %d", p)
		}
		return uint16(p), nil
	case string:
		return parsePort(p)
	default:
		return 0, errors.New("invalid port: missing or not a number")
	}
}

// alterID returns the numeric alterId; like the port it may be a string.
func (v *Vmess) alterID() (int, error) {
	switch aid := v.Aid.(type) {
	case nil:
		return 0, nil
	case int:
		return aid, nil
	case float64:
		return int(aid), nil
	case string:
		if aid == "" {
			return 0, nil
		}
		n, err := strconv.Atoi(aid)
		if err != nil {
			return 0, fmt.Errorf("invalid alterId %q", aid)
		}
		return n, nil
	default:
		return 0, errors.New("invalid type of aid")
	}
}

// transport returns the link's transport. VMess keeps the gRPC service
// name in "path" and the TCP header type in "type".
func (v *Vmess) transport() v2rayTransport {
	return v2rayTransport{Network: v.Network, HeaderType: v.Type, Host: v.Host, Path: v.Path, ServiceName: v.Path}
}

func (v *Vmess) CraftInboundOptions() (*option.Inbound, error) {
	port, err := v.port()
	if err != nil {
		return nil, err
	}
	listen, err := listenOptions(v.Address, strconv.Itoa(int(port)))
	if err != nil {
		return nil, err
	}
	aid, err := v.alterID()
	if err != nil {
		return nil, err
	}
	transport, err := buildTransport(v.transport())
	if err != nil {
		return nil, err
	}

	opts := option.VMessInboundOptions{
		ListenOptions: listen,
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
		Type:    v.Name(),
		Tag:     "vmess-in",
		Options: &opts,
	}, nil
}

func (v *Vmess) CraftOutboundOptions(allowInsecure bool) (*option.Outbound, error) {
	return v.craftOutbound(allowInsecure, utlsAvailable)
}

func (v *Vmess) craftOutbound(allowInsecure, utls bool) (*option.Outbound, error) {
	port, err := v.port()
	if err != nil {
		return nil, err
	}
	aid, err := v.alterID()
	if err != nil {
		return nil, err
	}

	tlsOpts, transport, err := buildStream(tlsParams{
		UTLS:          utls,
		Security:      v.TLS,
		SNI:           v.SNI,
		ALPN:          v.ALPN,
		Fingerprint:   v.TlsFingerprint,
		AllowInsecure: fmt.Sprint(v.AllowInsecure),
	}, v.transport(), allowInsecure)
	if err != nil {
		return nil, err
	}

	opts := option.VMessOutboundOptions{
		ServerOptions: option.ServerOptions{
			Server:     serverHost(v.Address),
			ServerPort: port,
		},
		UUID:                        v.ID,
		Security:                    v.Security,
		Transport:                   transport,
		AlterId:                     aid,
		OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{TLS: tlsOpts},
	}

	return &option.Outbound{
		Type:    v.Name(),
		Options: &opts,
	}, nil
}

func (v *Vmess) CraftOutbound(ctx context.Context, l logger.ContextLogger, allowInsecure bool) (adapter.Outbound, error) {

	options, err := v.CraftOutboundOptions(allowInsecure)
	if err != nil {
		return nil, err
	}

	vmessOptions, ok := options.Options.(*option.VMessOutboundOptions)
	if !ok {
		return nil, fmt.Errorf("vmess: unexpected options type %T", options.Options)
	}
	out, err := sing_vmess.NewOutbound(ctx, service.FromContext[adapter.Router](ctx), l, "out_vmess", *vmessOptions)
	if err != nil {
		return nil, fmt.Errorf("failed creating vmess outbound: %w", err)
	}

	return out, nil
}
