package singbox

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"

	"github.com/lilendian0x00/xray-knife/v11/pkg/core/protocol"
	"github.com/lilendian0x00/xray-knife/v11/utils"

	"github.com/fatih/color"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	sing_shadowsocks "github.com/sagernet/sing-box/protocol/shadowsocks"
	"github.com/sagernet/sing/common/logger"
	"github.com/sagernet/sing/service"
)

func NewShadowsocks(link string) Protocol {
	return &Shadowsocks{OrigLink: link}
}

func (s *Shadowsocks) Name() string {
	return protocol.ShadowsocksIdentifier
}

// Parse accepts the three shapes in circulation:
//
//	ss://BASE64URL(method:password)@host:port/?plugin=…#remark  (SIP002)
//	ss://method:password@host:port#remark                      (SIP002 plain, SS-2022)
//	ss://BASE64(method:password@host:port)#remark              (legacy)
func (s *Shadowsocks) Parse() error {
	body, ok := strings.CutPrefix(strings.TrimSpace(s.OrigLink), protocol.ShadowsocksIdentifier+"://")
	if !ok {
		return fmt.Errorf("shadowsocks unreconized: %s", s.OrigLink)
	}
	body, frag, _ := strings.Cut(body, "#")
	if remark, err := url.PathUnescape(frag); err == nil {
		s.Remark = remark
	} else {
		s.Remark = frag
	}

	legacy := !strings.Contains(body, "@")
	if legacy {
		// Legacy form: the whole authority is base64, the query (if any) is not.
		encoded, query, _ := strings.Cut(body, "?")
		encoded = strings.TrimSuffix(encoded, "/")
		decoded, err := utils.Base64Decode(unescapeLenient(encoded))
		if err != nil || !strings.Contains(string(decoded), "@") {
			return errors.New("invalid shadowsocks link: neither SIP002 nor legacy base64 form")
		}
		body = string(decoded)
		if query != "" {
			body += "/?" + query
		}
	}

	// Split at the last '@' by hand: url.Parse chokes on the '/' of standard
	// base64 and on raw '@' in plain passwords, and the host part has neither.
	at := strings.LastIndex(body, "@")
	userinfo, hostPart := body[:at], body[at+1:]
	uri, err := url.Parse(protocol.ShadowsocksIdentifier + "://" + hostPart)
	if err != nil {
		return fmt.Errorf("invalid shadowsocks link: %w", err)
	}
	if method, password, plain := strings.Cut(userinfo, ":"); plain {
		// Plain "method:password" (base64 never contains ':'). SIP002
		// percent-encodes it; the decoded legacy blob is raw.
		if !legacy {
			method, password = unescapeLenient(method), unescapeLenient(password)
		}
		s.Encryption, s.Password = method, password
	} else {
		decoded, err := utils.Base64Decode(unescapeLenient(userinfo))
		if err != nil {
			return errors.New("invalid shadowsocks link: userinfo is neither base64 nor method:password")
		}
		method, password, found := strings.Cut(string(decoded), ":")
		if !found {
			return errors.New("invalid shadowsocks link: userinfo has no method:password pair")
		}
		s.Encryption, s.Password = method, password
	}
	if s.Encryption == "" {
		return errors.New("invalid shadowsocks link: empty method")
	}

	s.Address, s.Port, err = net.SplitHostPort(uri.Host)
	if err != nil {
		return err
	}

	// Read plugin= from the raw query: SIP002 plugin options are separated
	// by ';', and url.ParseQuery drops any pair containing a raw ';', which
	// let "plugin=obfs-local;obfs=http" (and unsupported plugins) slip
	// through as a plain, plugin-less link.
	if plugin, found := rawQueryParam(uri.RawQuery, "plugin"); found && plugin != "" {
		name, opts, _ := strings.Cut(plugin, ";")
		switch name {
		case "obfs-local", "simple-obfs":
			s.Plugin = "obfs-local"
		case "v2ray-plugin":
			s.Plugin = name
		default:
			// Connecting without the plugin would only produce a false failure.
			return fmt.Errorf("shadowsocks plugin %q is not supported (obfs-local and v2ray-plugin are)", name)
		}
		s.PluginOptions = opts
	}

	return nil
}

// rawQueryParam returns the first value of name in rawQuery, splitting on
// '&' only and percent-decoding leniently ('+' stays '+').
func rawQueryParam(rawQuery, name string) (string, bool) {
	for _, pair := range strings.Split(rawQuery, "&") {
		key, value, _ := strings.Cut(pair, "=")
		if unescapeLenient(key) == name {
			return unescapeLenient(value), true
		}
	}
	return "", false
}

// unescapeLenient percent-decodes s, returning it unchanged if it is not
// valid percent-encoding (base64 padding often arrives as %3D).
func unescapeLenient(s string) string {
	if u, err := url.PathUnescape(s); err == nil {
		return u
	}
	return s
}

func (s *Shadowsocks) DetailsStr() string {
	info := fmt.Sprintf("%s: %s\n%s: %s\n%s: %s\n%s: %v\n%s: %s\n%s: %s\n",
		color.RedString("Protocol"), s.Name(),
		color.RedString("Remark"), s.Remark,
		color.RedString("IP"), s.Address,
		color.RedString("Port"), s.Port,
		color.RedString("Encryption"), s.Encryption,
		color.RedString("Password"), s.Password)
	if s.Plugin != "" {
		info += fmt.Sprintf("%s: %s %s\n", color.RedString("Plugin"), s.Plugin, s.PluginOptions)
	}
	return info
}

func (s *Shadowsocks) GetLink() string {
	return s.OrigLink
}

func (s *Shadowsocks) ConvertToGeneralConfig() (g protocol.GeneralConfig) {
	g.Protocol = s.Name()
	g.Address = s.Address
	g.ID = s.Password
	g.Port = s.Port
	g.Remark = s.Remark
	g.OrigLink = s.GetLink()

	return g
}

func (s *Shadowsocks) CraftInboundOptions() (*option.Inbound, error) {
	listen, err := listenOptions(s.Address, s.Port)
	if err != nil {
		return nil, err
	}
	opts := option.ShadowsocksInboundOptions{
		ListenOptions: listen,
		Method:        s.Encryption,
		Password:      s.Password,
	}
	return &option.Inbound{
		Type:    "shadowsocks",
		Tag:     "shadowsocks-in",
		Options: &opts,
	}, nil
}

func (s *Shadowsocks) CraftOutboundOptions(allowInsecure bool) (*option.Outbound, error) {
	port, err := parsePort(s.Port)
	if err != nil {
		return nil, err
	}

	opts := option.ShadowsocksOutboundOptions{
		ServerOptions: option.ServerOptions{
			Server:     serverHost(s.Address),
			ServerPort: port,
		},
		Password:      s.Password,
		Method:        s.Encryption,
		Plugin:        s.Plugin,
		PluginOptions: s.PluginOptions,
	}

	return &option.Outbound{
		Type:    "shadowsocks",
		Options: &opts,
	}, nil
}

func (s *Shadowsocks) CraftOutbound(ctx context.Context, l logger.ContextLogger, allowInsecure bool) (adapter.Outbound, error) {

	options, err := s.CraftOutboundOptions(allowInsecure)
	if err != nil {
		return nil, err
	}

	ssOptions, ok := options.Options.(*option.ShadowsocksOutboundOptions)
	if !ok {
		return nil, fmt.Errorf("shadowsocks: unexpected options type %T", options.Options)
	}
	out, err := sing_shadowsocks.NewOutbound(ctx, service.FromContext[adapter.Router](ctx), l, "out_shadowsocks", *ssOptions)
	if err != nil {
		return nil, fmt.Errorf("failed creating shadowsocks outbound: %w", err)
	}

	return out, nil
}
