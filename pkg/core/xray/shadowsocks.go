package xray

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"unicode/utf8"

	"github.com/lilendian0x00/xray-knife/v11/pkg/core/protocol"
	"github.com/lilendian0x00/xray-knife/v11/utils"

	"github.com/fatih/color"
	"github.com/xtls/xray-core/infra/conf"
)

func NewShadowsocks(link string) Protocol {
	return &Shadowsocks{OrigLink: link}
}

func (s *Shadowsocks) Name() string {
	return "shadowsocks"
}

// Parse accepts the three Shadowsocks link forms seen in the wild:
//
//	ss://BASE64URL(method:password)@host:port[/][?plugin=...][#remark]  (SIP002)
//	ss://method:password@host:port[#remark]                            (plain, SS-2022)
//	ss://BASE64(method:password@host:port)[#remark]                    (legacy)
func (s *Shadowsocks) Parse() error {
	const prefix = protocol.ShadowsocksIdentifier + "://"
	if !strings.HasPrefix(s.OrigLink, prefix) {
		return fmt.Errorf("shadowsocks unreconized: %s", s.OrigLink)
	}

	base, remark := splitRemark(s.OrigLink)
	body := strings.TrimPrefix(base, prefix)
	s.Remark = remark

	// Legacy form: everything (credentials and endpoint) is base64.
	if !strings.Contains(beforeQuery(body), "@") {
		encoded, query, _ := strings.Cut(body, "?")
		decoded, err := utils.Base64Decode(strings.TrimSuffix(lenientUnescape(encoded), "/"))
		if err != nil || !utf8.Valid(decoded) {
			return errors.New("invalid shadowsocks link: no credentials found")
		}
		body = string(decoded)
		if query != "" {
			body += "?" + query
		}
	}

	// The last "@" before the query separates credentials from the
	// endpoint (standard base64 userinfo may itself contain "/").
	at := strings.LastIndex(beforeQuery(body), "@")
	if at < 0 {
		return errors.New("invalid shadowsocks link: no credentials found")
	}
	userInfo, rest := body[:at], body[at+1:]

	methodPass, err := decodeSSUserInfo(userInfo)
	if err != nil {
		return err
	}
	method, password, found := strings.Cut(methodPass, ":")
	if !found || method == "" {
		return errors.New("invalid shadowsocks link: credentials are not method:password")
	}
	s.Encryption = strings.ToLower(method)
	s.Password = password

	uri, err := url.Parse("ss://" + rest)
	if err != nil {
		return fmt.Errorf("invalid shadowsocks endpoint: %w", err)
	}
	s.Address, s.Port, err = net.SplitHostPort(uri.Host)
	if err != nil {
		return err
	}
	s.Plugin = uri.Query().Get("plugin")
	return nil
}

// beforeQuery returns the part of a link body before its query string.
func beforeQuery(body string) string {
	if i := strings.IndexByte(body, '?'); i >= 0 {
		return body[:i]
	}
	return body
}

// decodeSSUserInfo returns "method:password" from SIP002 base64 userinfo
// or from plain (percent-encoded) userinfo. Percent-decoding comes first
// so "%3D"-padded base64 decodes, and it never turns "+" into a space, so
// SS-2022 keys survive.
func decodeSSUserInfo(userInfo string) (string, error) {
	unescaped := lenientUnescape(userInfo)
	if !strings.Contains(unescaped, ":") {
		decoded, err := utils.Base64Decode(unescaped)
		if err != nil || !utf8.Valid(decoded) {
			return "", errors.New("invalid shadowsocks link: credentials are neither base64 nor method:password")
		}
		return string(decoded), nil
	}
	return unescaped, nil
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
		info += fmt.Sprintf("%s: %s (unsupported on xray core)\n", color.RedString("Plugin"), s.Plugin)
	}
	return info
}

func (s *Shadowsocks) GetLink() string {
	if s.OrigLink != "" {
		return s.OrigLink
	} else {
		creds := fmt.Sprintf("%s:%s", s.Encryption, s.Password)
		encodedCreds := base64.RawURLEncoding.EncodeToString([]byte(creds))

		// The Userinfo part in ss links is the base64 encoded string
		// We construct the final URL string manually as url.URL doesn't handle this specific format directly
		hostPart := net.JoinHostPort(s.Address, s.Port)
		link := fmt.Sprintf("ss://%s@%s", encodedCreds, hostPart)
		if s.Plugin != "" {
			link += "/?plugin=" + url.QueryEscape(s.Plugin)
		}
		if s.Remark != "" {
			link += "#" + url.PathEscape(s.Remark)
		}
		return link
	}
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

// xraySSMethods are the ciphers xray-core implements. Legacy stream
// ciphers (aes-*-cfb, chacha20, rc4-md5, ...) and "none"/"plain" are
// sing-box only: xray-core rejects them.
var xraySSMethods = map[string]bool{
	"aes-128-gcm": true, "aead_aes_128_gcm": true,
	"aes-256-gcm": true, "aead_aes_256_gcm": true,
	"chacha20-poly1305": true, "chacha20-ietf-poly1305": true, "aead_chacha20_poly1305": true,
	"xchacha20-poly1305": true, "xchacha20-ietf-poly1305": true, "aead_xchacha20_poly1305": true,
	"2022-blake3-aes-128-gcm": true, "2022-blake3-aes-256-gcm": true, "2022-blake3-chacha20-poly1305": true,
}

// xrayUnsupported reports why xray can't carry this link, or "" if it can.
func (s *Shadowsocks) xrayUnsupported() string {
	if s.Plugin != "" {
		return fmt.Sprintf("shadowsocks plugin %q", s.Plugin)
	}
	if !xraySSMethods[s.Encryption] {
		return fmt.Sprintf("shadowsocks cipher %q", s.Encryption)
	}
	return ""
}

func (s *Shadowsocks) BuildOutboundDetourConfig(allowInsecure bool) (*conf.OutboundDetourConfig, error) {
	// Refuse rather than connect without the plugin: the result would be
	// a false failure (or a false pass against the wrong server).
	if reason := s.xrayUnsupported(); reason != "" {
		return nil, fmt.Errorf("%s is not supported by xray-core; use the sing-box or automatic core", reason)
	}
	portNum, err := parsePort(s.Port)
	if err != nil {
		return nil, err
	}
	settings, err := json.Marshal(map[string]interface{}{
		"servers": []map[string]interface{}{{
			"address":  s.Address,
			"port":     portNum,
			"password": s.Password,
			"method":   s.Encryption,
			"uot":      false,
		}},
	})
	if err != nil {
		return nil, fmt.Errorf("marshal shadowsocks settings: %w", err)
	}
	oset := json.RawMessage(settings)
	return &conf.OutboundDetourConfig{
		Tag:           "proxy",
		Protocol:      s.Name(),
		Settings:      &oset,
		StreamSetting: &conf.StreamConfig{},
	}, nil
}

func (s *Shadowsocks) BuildInboundDetourConfig() (*conf.InboundDetourConfig, error) {
	settings := map[string]interface{}{
		"method":   s.Encryption,
		"password": s.Password,
		"network":  "tcp,udp",
	}
	return inboundDetour(s.Name(), s.Address, s.Port, settings, nil)
}
