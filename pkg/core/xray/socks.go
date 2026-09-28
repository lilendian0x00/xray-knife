package xray

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"strings"

	"github.com/lilendian0x00/xray-knife/v11/pkg/core/protocol"
	"github.com/lilendian0x00/xray-knife/v11/utils"

	"github.com/fatih/color"
	"github.com/xtls/xray-core/infra/conf"
)

func NewSocks(link string) Protocol {
	return &Socks{OrigLink: link}
}

func (s *Socks) Name() string {
	return "socks"
}

func (s *Socks) Parse() error {
	if !strings.HasPrefix(s.OrigLink, protocol.SocksIdentifier) {
		return fmt.Errorf("socks unreconized: %s", s.OrigLink)
	}

	base, remark := splitRemark(s.OrigLink)
	uri, err := url.Parse(base)
	if err != nil {
		return err
	}
	s.Remark = remark
	s.Address, s.Port, err = net.SplitHostPort(uri.Host)
	if err != nil {
		return err
	}

	if uri.User != nil && len(uri.User.String()) != 0 {
		if password, hasPassword := uri.User.Password(); hasPassword {
			// Plain "user:pass" userinfo.
			s.Username = uri.User.Username()
			s.Password = password
		} else if decoded, decErr := utils.Base64Decode(uri.User.Username()); decErr == nil {
			if user, pass, found := strings.Cut(string(decoded), ":"); found {
				// Base64-encoded "user:pass".
				s.Username = user
				s.Password = pass
			} else {
				// Base64 without a colon: treat the raw userinfo as the username.
				s.Username = uri.User.Username()
			}
		} else {
			// Not base64: treat the raw userinfo as the username.
			s.Username = uri.User.Username()
		}
	}

	return nil
}

func (s *Socks) DetailsStr() string {
	copyV := *s

	info := fmt.Sprintf("%s: %s\n%s: %s\n%s: %s\n%s: %s\n%s: %v\n",
		color.RedString("Protocol"), s.Name(),
		color.RedString("Remark"), copyV.Remark,
		color.RedString("Network"), "tcp",
		color.RedString("Address"), copyV.Address,
		color.RedString("Port"), copyV.Port,
	)

	if len(copyV.Username) != 0 && len(copyV.Password) != 0 {
		info += color.RedString("Username") + ": " + copyV.Username
		info += "\n"
		info += color.RedString("Password") + ": " + copyV.Password
		info += "\n"
	}
	return info
}

// GetLink generates a SOCKS config link from the struct's fields.
func (s *Socks) GetLink() string {
	if s.OrigLink != "" {
		return s.OrigLink
	} else {
		baseURL := url.URL{
			Scheme: "socks",
			Host:   net.JoinHostPort(s.Address, s.Port),
		}

		if s.Username != "" && s.Password != "" {
			creds := fmt.Sprintf("%s:%s", s.Username, s.Password)
			encodedCreds := base64.StdEncoding.EncodeToString([]byte(creds))
			baseURL.User = url.User(encodedCreds)
		}

		if s.Remark != "" {
			baseURL.Fragment = s.Remark
		}

		return baseURL.String()
	}
}

func (s *Socks) ConvertToGeneralConfig() (g protocol.GeneralConfig) {
	g.Protocol = s.Name()
	g.Address = s.Address
	g.Port = fmt.Sprintf("%v", s.Port)
	g.Remark = s.Remark

	g.OrigLink = s.GetLink()

	return g
}

func (s *Socks) BuildOutboundDetourConfig(allowInsecure bool) (*conf.OutboundDetourConfig, error) {
	portNum, err := parsePort(s.Port)
	if err != nil {
		return nil, err
	}
	server := map[string]interface{}{
		"address": s.Address,
		"port":    portNum,
	}
	if s.Username != "" {
		server["users"] = []map[string]string{{"user": s.Username, "pass": s.Password}}
	}
	settings, err := json.Marshal(map[string]interface{}{
		"servers": []map[string]interface{}{server},
	})
	if err != nil {
		return nil, fmt.Errorf("marshal socks settings: %w", err)
	}
	oset := json.RawMessage(settings)
	p := conf.TransportProtocol("tcp")
	return &conf.OutboundDetourConfig{
		Tag:      "proxy",
		Protocol: "socks",
		Settings: &oset,
		StreamSetting: &conf.StreamConfig{
			Network:     &p,
			TCPSettings: &conf.TCPConfig{},
		},
	}, nil
}

func (s *Socks) BuildInboundDetourConfig() (*conf.InboundDetourConfig, error) {
	settings := map[string]interface{}{
		"auth":             "noauth",
		"udp":              true,
		"allowTransparent": false,
	}
	if len(s.Username) != 0 {
		settings["auth"] = "password"
		settings["accounts"] = []map[string]string{{"user": s.Username, "pass": s.Password}}
	}
	p := conf.TransportProtocol("tcp")
	return inboundDetour(s.Name(), s.Address, s.Port, settings, &conf.StreamConfig{Network: &p})
}
