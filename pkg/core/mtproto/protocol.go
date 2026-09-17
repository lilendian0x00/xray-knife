package mtproto

import (
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/fatih/color"

	"github.com/lilendian0x00/xray-knife/v11/pkg/core/protocol"
)

// MTProto is a parsed Telegram MTProto proxy share link.
type MTProto struct {
	OrigLink  string
	Remark    string
	Address   string
	Port      string
	RawSecret string // secret exactly as it appeared in the link
	Secret    Secret
}

// NewMTProto wraps a share link; call Parse before using other methods.
func NewMTProto(link string) *MTProto {
	return &MTProto{OrigLink: strings.TrimSpace(link)}
}

// IsProxyLink reports whether link is an MTProto proxy share link:
// tg://proxy?… or http(s)://t.me|telegram.me|telegram.dog/proxy?….
func IsProxyLink(link string) bool {
	u, err := url.Parse(strings.TrimSpace(link))
	if err != nil {
		return false
	}
	switch strings.ToLower(u.Scheme) {
	case "tg":
		return u.User == nil && strings.EqualFold(u.Host, "proxy") && (u.Path == "" || u.Path == "/")
	case "http", "https":
		switch strings.ToLower(u.Hostname()) {
		case "t.me", "telegram.me", "telegram.dog":
			return u.User == nil && u.Port() == "" && (u.Path == "/proxy" || u.Path == "/proxy/")
		}
	}
	return false
}

func (m *MTProto) Name() string { return protocol.MTProtoIdentifier }

// Parse validates the link and decodes its secret.
func (m *MTProto) Parse() error {
	if !IsProxyLink(m.OrigLink) {
		return fmt.Errorf("not an mtproto proxy link: %s", m.OrigLink)
	}
	u, err := url.Parse(m.OrigLink)
	if err != nil {
		return err
	}
	q, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return fmt.Errorf("invalid mtproto query: %w", err)
	}
	for _, name := range []string{"server", "port", "secret"} {
		if len(q[name]) > 1 {
			return fmt.Errorf("duplicate mtproto %s parameter", name)
		}
	}
	m.Address = strings.TrimSpace(q.Get("server"))
	if m.Address == "" {
		return errors.New("mtproto link is missing the server parameter")
	}
	m.Port = strings.TrimSpace(q.Get("port"))
	if m.Port == "" {
		return errors.New("mtproto link is missing the port parameter")
	}
	n, err := strconv.ParseUint(m.Port, 10, 16)
	if err != nil || n == 0 {
		return fmt.Errorf("mtproto link has an invalid port %q", m.Port)
	}
	m.Port = strconv.FormatUint(n, 10)
	m.RawSecret = strings.TrimSpace(q.Get("secret"))
	if m.RawSecret == "" {
		return errors.New("mtproto link is missing the secret parameter")
	}
	m.Secret, err = ParseSecret(m.RawSecret)
	if err != nil {
		return err
	}
	m.Remark = u.Fragment
	return nil
}

// GetLink returns the canonical tg://proxy form with the hex secret.
func (m *MTProto) GetLink() string {
	// Built by hand to keep the parameter order stable.
	link := "tg://proxy?server=" + url.QueryEscape(m.Address) + "&port=" + m.Port + "&secret=" + m.Secret.Hex()
	if m.Remark != "" {
		link += "#" + url.PathEscape(m.Remark)
	}
	return link
}

func (m *MTProto) DetailsStr() string {
	info := fmt.Sprintf("%s: %s\n%s: %s\n%s: %s\n%s: %s\n%s: %s\n",
		color.RedString("Protocol"), m.Name(),
		color.RedString("Remark"), m.Remark,
		color.RedString("Address"), m.Address,
		color.RedString("Port"), m.Port,
		color.RedString("Secret Type"), m.Secret.Type.String(),
	)
	if m.Secret.Type == SecretFakeTLS {
		info += fmt.Sprintf("%s: %s\n", color.RedString("Cloak Host"), m.Secret.CloakHost)
	}
	info += fmt.Sprintf("%s: %s\n", color.RedString("Secret"), m.Secret.Hex())
	return info
}

func (m *MTProto) ConvertToGeneralConfig() protocol.GeneralConfig {
	g := protocol.GeneralConfig{
		Protocol: protocol.MTProtoIdentifier,
		Address:  m.Address,
		Port:     m.Port,
		ID:       m.Secret.Hex(),
		TLS:      "none",
		Network:  "tcp",
		Type:     "tcp",
		Remark:   m.Remark,
		OrigLink: m.OrigLink,
	}
	if m.Secret.Type == SecretFakeTLS {
		g.TLS = "faketls"
		g.SNI = m.Secret.CloakHost
	}
	return g
}
