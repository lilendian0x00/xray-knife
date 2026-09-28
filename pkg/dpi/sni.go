package dpi

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// WithSNI returns link with its TLS server name replaced by sni. It handles
// URL-style links (vless, trojan, hysteria2, ss plugins aside) through the
// "sni" query parameter and VMess JSON links through their "sni" field.
func WithSNI(link, sni string) (string, error) {
	scheme, rest, ok := strings.Cut(link, "://")
	if !ok {
		return "", errors.New("not a share link")
	}
	if strings.EqualFold(scheme, "vmess") {
		return vmessWithSNI(rest, sni)
	}

	// Keep the fragment (remark) out of url.Parse: remarks often contain
	// characters that are not valid escapes.
	body, remark, hasRemark := strings.Cut(rest, "#")
	u, err := url.Parse(scheme + "://" + body)
	if err != nil {
		return "", fmt.Errorf("parse link: %w", err)
	}
	q := u.Query()
	q.Set("sni", sni)
	// Some clients read "peer" (legacy trojan) or "serverName".
	if q.Has("peer") {
		q.Set("peer", sni)
	}
	u.RawQuery = q.Encode()
	out := u.String()
	if hasRemark {
		out += "#" + remark
	}
	return out, nil
}

func vmessWithSNI(payload, sni string) (string, error) {
	raw, err := decodeAnyBase64(payload)
	if err != nil {
		return "", fmt.Errorf("vmess link is not base64 JSON: %w", err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return "", fmt.Errorf("vmess link is not base64 JSON: %w", err)
	}
	m["sni"] = sni
	b, err := json.Marshal(m)
	if err != nil {
		return "", err
	}
	return "vmess://" + base64.StdEncoding.EncodeToString(b), nil
}

func decodeAnyBase64(s string) ([]byte, error) {
	s = strings.TrimRight(strings.TrimSpace(s), "=")
	if b, err := base64.RawStdEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	return base64.RawURLEncoding.DecodeString(s)
}

// RandomCase returns s with letters in alternating case ("ExAmPlE.CoM").
// SNI matching is case-insensitive per RFC 6066, but some filters compare
// bytes, so a mixed-case name slips past them.
func RandomCase(s string) string {
	b := []byte(s)
	upper := true
	for i, c := range b {
		switch {
		case c >= 'a' && c <= 'z':
			if upper {
				b[i] = c - 32
			}
			upper = !upper
		case c >= 'A' && c <= 'Z':
			if !upper {
				b[i] = c + 32
			}
			upper = !upper
		}
	}
	return string(b)
}
