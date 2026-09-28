package xray

import (
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	xnet "github.com/xtls/xray-core/common/net"
)

// splitRemark separates the "#remark" fragment from a share link so that
// url.Parse never sees it. url.Parse rejects a fragment holding a bare
// "%" (e.g. "#Speed 100%"), which would throw away an otherwise valid
// link; the remark is decoded leniently and exactly once instead.
func splitRemark(link string) (base, remark string) {
	base, frag, found := strings.Cut(link, "#")
	if !found {
		return link, ""
	}
	return base, lenientUnescape(frag)
}

// lenientUnescape percent-decodes s, keeping malformed escapes (a "%" not
// followed by two hex digits) literally. Unlike url.QueryUnescape it
// leaves "+" alone.
func lenientUnescape(s string) string {
	if !strings.Contains(s, "%") {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		if s[i] == '%' && i+2 < len(s) && isHex(s[i+1]) && isHex(s[i+2]) {
			b.WriteByte(unhex(s[i+1])<<4 | unhex(s[i+2]))
			i += 2
			continue
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

func isHex(c byte) bool {
	return ('0' <= c && c <= '9') || ('a' <= c && c <= 'f') || ('A' <= c && c <= 'F')
}

func unhex(c byte) byte {
	switch {
	case '0' <= c && c <= '9':
		return c - '0'
	case 'a' <= c && c <= 'f':
		return c - 'a' + 10
	default:
		return c - 'A' + 10
	}
}

// userSecret returns the decoded userinfo of a share link: the username,
// or "user:password" when a password part is present. Trojan and
// Hysteria2 passwords may contain ":" and must be sent decoded
// (url.Userinfo.String() returns the escaped form).
func userSecret(u *url.Userinfo) string {
	if u == nil {
		return ""
	}
	if p, ok := u.Password(); ok {
		return u.Username() + ":" + p
	}
	return u.Username()
}

// unbracket strips the brackets url.URL.Host keeps around IPv6 literals.
func unbracket(host string) string {
	if len(host) >= 2 && host[0] == '[' && host[len(host)-1] == ']' {
		return host[1 : len(host)-1]
	}
	return host
}

// listenAddress turns an inbound listen address into an IP literal.
// An empty address or "localhost" means loopback. Anything that is not
// an IP is rejected rather than silently widened to every interface:
// the inbounds built here (SOCKS, HTTP) are often unauthenticated.
func listenAddress(addr string) (string, error) {
	a := unbracket(strings.TrimSpace(addr))
	switch strings.ToLower(a) {
	case "", "localhost":
		return "127.0.0.1", nil
	}
	if ip := net.ParseIP(a); ip != nil {
		return ip.String(), nil
	}
	return "", fmt.Errorf("listen address %q is not an IP address (use e.g. 127.0.0.1, 0.0.0.0 or ::1)", addr)
}

// truthy interprets share-link booleans such as allowInsecure, which
// appear as "1"/"true" in query strings and as bools or numbers in VMess
// JSON.
func truthy(v interface{}) bool {
	switch t := v.(type) {
	case bool:
		return t
	case string:
		switch strings.ToLower(strings.TrimSpace(t)) {
		case "1", "true", "yes":
			return true
		}
	case float64:
		return t != 0
	case json.Number:
		return t.String() != "0" && t.String() != ""
	}
	return false
}

// rawQueryValues parses a query string like url.ParseQuery but without
// turning "+" into a space. WireGuard keys are standard base64, and a
// "+" in them is almost never percent-encoded by link generators.
func rawQueryValues(raw string) url.Values {
	v := url.Values{}
	for pair := range strings.SplitSeq(raw, "&") {
		if pair == "" {
			continue
		}
		key, value, _ := strings.Cut(pair, "=")
		key = lenientUnescape(key)
		if key == "" {
			continue
		}
		v.Add(key, lenientUnescape(value))
	}
	return v
}

// splitList splits a comma-separated link value, trimming blanks.
func splitList(s string) []string {
	var out []string
	for part := range strings.SplitSeq(s, ",") {
		if part = strings.TrimSpace(part); part != "" {
			out = append(out, part)
		}
	}
	return out
}

// validHostList reports whether s can be used as a Host header / SNI
// value: a comma-separated list of names, optionally with ":port".
// Underscores, wildcards and IDN labels are allowed (real links use
// them); whitespace, control characters and URL/JSON delimiters are
// not, since they would corrupt the generated config or request.
func validHostList(s string) bool {
	for _, r := range s {
		if r <= ' ' || r == 0x7f {
			return false
		}
		if strings.ContainsRune(`[]()"\<>{}|^`+"`/?#@", r) {
			return false
		}
	}
	return true
}

// parsePort validates a share-link port (1-65535).
func parsePort(port string) (uint16, error) {
	n, err := strconv.ParseUint(strings.TrimSpace(port), 10, 16)
	if err != nil || n == 0 {
		return 0, fmt.Errorf("invalid port %q", port)
	}
	return uint16(n), nil
}

// portString renders a port that VMess JSON may carry as a string or a
// number.
func portString(v interface{}) string {
	switch t := v.(type) {
	case nil:
		return ""
	case string:
		return strings.TrimSpace(t)
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64)
	case json.Number:
		return t.String()
	default:
		return fmt.Sprint(t)
	}
}

// parseXrayAddress converts an IP or domain into an xray address.
func parseXrayAddress(a string) xnet.Address {
	return xnet.ParseAddress(a)
}

// validSNI reports whether s can be a TLS server name: a single host
// name, so no list separator or port (see validHostList for Host).
func validSNI(s string) bool {
	return validHostList(s) && !strings.ContainsAny(s, ",:")
}

// firstQuery returns the first non-empty value among the given parameter
// spellings, in order.
func firstQuery(q url.Values, keys ...string) string {
	for _, k := range keys {
		if v := q.Get(k); v != "" {
			return v
		}
	}
	return ""
}
