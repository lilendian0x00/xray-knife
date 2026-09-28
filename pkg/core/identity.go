package core

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/url"
	"reflect"
	"sort"
	"strconv"
	"strings"

	"github.com/lilendian0x00/xray-knife/v11/pkg/core/mtproto"
	"github.com/lilendian0x00/xray-knife/v11/pkg/core/protocol"
	"github.com/lilendian0x00/xray-knife/v11/pkg/core/singbox"
	"github.com/lilendian0x00/xray-knife/v11/pkg/core/xray"
)

// ConnectionFingerprintVersion changes when stored identities need reindexing.
const ConnectionFingerprintVersion = "connection-v2"

// ConnectionFingerprint hashes a link's settings, including unknown options, without its remark.
// Keep the version prefix when storing it; matching identities do not prove connectivity.
func ConnectionFingerprint(c Core, link string) (string, error) {
	if c == nil {
		return "", errors.New("connection fingerprint requires a core")
	}
	link = strings.TrimSpace(link)
	p, err := c.CreateProtocol(link)
	if err != nil || p == nil {
		return "", errors.New("cannot fingerprint unsupported or malformed share link")
	}
	if err := p.Parse(); err != nil {
		return "", errors.New("cannot fingerprint malformed share link")
	}
	return fingerprintParsed(p, link)
}

// FingerprintProtocol returns the ConnectionFingerprint of an already
// parsed protocol, so callers that parse each link once (for testing,
// dedup and display) need not parse it again. It fingerprints the link
// the protocol was created from, giving the same value as
// ConnectionFingerprint(core, link); p must have been parsed.
func FingerprintProtocol(p protocol.Protocol) (string, error) {
	if p == nil {
		return "", errors.New("connection fingerprint requires a protocol")
	}
	link := originalLink(p)
	if strings.TrimSpace(link) == "" {
		return "", errors.New("cannot fingerprint a protocol without a share link")
	}
	return fingerprintParsed(p, link)
}

// originalLink returns the share link p was created from. Protocols keep
// it in an exported OrigLink field; GetLink may rebuild the link instead
// (MTProto does), which would drop unknown options.
func originalLink(p protocol.Protocol) string {
	v := reflect.ValueOf(p)
	if v.Kind() == reflect.Pointer && !v.IsNil() {
		v = v.Elem()
	}
	if v.Kind() == reflect.Struct {
		if f := v.FieldByName("OrigLink"); f.IsValid() && f.Kind() == reflect.String && f.String() != "" {
			return f.String()
		}
	}
	return p.GetLink()
}

// fingerprintParsed hashes link, using the parsed p to normalise
// credentials that have several encodings.
func fingerprintParsed(p protocol.Protocol, link string) (string, error) {
	link = strings.TrimSpace(link)
	// The remark never affects identity; cut it before url.Parse, which
	// rejects fragments such as "#100%".
	link = xray.NormalizeLink(link)
	base, _, _ := strings.Cut(link, "#")
	var u *url.URL
	var err error
	if strings.HasPrefix(base, "wireguard://") {
		u, err = wireguardURL(base)
	} else {
		u, err = url.Parse(moveHopPorts(base))
	}
	if err != nil {
		return "", errors.New("cannot fingerprint malformed share link")
	}
	var canonical []byte
	if u.Scheme == "vmess" {
		canonical, err = canonicalVMess(base, u)
	} else {
		// Normalize encoded/plain credentials using the selected parser. These
		// fields are absent or incomplete in GeneralConfig (notably SOCKS).
		switch v := p.(type) {
		case *xray.Shadowsocks:
			u.User = url.UserPassword(v.Encryption, v.Password)
		case *singbox.Shadowsocks:
			u.User = url.UserPassword(v.Encryption, v.Password)
		case *xray.Socks:
			u.User = url.UserPassword(v.Username, v.Password)
		case *singbox.Socks:
			u.User = url.UserPassword(v.Username, v.Password)
		case *mtproto.MTProto:
			query, queryErr := url.ParseQuery(u.RawQuery)
			if queryErr != nil {
				return "", errors.New("cannot fingerprint malformed share link")
			}
			query.Set("server", strings.ToLower(v.Address))
			query.Set("port", v.Port)
			query.Set("secret", v.Secret.Hex())
			u = &url.URL{Scheme: "tg", Host: "proxy", RawQuery: query.Encode()}
		}
		switch u.Scheme {
		case "hy2":
			u.Scheme = "hysteria2"
		case "socks5", "socks5h":
			u.Scheme = "socks"
		}
		canonical, err = canonicalURI(u, false)
	}
	if err != nil {
		return "", errors.New("cannot fingerprint malformed share link")
	}
	sum := sha256.Sum256(append([]byte(ConnectionFingerprintVersion+"\x00"), canonical...))
	return ConnectionFingerprintVersion + ":" + hex.EncodeToString(sum[:]), nil
}

func canonicalURI(u *url.URL, vmess bool) ([]byte, error) {
	query, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return nil, err // URL.Query would silently discard malformed options.
	}
	if vmess {
		query.Del("remarks")
	}
	if u.Port() == "" {
		// Schemes whose parsers assume a port when the link has none.
		if port, ok := defaultPorts[u.Scheme]; ok && u.Hostname() != "" {
			u.Host = net.JoinHostPort(u.Hostname(), port)
		}
	}
	dropDefaultParams(u.Scheme, query)
	if hopSchemes[u.Scheme] {
		basePort := u.Port()
		if n, err := strconv.ParseUint(basePort, 10, 16); err == nil {
			basePort = strconv.FormatUint(n, 10)
		}
		normalizeHopPorts(query, basePort)
	}
	u.RawQuery = query.Encode()
	u.Fragment, u.RawFragment = "", ""
	u.ForceQuery = false
	if u.Path == "/" {
		u.Path, u.RawPath = "", "" // "host:443/?a" and "host:443?a" are one link
	}
	if host, port, err := net.SplitHostPort(u.Host); err == nil {
		if n, err := strconv.ParseUint(port, 10, 16); err == nil {
			port = strconv.FormatUint(n, 10)
		}
		u.Host = net.JoinHostPort(strings.ToLower(host), port)
	}
	return []byte(u.String()), nil
}

func canonicalVMess(link string, u *url.URL) ([]byte, error) {
	// The usual VMess form is a base64 JSON object. Keep unknown fields and
	// exact JSON numbers; decoding into a protocol struct would lose extensions.
	if decoded, err := decodeIdentityBase64(strings.TrimPrefix(link, "vmess://")); err == nil {
		if fields, err := vmessFields(decoded); err == nil {
			delete(fields, "ps")
			// "v" is the share-format version, not a connection setting.
			delete(fields, "v")
			// These protocol fields accept both numeric and string forms.
			for _, key := range []string{"port", "aid"} {
				if value, ok := fields[key].(json.Number); ok {
					fields[key] = value.String()
				}
			}
			dropVMessDefaults(fields)
			body, err := json.Marshal(fields)
			return append([]byte("vmess-json:"), body...), err
		}
	}
	// Legacy VMess encodes method:uuid@host:port, with options in the query.
	decoded, err := decodeIdentityBase64(u.Host)
	if err != nil {
		return nil, err
	}
	legacy, err := url.Parse("vmess://" + string(decoded) + "?" + u.RawQuery)
	if err != nil {
		return nil, err
	}
	return canonicalURI(legacy, true)
}

// vmessKeys are the VMess JSON fields the parsers read. encoding/json
// matches them case-insensitively (the last spelling in the object wins),
// so the canonical form folds their case the same way; other keys keep
// theirs.
var vmessKeys = map[string]bool{
	"v": true, "ps": true, "add": true, "port": true, "id": true, "aid": true, "scy": true,
	"net": true, "type": true, "host": true, "path": true, "tls": true, "sni": true,
	"alpn": true, "fp": true, "allowinsecure": true, "pcs": true, "vcn": true, "ech": true,
}

// vmessFields decodes a VMess JSON object keeping exact numbers and the
// parser's key matching.
func vmessFields(decoded []byte) (map[string]any, error) {
	dec := json.NewDecoder(bytes.NewReader(decoded))
	dec.UseNumber()
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		return nil, errors.New("not a JSON object")
	}
	fields := map[string]any{}
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return nil, err
		}
		key, _ := tok.(string)
		var value any
		if err := dec.Decode(&value); err != nil {
			return nil, err
		}
		if lower := strings.ToLower(key); vmessKeys[lower] {
			key = lower
		}
		fields[key] = value // later keys win, as with encoding/json
	}
	if _, err := dec.Token(); err != nil { // closing brace
		return nil, err
	}
	if err := dec.Decode(new(any)); err != io.EOF {
		return nil, errors.New("invalid VMess JSON")
	}
	return fields, nil
}

func decodeIdentityBase64(s string) ([]byte, error) {
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if b, err := enc.DecodeString(s); err == nil {
			return b, nil
		}
	}
	return nil, errors.New("invalid base64")
}

// defaultPorts are the ports parsers assume when a link omits one.
var defaultPorts = map[string]string{"hysteria2": "443", "hy2": "443", "ssh": "22"}

// wireguardURL parses a WireGuard link by hand, like the parsers do: its
// keys are standard base64, so an unescaped "/" would end the URL
// authority early and a raw "+" would read as a space. Raw and
// percent-encoded keys give the same URL.
func wireguardURL(base string) (*url.URL, error) {
	body := strings.TrimPrefix(base, "wireguard://")
	body, rawQuery, _ := strings.Cut(body, "?")
	at := strings.LastIndex(body, "@")
	if at < 0 {
		return nil, errors.New("wireguard link without key")
	}
	key, err := url.PathUnescape(strings.ReplaceAll(body[:at], "+", "%2B"))
	if err != nil {
		key = body[:at]
	}
	return &url.URL{
		Scheme:   "wireguard",
		User:     url.User(key),
		Host:     strings.TrimSuffix(body[at+1:], "/"),
		RawQuery: strings.ReplaceAll(rawQuery, "+", "%2B"),
	}, nil
}

// hopSchemes support port hopping, written either in the authority
// ("host:443,20000-30000") or as an "mport" parameter.
var hopSchemes = map[string]bool{"hysteria2": true, "hy2": true, "hysteria": true}

// moveHopPorts rewrites a port-hopping authority into its first port plus
// an "mport" parameter, the form url.Parse accepts. Both spellings then
// normalise to the same identity (see normalizeHopPorts).
func moveHopPorts(link string) string {
	scheme, rest, found := strings.Cut(link, "://")
	if !found || !hopSchemes[strings.ToLower(scheme)] {
		return link
	}
	end := strings.IndexAny(rest, "/?")
	if end < 0 {
		end = len(rest)
	}
	authority, tail := rest[:end], rest[end:]
	colon := strings.LastIndex(authority, ":")
	if colon < 0 || strings.LastIndex(authority, "]") > colon {
		return link
	}
	ports := authority[colon+1:]
	if !strings.ContainsAny(ports, ",-") {
		return link
	}
	first := ports
	if i := strings.IndexAny(first, ",-"); i >= 0 {
		first = first[:i]
	}
	path, query, _ := strings.Cut(tail, "?")
	if query != "" {
		query += "&"
	}
	query += "mport=" + url.QueryEscape(ports)
	return scheme + "://" + authority[:colon+1] + first + path + "?" + query
}

// normalizeHopPorts rewrites every "mport" value as one sorted, deduped
// list of "a" or "a-b" ranges without the base port.
func normalizeHopPorts(q url.Values, basePort string) {
	values, ok := q["mport"]
	if !ok {
		return
	}
	seen := map[string]bool{}
	var ranges []string
	for _, v := range values {
		for r := range strings.SplitSeq(v, ",") {
			r = strings.ReplaceAll(strings.TrimSpace(r), ":", "-")
			if lo, hi, isRange := strings.Cut(r, "-"); isRange && lo == hi {
				r = lo
			}
			if r == "" || r == basePort || seen[r] {
				continue
			}
			seen[r] = true
			ranges = append(ranges, r)
		}
	}
	sort.Strings(ranges)
	if len(ranges) == 0 {
		q.Del("mport")
		return
	}
	q["mport"] = []string{strings.Join(ranges, ",")}
}

// paramAlias lists, in the parser's precedence order, other spellings of
// a parameter. The parser takes the first non-empty one; merge instead
// means it reads them all (SSH host keys).
type paramAlias struct {
	target string
	names  []string
	merge  bool
}

// paramAliases mirrors the parsers exactly (names are case-sensitive, as
// url.Values lookups are).
var paramAliases = map[string][]paramAlias{
	"vless":  {{target: "allowInsecure", names: []string{"insecure", "allow_insecure"}}},
	"trojan": {{target: "allowInsecure", names: []string{"insecure", "allow_insecure"}}},
	"tuic": {
		{target: "congestion_control", names: []string{"congestion-control", "cc"}},
		{target: "udp_relay_mode", names: []string{"udp-relay-mode"}},
		{target: "sni", names: []string{"peer"}},
		{target: "allow_insecure", names: []string{"allowInsecure", "insecure"}},
		{target: "disable_sni", names: []string{"disable-sni"}},
		{target: "reduce_rtt", names: []string{"zero_rtt_handshake"}},
	},
	"hysteria": {
		{target: "auth", names: []string{"auth_str"}},
		{target: "peer", names: []string{"sni"}},
		{target: "insecure", names: []string{"allowInsecure"}},
		{target: "upmbps", names: []string{"up"}},
		{target: "downmbps", names: []string{"down"}},
	},
	"anytls": {
		{target: "sni", names: []string{"peer"}},
		{target: "insecure", names: []string{"allowInsecure", "allow_insecure"}},
	},
	"ssh": {
		{target: "pk", names: []string{"private_key"}},
		{target: "pkp", names: []string{"private_key_passphrase", "passphrase"}},
		{target: "hk", names: []string{"host_key"}, merge: true},
	},
}

// boolParams hold a boolean; any true spelling becomes "1" and false
// (the default) is dropped.
var boolParams = map[string]bool{"insecure": true, "allowInsecure": true, "allow_insecure": true, "disable_sni": true, "reduce_rtt": true}

// normalizeAliases applies paramAliases, boolean spellings and the
// defaults of the sing-box-only schemes. Empty values are already gone,
// so "present" means "non-empty" as in the parsers.
func normalizeAliases(scheme string, q url.Values) {
	for _, a := range paramAliases[scheme] {
		if a.merge {
			for _, name := range a.names {
				q[a.target] = append(q[a.target], q[name]...)
				delete(q, name)
			}
			if len(q[a.target]) == 0 {
				delete(q, a.target)
			}
			continue
		}
		// Only the first spelling present counts; the parser ignores the rest.
		for _, name := range a.names {
			if _, ok := q[a.target]; !ok && len(q[name]) > 0 {
				q[a.target] = q[name]
			}
			delete(q, name)
		}
	}
	for key, values := range q {
		if !boolParams[key] || len(values) != 1 {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(values[0])) {
		case "1", "true", "yes":
			q[key] = []string{"1"}
		case "0", "false", "no":
			delete(q, key)
		}
	}
	drop := func(key, def string) {
		if len(q[key]) == 1 && strings.EqualFold(q[key][0], def) {
			delete(q, key)
		}
	}
	switch scheme {
	case "tuic":
		// The parser lower-cases both and accepts newreno spellings.
		for _, key := range []string{"congestion_control", "udp_relay_mode"} {
			if len(q[key]) == 1 {
				q[key] = []string{strings.ToLower(q[key][0])}
			}
		}
		if cc := q.Get("congestion_control"); cc == "newreno" || cc == "new-reno" {
			q.Set("congestion_control", "new_reno")
		}
		drop("congestion_control", "cubic")
		drop("udp_relay_mode", "native")
	case "hysteria":
		drop("protocol", "udp")
		drop("upmbps", "10") // the parser's defaults
		drop("downmbps", "50")
		// obfs=xplus&obfsParam=PW and obfs=PW both mean xplus with PW.
		if _, ok := q["obfsParam"]; ok {
			drop("obfs", "xplus")
		} else if len(q["obfs"]) == 1 && !strings.EqualFold(q["obfs"][0], "xplus") {
			q["obfsParam"] = q["obfs"]
			delete(q, "obfs")
		}
	case "anytls":
		drop("security", "tls")
	}
}

// dropDefaultParams removes query options whose value is what the parsers
// assume when the option is absent, so equivalent links share an identity:
// empty values, and per-protocol defaults such as VLESS "security=none"
// or Trojan "security=tls". Anything else, including unknown options, is
// kept.
func dropDefaultParams(scheme string, q url.Values) {
	for key, values := range q {
		empty := true
		for _, v := range values {
			if v != "" {
				empty = false
				break
			}
		}
		if empty {
			delete(q, key)
		}
	}
	normalizeAliases(scheme, q)
	drop := func(key string, defaults ...string) {
		if len(q[key]) != 1 {
			return
		}
		for _, d := range defaults {
			if strings.EqualFold(q[key][0], d) {
				delete(q, key)
				return
			}
		}
	}
	switch scheme {
	case "vless":
		drop("encryption", "none")
		drop("security", "none")
	case "trojan":
		drop("security", "tls")
	default:
		return
	}
	drop("type", "tcp", "raw")
	drop("headerType", "none")
	security := strings.ToLower(q.Get("security"))
	if scheme == "trojan" && security == "" {
		security = "tls"
	}
	if security == "tls" || security == "reality" {
		drop("fp", "chrome")
	}
}

// dropVMessDefaults is dropDefaultParams for the VMess JSON form. Server
// names are case-insensitive, so they are lower-cased.
func dropVMessDefaults(fields map[string]any) {
	for key, v := range fields {
		if s, ok := v.(string); ok && s == "" {
			delete(fields, key)
		}
	}
	for _, key := range []string{"add", "host", "sni"} {
		if s, ok := fields[key].(string); ok {
			fields[key] = strings.ToLower(s)
		}
	}
	drop := func(key string, defaults ...string) {
		s, ok := fields[key].(string)
		if !ok {
			return
		}
		for _, d := range defaults {
			if strings.EqualFold(s, d) {
				delete(fields, key)
				return
			}
		}
	}
	drop("net", "tcp", "raw")
	drop("type", "none")
	drop("tls", "none")
	drop("scy", "auto")
	drop("aid", "0")
	if tls, _ := fields["tls"].(string); strings.EqualFold(tls, "tls") {
		drop("fp", "chrome")
	}
}
