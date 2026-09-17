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
	"strconv"
	"strings"

	"github.com/lilendian0x00/xray-knife/v11/pkg/core/mtproto"
	"github.com/lilendian0x00/xray-knife/v11/pkg/core/singbox"
	"github.com/lilendian0x00/xray-knife/v11/pkg/core/xray"
)

// ConnectionFingerprintVersion changes when stored identities need reindexing.
const ConnectionFingerprintVersion = "connection-v1"

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

	u, err := url.Parse(link)
	if err != nil {
		return "", errors.New("cannot fingerprint malformed share link")
	}
	var canonical []byte
	if u.Scheme == "vmess" {
		canonical, err = canonicalVMess(link, u)
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
		if u.Scheme == "hy2" {
			u.Scheme = "hysteria2"
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
	u.RawQuery = query.Encode()
	u.Fragment, u.RawFragment = "", ""
	u.ForceQuery = false
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
		var fields map[string]any
		dec := json.NewDecoder(bytes.NewReader(decoded))
		dec.UseNumber()
		if err := dec.Decode(&fields); err == nil && fields != nil {
			if err := dec.Decode(new(any)); err != io.EOF {
				return nil, errors.New("invalid VMess JSON")
			}
			delete(fields, "ps")
			// These protocol fields accept both numeric and string forms.
			for _, key := range []string{"port", "aid", "v"} {
				if value, ok := fields[key].(json.Number); ok {
					fields[key] = value.String()
				}
			}
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

func decodeIdentityBase64(s string) ([]byte, error) {
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if b, err := enc.DecodeString(s); err == nil {
			return b, nil
		}
	}
	return nil, errors.New("invalid base64")
}
