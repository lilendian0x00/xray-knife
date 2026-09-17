package mtproto

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// SecretType classifies an MTProto proxy secret by its wire behavior.
type SecretType uint8

const (
	// SecretSimple is a bare 16-byte key: obfuscated2 only.
	SecretSimple SecretType = iota + 1
	// SecretSecured is a 0xdd-prefixed key: obfuscated2 with padded framing.
	SecretSecured
	// SecretFakeTLS is a 0xee-prefixed key followed by a cloak domain.
	SecretFakeTLS
)

const (
	secretKeyLen      = 16
	secretTagSecured  = 0xdd
	secretTagFakeTLS  = 0xee
	maxCloakHostBytes = 253
)

func (t SecretType) String() string {
	switch t {
	case SecretSimple:
		return "simple"
	case SecretSecured:
		return "secured"
	case SecretFakeTLS:
		return "faketls"
	default:
		return "unknown"
	}
}

// Secret is a decoded MTProto proxy secret.
type Secret struct {
	Type      SecretType
	Key       [secretKeyLen]byte
	CloakHost string // SecretFakeTLS only
}

// Hex returns the canonical lowercase hex of the whole secret, type prefix and
// cloak host included.
func (s Secret) Hex() string {
	return hex.EncodeToString(s.bytes())
}

func (s Secret) bytes() []byte {
	switch s.Type {
	case SecretSecured:
		return append([]byte{secretTagSecured}, s.Key[:]...)
	case SecretFakeTLS:
		b := append([]byte{secretTagFakeTLS}, s.Key[:]...)
		return append(b, []byte(s.CloakHost)...)
	default:
		return append([]byte(nil), s.Key[:]...)
	}
}

// ParseSecret decodes the "secret" query parameter of a proxy link. It accepts
// hex (any case) and base64 (URL-safe or standard, padded or not).
func ParseSecret(raw string) (Secret, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return Secret{}, errors.New("invalid mtproto secret: empty")
	}
	b, err := decodeSecretBytes(raw)
	if err != nil {
		return Secret{}, err
	}
	var s Secret
	switch {
	case len(b) == secretKeyLen:
		s.Type = SecretSimple
		copy(s.Key[:], b)
	case len(b) == secretKeyLen+1 && b[0] == secretTagSecured:
		s.Type = SecretSecured
		copy(s.Key[:], b[1:])
	case len(b) > secretKeyLen+1 && b[0] == secretTagFakeTLS:
		s.Type = SecretFakeTLS
		copy(s.Key[:], b[1:1+secretKeyLen])
		s.CloakHost = string(b[1+secretKeyLen:])
		if !validHostname(s.CloakHost) {
			return Secret{}, fmt.Errorf("invalid mtproto secret: cloak host %q is not a hostname", s.CloakHost)
		}
	case len(b) < secretKeyLen:
		return Secret{}, fmt.Errorf("invalid mtproto secret: length %d, want 16 bytes or a dd/ee prefixed key", len(b))
	default:
		return Secret{}, fmt.Errorf("invalid mtproto secret: prefix 0x%02x does not match length %d", b[0], len(b))
	}
	return s, nil
}

func decodeSecretBytes(raw string) ([]byte, error) {
	if b, err := hex.DecodeString(raw); err == nil {
		return b, nil
	}
	for _, enc := range []*base64.Encoding{base64.RawURLEncoding, base64.URLEncoding, base64.RawStdEncoding, base64.StdEncoding} {
		if b, err := enc.DecodeString(raw); err == nil {
			return b, nil
		}
	}
	return nil, errors.New("invalid mtproto secret: neither hex nor base64")
}

// validHostname accepts RFC 1123 labels joined by dots. Strict on purpose: the
// cloak host goes out as TLS SNI.
func validHostname(h string) bool {
	if h == "" || len(h) > maxCloakHostBytes {
		return false
	}
	for _, label := range strings.Split(h, ".") {
		if label == "" || len(label) > 63 {
			return false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			isAlnum := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
			if !isAlnum && !(c == '-' && i != 0 && i != len(label)-1) {
				return false
			}
		}
	}
	return true
}
