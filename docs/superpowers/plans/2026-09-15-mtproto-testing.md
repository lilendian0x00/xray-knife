# MTProto Proxy Testing Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** `xray-knife http` tests Telegram MTProto proxy links (`tg://proxy?…`, `https://t.me/proxy?…`) with a native Go probe and reports them like any other protocol.

**Architecture:** A new package `pkg/core/mtproto` holds the link parser, a client for the obfuscated2 and fake-TLS handshakes ported from gotd/td (MIT), one `req_pq_multi` round trip, and a `Core` that the `AutomaticCore` routes MTProto links to. A new `protocol.Prober` interface lets the examiner bypass the HTTP client for protocols that cannot carry HTTP. Everything else (dedup, prescan, DB, web UI) works through the existing `protocol.Protocol` contract.

**Tech Stack:** Go 1.26, standard library crypto (`aes`, `cipher`, `hmac`, `sha256`), `github.com/refraction-networking/utls` (already a dependency) for the Chrome-fingerprint ClientHello, `pkg/netbind` for interface binding.

**Spec:** `docs/superpowers/specs/2026-09-15-mtproto-testing-design.md`

## Global Constraints

- No new Go modules. `go.mod` and `go.sum` must not change. Run `go mod tidy -diff` before the final commit; it must print nothing.
- Ported code comes from `github.com/gotd/td` v0.161.0 (MIT, copyright 2020 Aleksandr Razumov). Every ported file starts with a comment naming its upstream path, and `pkg/core/mtproto/LICENSE.gotd` carries the MIT text.
- Nothing from `github.com/gotd/td` is imported.
- Protocol identifier string is exactly `mtproto`. Secret type strings are exactly `simple`, `secured`, `faketls`.
- Framing is always padded intermediate (tag `dd dd dd dd`). Target DC is always `2`.
- Timeout status text is exactly `config delay is more than the maximum allowed delay` (matches the HTTP path).
- All new tests use in-memory I/O or loopback listeners; no public network is required. The only new external-network test is gated on `XRAY_KNIFE_MTPROTO_LINK`. Existing repository tests may have separate network requirements.
- Commit after every task with a Conventional Commits subject. Append attribution lines only when the implementation session explicitly provides them.
- Run `go vet ./pkg/core/... ./pkg/http/... ./pkg/proxy/... ./cmd/...` before each commit; it must be clean.

## File map

| Path | Responsibility |
|---|---|
| `pkg/core/protocol/interface.go` | add `MTProtoIdentifier`, `Prober`, `ProbeOptions`, `ProbeResult` |
| `pkg/core/mtproto/secret.go` | decode and classify a proxy secret |
| `pkg/core/mtproto/protocol.go` | `MTProto` link parser implementing `protocol.Protocol` |
| `pkg/core/mtproto/obfuscated2.go` | ported obfuscated2 init, key derivation, stream |
| `pkg/core/mtproto/faketls.go` | ported TLS record layer, ClientHello builder, ServerHello verifier |
| `pkg/core/mtproto/framing.go` | padded-intermediate frame read and write |
| `pkg/core/mtproto/reqpq.go` | `req_pq_multi` encoder, `resPQ` decoder, `TransportError` |
| `pkg/core/mtproto/prober.go` | `MTProto.Probe` orchestration and timing |
| `pkg/core/mtproto/mtproto.go` | `Core` implementing `core.Core`, `ErrNotProxyable`, `IsProxyLink` |
| `pkg/core/mtproto/testserver_test.go` | in-process fake MTProto proxy for tests |
| `pkg/core/mtproto/LICENSE.gotd` | MIT text and list of ported files |
| `pkg/core/factory.go` | route MTProto links to the new core |
| `pkg/core/identity.go` | fingerprint case for `*mtproto.MTProto` |
| `pkg/http/probe.go` | `Examiner.examineProbe` |
| `pkg/http/examiner.go` | one `Prober` branch in `ExamineConfig` |
| `cmd/http/http.go` | `Prober` branch in ping mode |
| `cmd/net/tcp.go` | use the automatic core |
| `pkg/proxy/chain.go` | reject or skip MTProto links before core-specific parsing |
| `pkg/core/xray/protocol.go`, `pkg/core/singbox/protocol.go` | return `mtproto.ErrNotProxyable` for MTProto links in explicit cores |
| `README.md`, `docs/zh_README.md` | mention MTProto |

---

### Task 1: Prober interface and identifier

**Files:**
- Modify: `pkg/core/protocol/interface.go`

**Interfaces:**
- Produces: `protocol.MTProtoIdentifier = "mtproto"`, `protocol.Prober`, `protocol.ProbeOptions{Timeout time.Duration; BindInterface string}`, `protocol.ProbeResult{ConnectTime, TTFB, Delay time.Duration; Detail string}`.

- [ ] **Step 1: Add the identifier and interface**

Edit `pkg/core/protocol/interface.go`. Add `"context"` and `"time"` imports, add `MTProtoIdentifier` to the identifier const block, and append the new types after `Protocol`:

```go
package protocol

import (
	"context"
	"time"
)

const (
	VmessIdentifier       = "vmess"
	VlessIdentifier       = "vless"
	TrojanIdentifier      = "trojan"
	ShadowsocksIdentifier = "ss"
	WireguardIdentifier   = "wireguard"
	SocksIdentifier       = "socks"
	Hysteria2Identifier   = "hysteria2"
	TunIdentifier         = "tun"
	MTProtoIdentifier     = "mtproto"
)
```

Append at the end of the file:

```go
// Prober is implemented by protocols that cannot carry HTTP and instead verify
// reachability with a protocol-native round trip. The examiner uses it in place
// of Core.MakeHttpClient.
type Prober interface {
	Probe(ctx context.Context, opts ProbeOptions) (ProbeResult, error)
}

// ProbeOptions controls a single Probe call.
type ProbeOptions struct {
	// Timeout bounds the whole probe (dial, handshake and round trip).
	Timeout time.Duration
	// BindInterface pins the dial to an OS interface; empty disables binding.
	BindInterface string
}

// ProbeResult reports timings measured from the start of the probe.
type ProbeResult struct {
	ConnectTime time.Duration
	TTFB        time.Duration
	Delay       time.Duration
	// Detail is a short human-readable note such as "faketls, dc2 resPQ ok".
	Detail string
}
```

- [ ] **Step 2: Build**

Run: `go build ./...`
Expected: `Go build: Success` (or no output).

- [ ] **Step 3: Commit**

```bash
git add pkg/core/protocol/interface.go
git commit -m "protocol: add Prober interface and mtproto identifier"
```

---

### Task 2: Secret parsing

**Files:**
- Create: `pkg/core/mtproto/secret.go`
- Test: `pkg/core/mtproto/secret_test.go`

**Interfaces:**
- Produces: `type SecretType uint8` with `SecretSimple`, `SecretSecured`, `SecretFakeTLS` and `String()`; `type Secret struct{Type SecretType; Key [16]byte; CloakHost string}` with `Hex() string`; `func ParseSecret(raw string) (Secret, error)`.

- [ ] **Step 1: Write the failing tests**

Create `pkg/core/mtproto/secret_test.go`:

```go
package mtproto

import (
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"
)

const testKeyHex = "00112233445566778899aabbccddeeff"

func TestParseSecretTypes(t *testing.T) {
	cases := []struct {
		name      string
		raw       string
		wantType  SecretType
		wantHost  string
		wantHex   string
		wantError string
	}{
		{name: "simple hex", raw: testKeyHex, wantType: SecretSimple, wantHex: testKeyHex},
		{name: "simple uppercase hex", raw: strings.ToUpper(testKeyHex), wantType: SecretSimple, wantHex: testKeyHex},
		{name: "secured hex", raw: "dd" + testKeyHex, wantType: SecretSecured, wantHex: "dd" + testKeyHex},
		{name: "faketls hex", raw: "ee" + testKeyHex + hex.EncodeToString([]byte("www.google.com")), wantType: SecretFakeTLS, wantHost: "www.google.com", wantHex: "ee" + testKeyHex + hex.EncodeToString([]byte("www.google.com"))},
		{name: "faketls base64url", raw: base64.RawURLEncoding.EncodeToString(mustHex(t, "ee"+testKeyHex+hex.EncodeToString([]byte("example.org")))), wantType: SecretFakeTLS, wantHost: "example.org", wantHex: "ee" + testKeyHex + hex.EncodeToString([]byte("example.org"))},
		{name: "secured base64 std padded", raw: base64.StdEncoding.EncodeToString(mustHex(t, "dd"+testKeyHex)), wantType: SecretSecured, wantHex: "dd" + testKeyHex},
		{name: "empty", raw: "", wantError: "empty"},
		{name: "not hex not base64", raw: "zz!!", wantError: "neither hex nor base64"},
		{name: "wrong length", raw: "0011", wantError: "length"},
		{name: "unknown prefix 17 bytes", raw: "aa" + testKeyHex, wantError: "prefix"},
		{name: "faketls empty host", raw: "ee" + testKeyHex, wantError: "prefix"},
		{name: "faketls bad host", raw: "ee" + testKeyHex + hex.EncodeToString([]byte("bad host!")), wantError: "cloak host"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseSecret(tc.raw)
			if tc.wantError != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantError) {
					t.Fatalf("err = %v, want containing %q", err, tc.wantError)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got.Type != tc.wantType {
				t.Errorf("type = %v, want %v", got.Type, tc.wantType)
			}
			if got.CloakHost != tc.wantHost {
				t.Errorf("host = %q, want %q", got.CloakHost, tc.wantHost)
			}
			if hex.EncodeToString(got.Key[:]) != testKeyHex {
				t.Errorf("key = %x, want %s", got.Key, testKeyHex)
			}
			if got.Hex() != tc.wantHex {
				t.Errorf("Hex() = %q, want %q", got.Hex(), tc.wantHex)
			}
		})
	}
}

func TestSecretTypeString(t *testing.T) {
	for typ, want := range map[SecretType]string{SecretSimple: "simple", SecretSecured: "secured", SecretFakeTLS: "faketls", SecretType(0): "unknown"} {
		if got := typ.String(); got != want {
			t.Errorf("%d.String() = %q, want %q", typ, got, want)
		}
	}
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./pkg/core/mtproto/ -run 'TestParseSecret|TestSecretType' -v`
Expected: build failure, `undefined: ParseSecret`.

- [ ] **Step 3: Implement**

Create `pkg/core/mtproto/secret.go`:

```go
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

// Hex returns the canonical lowercase hex encoding of the full secret,
// including its type prefix and cloak host, suitable for share links and
// connection fingerprints.
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
	case len(b) < secretKeyLen || (len(b) > secretKeyLen && b[0] != secretTagSecured && b[0] != secretTagFakeTLS):
		if len(b) < secretKeyLen {
			return Secret{}, fmt.Errorf("invalid mtproto secret: length %d, want 16 bytes or a dd/ee prefixed key", len(b))
		}
		return Secret{}, fmt.Errorf("invalid mtproto secret: unknown prefix 0x%02x", b[0])
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

// validHostname accepts RFC 1123 host labels joined by dots. It is
// deliberately strict: the cloak host is sent as TLS SNI.
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
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./pkg/core/mtproto/ -run 'TestParseSecret|TestSecretType' -v`
Expected: all subtests `PASS`. If the `wrong length` case fails on message text, the error for a 2-byte input must contain the word `length`; the `unknown prefix 17 bytes` and `faketls empty host` cases (17 bytes with prefix `aa` or `ee`) must contain `prefix`.

- [ ] **Step 5: Commit**

```bash
git add pkg/core/mtproto/secret.go pkg/core/mtproto/secret_test.go
git commit -m "mtproto: parse proxy secrets (simple, secured, faketls)"
```

---

### Task 3: Link parser implementing protocol.Protocol

**Files:**
- Create: `pkg/core/mtproto/protocol.go`
- Test: `pkg/core/mtproto/protocol_test.go`

**Interfaces:**
- Consumes: `ParseSecret`, `Secret.Hex`, `SecretType.String` (Task 2); `protocol.GeneralConfig`, `protocol.MTProtoIdentifier` (Task 1).
- Produces: `type MTProto struct{OrigLink, Remark, Address, Port, RawSecret string; Secret Secret}`; `func NewMTProto(link string) *MTProto`; methods `Name`, `Parse`, `DetailsStr`, `GetLink`, `ConvertToGeneralConfig`; `func IsProxyLink(link string) bool`.

- [ ] **Step 1: Write the failing tests**

Create `pkg/core/mtproto/protocol_test.go`:

```go
package mtproto

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/lilendian0x00/xray-knife/v11/pkg/core/protocol"
)

func TestIsProxyLink(t *testing.T) {
	yes := []string{
		"tg://proxy?server=1.2.3.4&port=443&secret=" + testKeyHex,
		"https://t.me/proxy?server=1.2.3.4&port=443&secret=" + testKeyHex,
		"http://t.me/proxy?server=1.2.3.4&port=443&secret=" + testKeyHex,
		"https://telegram.me/proxy?server=a&port=1&secret=b",
		"https://telegram.dog/proxy?server=a&port=1&secret=b",
		"  tg://proxy?server=a&port=1&secret=b  ",
	}
	no := []string{
		"https://t.me/joinchat/abc",
		"tg://evil/proxy?server=a&port=1&secret=b",
		"tg://proxy/extra?server=a&port=1&secret=b",
		"https://user@t.me/proxy?server=a&port=1&secret=b",
		"https://example.com/proxy?server=a&port=1&secret=b",
		"vless://uuid@host:443?type=tcp",
		"https://t.me/sub-provider/list.txt",
		"",
		"not a link",
	}
	for _, l := range yes {
		if !IsProxyLink(l) {
			t.Errorf("IsProxyLink(%q) = false, want true", l)
		}
	}
	for _, l := range no {
		if IsProxyLink(l) {
			t.Errorf("IsProxyLink(%q) = true, want false", l)
		}
	}
}

func TestMTProtoParse(t *testing.T) {
	fakeHex := "ee" + testKeyHex + hex.EncodeToString([]byte("www.google.com"))
	cases := []struct {
		name     string
		link     string
		wantAddr string
		wantPort string
		wantType SecretType
		wantRem  string
		wantErr  string
	}{
		{name: "tg simple", link: "tg://proxy?server=1.2.3.4&port=443&secret=" + testKeyHex, wantAddr: "1.2.3.4", wantPort: "443", wantType: SecretSimple},
		{name: "t.me faketls", link: "https://t.me/proxy?server=proxy.example.com&port=8443&secret=" + fakeHex, wantAddr: "proxy.example.com", wantPort: "8443", wantType: SecretFakeTLS},
		{name: "fragment remark", link: "tg://proxy?server=1.2.3.4&port=443&secret=dd" + testKeyHex + "#My%20Proxy", wantAddr: "1.2.3.4", wantPort: "443", wantType: SecretSecured, wantRem: "My Proxy"},
		{name: "ipv6 server", link: "tg://proxy?server=2001:db8::1&port=443&secret=" + testKeyHex, wantAddr: "2001:db8::1", wantPort: "443", wantType: SecretSimple},
		{name: "decimal port normalization", link: "tg://proxy?server=a&port=00443&secret=" + testKeyHex, wantAddr: "a", wantPort: "443", wantType: SecretSimple},
		{name: "malformed query", link: "tg://proxy?server=a&port=443&secret=" + testKeyHex + "&extra=%zz", wantErr: "query"},
		{name: "duplicate server", link: "tg://proxy?server=a&server=b&port=443&secret=" + testKeyHex, wantErr: "duplicate"},
		{name: "missing server", link: "tg://proxy?port=443&secret=" + testKeyHex, wantErr: "server"},
		{name: "missing port", link: "tg://proxy?server=a&secret=" + testKeyHex, wantErr: "port"},
		{name: "bad port", link: "tg://proxy?server=a&port=99999&secret=" + testKeyHex, wantErr: "port"},
		{name: "missing secret", link: "tg://proxy?server=a&port=443", wantErr: "secret"},
		{name: "bad secret", link: "tg://proxy?server=a&port=443&secret=zz", wantErr: "secret"},
		{name: "not a proxy link", link: "vless://uuid@host:443", wantErr: "not an mtproto proxy link"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := NewMTProto(tc.link)
			err := m.Parse()
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want containing %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if m.Address != tc.wantAddr || m.Port != tc.wantPort || m.Secret.Type != tc.wantType || m.Remark != tc.wantRem {
				t.Errorf("got %q:%q %v %q", m.Address, m.Port, m.Secret.Type, m.Remark)
			}
		})
	}
}

func TestMTProtoGetLinkCanonical(t *testing.T) {
	m := NewMTProto("https://t.me/proxy?secret=" + strings.ToUpper(testKeyHex) + "&port=443&server=Proxy.Example.com")
	if err := m.Parse(); err != nil {
		t.Fatal(err)
	}
	want := "tg://proxy?server=Proxy.Example.com&port=443&secret=" + testKeyHex
	if got := m.GetLink(); got != want {
		t.Errorf("GetLink() = %q, want %q", got, want)
	}
	m2 := NewMTProto("tg://proxy?server=a.b&port=1&secret=" + testKeyHex + "#name")
	if err := m2.Parse(); err != nil {
		t.Fatal(err)
	}
	if got := m2.GetLink(); got != "tg://proxy?server=a.b&port=1&secret="+testKeyHex+"#name" {
		t.Errorf("GetLink() with remark = %q", got)
	}
}

func TestMTProtoGeneralConfig(t *testing.T) {
	fakeHex := "ee" + testKeyHex + hex.EncodeToString([]byte("www.google.com"))
	link := "tg://proxy?server=1.2.3.4&port=443&secret=" + fakeHex + "#r"
	m := NewMTProto(link)
	if err := m.Parse(); err != nil {
		t.Fatal(err)
	}
	g := m.ConvertToGeneralConfig()
	want := protocol.GeneralConfig{
		Protocol: protocol.MTProtoIdentifier,
		Address:  "1.2.3.4",
		Port:     "443",
		ID:       fakeHex,
		TLS:      "faketls",
		SNI:      "www.google.com",
		Network:  "tcp",
		Type:     "tcp",
		Remark:   "r",
		OrigLink: link,
	}
	if g != want {
		t.Errorf("GeneralConfig = %+v\nwant %+v", g, want)
	}
	plain := NewMTProto("tg://proxy?server=1.2.3.4&port=443&secret=" + testKeyHex)
	if err := plain.Parse(); err != nil {
		t.Fatal(err)
	}
	if g := plain.ConvertToGeneralConfig(); g.TLS != "none" || g.SNI != "" {
		t.Errorf("plain GeneralConfig TLS=%q SNI=%q, want none/empty", g.TLS, g.SNI)
	}
	if !strings.Contains(m.DetailsStr(), "www.google.com") || !strings.Contains(m.DetailsStr(), "faketls") {
		t.Errorf("DetailsStr missing cloak host or type:\n%s", m.DetailsStr())
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./pkg/core/mtproto/ -run 'TestIsProxyLink|TestMTProto' -v`
Expected: build failure, `undefined: IsProxyLink` / `undefined: NewMTProto`.

- [ ] **Step 3: Implement**

Create `pkg/core/mtproto/protocol.go`:

```go
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
	// Build the query by hand so the parameter order is stable and readable.
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
```

Add parser round trips for URL-escaped standard base64 secrets containing `+`, `/` and `=` (construct with `url.Values`, since an unescaped `+` means a space in a URL query), and remarks containing spaces, `#`, `%`, `/`, `+` and non-ASCII text.

Note on `GetLink`: `url.QueryEscape` turns `:` into `%3A` for IPv6 servers, which the `Parse` round trip decodes back. The canonical test uses a hostname so the expected string is literal.

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./pkg/core/mtproto/ -v`
Expected: all `PASS`. `TestMTProtoGetLinkCanonical` expects the remark escaped with `url.PathEscape` (`#name` stays `#name`).

- [ ] **Step 5: Commit**

```bash
git add pkg/core/mtproto/protocol.go pkg/core/mtproto/protocol_test.go
git commit -m "mtproto: parse tg:// and t.me proxy share links"
```

---

### Task 4: obfuscated2 stream (ported)

**Files:**
- Create: `pkg/core/mtproto/obfuscated2.go`
- Create: `pkg/core/mtproto/LICENSE.gotd`
- Test: `pkg/core/mtproto/obfuscated2_test.go`

**Interfaces:**
- Produces: `var paddedIntermediateTag = [4]byte{0xdd,0xdd,0xdd,0xdd}`; `const obfsInitLen = 64`; `func generateInit(rnd io.Reader) ([64]byte, error)`; `func clientStreams(init [64]byte, key [16]byte) (encrypt, decrypt cipher.Stream, err error)`; `type obfuscated2 struct{conn io.ReadWriter; header []byte; encrypt, decrypt cipher.Stream}` with `handshake() error`, `Read`, `Write`; `func newObfuscated2(rnd io.Reader, conn io.ReadWriter, key [16]byte, tag [4]byte, dc int) (*obfuscated2, error)`.
- Test-only helper (lives in the test file, reused by Task 7): `func serverStreams(init [64]byte, key [16]byte) (encrypt, decrypt cipher.Stream, err error)`, `type rwPair struct{r, w *bytes.Buffer}`.

Upstream reference: `github.com/gotd/td@v0.161.0/mtproxy/obfuscated2/{keys.go,keys_util.go,obfuscated2.go}`. The essential detail: the encrypt stream is run over the whole 64-byte init block (not just bytes 56..64) so that the client and the proxy agree on the CTR position afterwards.

- [ ] **Step 1: Add the license file**

Resolve the upstream `v0.161.0` tag to its commit when porting, and record that commit alongside the version in the license provenance header. Do not add gotd to `go.mod`.

Create `pkg/core/mtproto/LICENSE.gotd`:

```
The files obfuscated2.go and faketls.go in this directory, and the padded
intermediate framing in framing.go, are ported from github.com/gotd/td
v0.161.0 (packages mtproxy, mtproxy/obfuscated2, mtproxy/faketls and
proto/codec) and adapted to the standard library.

MIT License

Copyright (c) 2020 Aleksandr Razumov

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

- [ ] **Step 2: Write the failing tests**

Create `pkg/core/mtproto/obfuscated2_test.go`:

```go
package mtproto

import (
	"bytes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"testing"
)

// rwPair is a one-directional-per-buffer io.ReadWriter for wiring a client
// to a fake server in-process: reads come from r, writes go to w.
type rwPair struct{ r, w *bytes.Buffer }

func (p rwPair) Read(b []byte) (int, error)  { return p.r.Read(b) }
func (p rwPair) Write(b []byte) (int, error) { return p.w.Write(b) }

// serverStreams mirrors clientStreams for the proxy side: the server decrypts
// with the client's encrypt stream and encrypts with the client's decrypt stream.
func serverStreams(init [obfsInitLen]byte, key [16]byte) (encrypt, decrypt cipher.Stream, err error) {
	clientEnc, clientDec, err := clientStreams(init, key)
	return clientDec, clientEnc, err
}

func testKey(t *testing.T) [16]byte {
	t.Helper()
	var k [16]byte
	copy(k[:], mustHex(t, testKeyHex))
	return k
}

func TestGenerateInitSkipsForbiddenPrefixes(t *testing.T) {
	block := func(prefix ...byte) []byte {
		b := bytes.Repeat([]byte{0x01}, obfsInitLen)
		copy(b, prefix)
		return b
	}
	var feed []byte
	feed = append(feed, block(0xef)...)                   // abridged marker
	feed = append(feed, block('H', 'E', 'A', 'D')...)     // HTTP verb
	feed = append(feed, block('P', 'O', 'S', 'T')...)     // HTTP verb
	feed = append(feed, block(0xdd, 0xdd, 0xdd, 0xdd)...) // padded intermediate tag
	feed = append(feed, block(0xee, 0xee, 0xee, 0xee)...) // intermediate tag
	feed = append(feed, block(0x02, 0x02, 0x02, 0x02, 0, 0, 0, 0)...) // zero second word
	good := block(0x02, 0x02, 0x02, 0x02, 0x03)
	feed = append(feed, good...)

	init, err := generateInit(bytes.NewReader(feed))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(init[:], good) {
		t.Fatalf("generateInit returned a forbidden block:\n% x", init[:8])
	}
}

func TestObfuscated2RoundTrip(t *testing.T) {
	key := testKey(t)
	var c2s, s2c bytes.Buffer
	client, err := newObfuscated2(rand.Reader, rwPair{r: &s2c, w: &c2s}, key, paddedIntermediateTag, 2)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.handshake(); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Write([]byte("hello, proxy")); err != nil {
		t.Fatal(err)
	}

	// Server side: the first 64 bytes are the header; bytes 0..56 are plaintext.
	var init [obfsInitLen]byte
	copy(init[:], c2s.Next(obfsInitLen))
	serverEnc, serverDec, err := serverStreams(init, key)
	if err != nil {
		t.Fatal(err)
	}
	var plain [obfsInitLen]byte
	serverDec.XORKeyStream(plain[:], init[:])
	// Only bytes 56..64 were encrypted on the wire. Decrypting the clear
	// prefix produces junk; consume it solely to advance CTR by 64 bytes.
	// Check the clear prefix against the original seed in the vector test below.
	if [4]byte(plain[56:60]) != paddedIntermediateTag {
		t.Errorf("tag = % x, want dd dd dd dd", plain[56:60])
	}
	if dc := binary.LittleEndian.Uint16(plain[60:62]); dc != 2 {
		t.Errorf("dc = %d, want 2", dc)
	}
	payload := c2s.Bytes()
	serverDec.XORKeyStream(payload, payload)
	if string(payload) != "hello, proxy" {
		t.Errorf("server decrypted %q", payload)
	}

	// Server -> client.
	reply := []byte("hello, client")
	enc := make([]byte, len(reply))
	serverEnc.XORKeyStream(enc, reply)
	s2c.Write(enc)
	got := make([]byte, len(reply))
	if _, err := client.Read(got); err != nil {
		t.Fatal(err)
	}
	if string(got) != "hello, client" {
		t.Errorf("client decrypted %q", got)
	}
}

func TestObfuscated2WrongKeyProducesWrongTag(t *testing.T) {
	var wire bytes.Buffer
	client, err := newObfuscated2(rand.Reader, rwPair{r: new(bytes.Buffer), w: &wire}, testKey(t), paddedIntermediateTag, 2)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.handshake(); err != nil {
		t.Fatal(err)
	}
	var init [obfsInitLen]byte
	copy(init[:], wire.Bytes())
	_, serverDec, err := serverStreams(init, [16]byte{9, 9, 9})
	if err != nil {
		t.Fatal(err)
	}
	var plain [obfsInitLen]byte
	serverDec.XORKeyStream(plain[:], init[:])
	if [4]byte(plain[56:60]) == paddedIntermediateTag {
		t.Fatal("a wrong key must not reveal the transport tag")
	}
}
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `go test ./pkg/core/mtproto/ -run 'TestGenerateInit|TestObfuscated2' -v`
Expected: build failure, `undefined: generateInit` and friends.

- [ ] **Step 4: Implement**

Create `pkg/core/mtproto/obfuscated2.go`:

```go
// Ported from github.com/gotd/td v0.161.0, mtproxy/obfuscated2 (keys.go,
// keys_util.go, obfuscated2.go). MIT License, Copyright (c) 2020 Aleksandr
// Razumov. See LICENSE.gotd in this directory.

package mtproto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
)

// paddedIntermediateTag is the MTProto transport tag for padded intermediate
// framing. It is written into the obfuscated2 header so the proxy knows how to
// frame the stream.
var paddedIntermediateTag = [4]byte{0xdd, 0xdd, 0xdd, 0xdd}

const obfsInitLen = 64

// obfuscated2 is the AES-CTR obfuscated transport used between a Telegram
// client and an MTProto proxy. See
// https://core.telegram.org/mtproto/mtproto-transports#transport-obfuscation
type obfuscated2 struct {
	conn    io.ReadWriter
	header  []byte
	encrypt cipher.Stream
	decrypt cipher.Stream
}

// newObfuscated2 derives the client streams and the 64-byte header for a
// session to the given DC. Call handshake to send the header before Write.
func newObfuscated2(rnd io.Reader, conn io.ReadWriter, key [16]byte, tag [4]byte, dc int) (*obfuscated2, error) {
	init, err := generateInit(rnd)
	if err != nil {
		return nil, fmt.Errorf("obfuscated2: generate init: %w", err)
	}
	copy(init[56:60], tag[:])
	binary.LittleEndian.PutUint16(init[60:62], uint16(dc))

	encrypt, decrypt, err := clientStreams(init, key)
	if err != nil {
		return nil, err
	}
	// Encrypt the whole block, not just bytes 56..64: the proxy decrypts all
	// 64 bytes too, and both sides must advance the CTR counter equally.
	var encrypted [obfsInitLen]byte
	encrypt.XORKeyStream(encrypted[:], init[:])
	header := make([]byte, obfsInitLen)
	copy(header, init[:56])
	copy(header[56:], encrypted[56:])
	return &obfuscated2{conn: conn, header: header, encrypt: encrypt, decrypt: decrypt}, nil
}

// handshake sends the header. Nothing comes back: the proxy starts relaying.
func (o *obfuscated2) handshake() error {
	n, err := o.conn.Write(o.header)
	if err == nil && n != len(o.header) {
		err = io.ErrShortWrite
	}
	if err != nil {
		return fmt.Errorf("obfuscated2: write header: %w", err)
	}
	return nil
}

func (o *obfuscated2) Write(p []byte) (int, error) {
	buf := make([]byte, len(p))
	o.encrypt.XORKeyStream(buf, p)
	n, err := o.conn.Write(buf)
	if err == nil && n != len(buf) {
		err = io.ErrShortWrite
	}
	return n, err
}

func (o *obfuscated2) Read(p []byte) (int, error) {
	n, err := o.conn.Read(p)
	if n > 0 {
		o.decrypt.XORKeyStream(p[:n], p[:n])
	}
	return n, err
}

// clientStreams derives the client's encrypt and decrypt AES-CTR streams.
// Encrypt key material is init[8:40] (key) and init[40:56] (IV); decrypt
// material is the same 48 bytes reversed. With a proxy secret, both keys are
// SHA-256(material || secret).
func clientStreams(init [obfsInitLen]byte, key [16]byte) (encrypt, decrypt cipher.Stream, err error) {
	encKey := sha256.Sum256(append(append([]byte{}, init[8:40]...), key[:]...))
	encIV := init[40:56]

	var rev [48]byte
	for i := 0; i < 48; i++ {
		rev[i] = init[55-i]
	}
	decKey := sha256.Sum256(append(append([]byte{}, rev[:32]...), key[:]...))
	decIV := rev[32:48]

	if encrypt, err = newCTR(encKey[:], encIV); err != nil {
		return nil, nil, err
	}
	if decrypt, err = newCTR(decKey[:], decIV); err != nil {
		return nil, nil, err
	}
	return encrypt, decrypt, nil
}

func newCTR(key, iv []byte) (cipher.Stream, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("obfuscated2: aes: %w", err)
	}
	return cipher.NewCTR(block, iv), nil
}

// generateInit draws 64 random bytes, retrying while the prefix would look
// like another protocol (HTTP verbs, abridged or intermediate markers) or the
// second word is zero. Mirrors the official clients.
func generateInit(rnd io.Reader) ([obfsInitLen]byte, error) {
	var init [obfsInitLen]byte
	for {
		if _, err := io.ReadFull(rnd, init[:]); err != nil {
			return init, err
		}
		if init[0] == 0xef {
			continue
		}
		switch binary.LittleEndian.Uint32(init[0:4]) {
		case 0x44414548, // HEAD
			0x54534f50, // POST
			0x20544547, // GET
			0x4954504f, // OPTI
			0x02010316, // TLS-looking prefix
			0xdddddddd, // padded intermediate
			0xeeeeeeee: // intermediate
			continue
		}
		if binary.LittleEndian.Uint32(init[4:8]) == 0 {
			continue
		}
		return init, nil
	}
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `go test ./pkg/core/mtproto/ -run 'TestGenerateInit|TestObfuscated2' -v`
Expected: all obfuscation tests `PASS`.

Before committing, add `TestObfuscated2HeaderVector`: supply a fixed 64-byte seed and secret; compare the exact header and first encrypted payload with a checked-in vector independently generated from the Telegram transport algorithm or pinned upstream fixture. Assert wire bytes 0..56 equal the seed. Record vector provenance. The mirrored `serverStreams` helper alone cannot detect a shared key-derivation error.

- [ ] **Step 6: Commit**

```bash
git add pkg/core/mtproto/obfuscated2.go pkg/core/mtproto/obfuscated2_test.go pkg/core/mtproto/LICENSE.gotd
git commit -m "mtproto: port obfuscated2 client stream from gotd"
```

---

### Task 5: Fake TLS handshake and record layer (ported)

**Files:**
- Create: `pkg/core/mtproto/faketls.go`
- Test: `pkg/core/mtproto/faketls_test.go`

**Interfaces:**
- Produces: `type recordType byte` with `recordChangeCipherSpec=0x14`, `recordAlert=0x15`, `recordHandshake=0x16`, `recordApplication=0x17`; `var tlsVersion10, tlsVersion12 [2]byte`; `const helloRandomOffset = 11`, `helloRandomLen = 32`; `type tlsRecord struct{Type recordType; Version [2]byte; Data []byte}`; `func readRecord(io.Reader) (tlsRecord, error)`; `func writeRecord(io.Writer, tlsRecord) error`; `func buildClientHello(rnd io.Reader, now time.Time, host string, key []byte) (record []byte, clientRandom [32]byte, err error)`; `func verifyServerHello(r io.Reader, clientRandom [32]byte, key []byte) error`; `type fakeTLS struct{rnd io.Reader; now func() time.Time; conn io.ReadWriter; sentCCS bool; readBuf bytes.Buffer}`; `func newFakeTLS(rnd, now, conn) *fakeTLS`; methods `handshake(host string, key []byte) error`, `Read`, `Write`.
- Test-only helper (reused by Task 7): `func buildServerHelloFlight(rnd io.Reader, clientRandom [32]byte, key []byte) []byte`.

Upstream reference: `github.com/gotd/td@v0.161.0/mtproxy/faketls/{tls.go,record.go,client_hello.go,server_hello.go,faketls.go}`. The ClientHello is generated by `utls` with the Chrome fingerprint so the flight looks like a browser; only the 32-byte random is overwritten.

- [ ] **Step 1: Write the failing tests**

Create `pkg/core/mtproto/faketls_test.go`:

```go
package mtproto

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"io"
	"strings"
	"testing"
	"time"
)

// buildServerHelloFlight fakes what a proxy answers to a valid ClientHello:
// ServerHello, ChangeCipherSpec and one application-data record, with the
// server random carrying HMAC-SHA256(key, clientRandom || flight-with-zero-random).
func buildServerHelloFlight(rnd io.Reader, clientRandom [helloRandomLen]byte, key []byte) []byte {
	hello := []byte{0x02, 0x00, 0x00, 38, 0x03, 0x03} // ServerHello, body length 38, TLS 1.2
	hello = append(hello, make([]byte, helloRandomLen)...)
	hello = append(hello, 0x00, 0x13, 0x01, 0x00) // no session id, TLS_AES_128_GCM_SHA256, no compression
	cert := make([]byte, 64)
	_, _ = io.ReadFull(rnd, cert)

	var flight bytes.Buffer
	_ = writeRecord(&flight, tlsRecord{Type: recordHandshake, Version: tlsVersion12, Data: hello})
	_ = writeRecord(&flight, tlsRecord{Type: recordChangeCipherSpec, Version: tlsVersion12, Data: []byte{0x01}})
	_ = writeRecord(&flight, tlsRecord{Type: recordApplication, Version: tlsVersion12, Data: cert})

	packet := flight.Bytes()
	mac := hmac.New(sha256.New, key)
	mac.Write(clientRandom[:])
	mac.Write(packet)
	copy(packet[helloRandomOffset:helloRandomOffset+helloRandomLen], mac.Sum(nil))
	return packet
}

func TestBuildClientHelloDigest(t *testing.T) {
	key := mustHex(t, testKeyHex)
	now := time.Unix(1_800_000_000, 0)
	record, clientRandom, err := buildClientHello(rand.Reader, now, "www.google.com", key)
	if err != nil {
		t.Fatal(err)
	}
	if record[0] != byte(recordHandshake) || record[1] != 0x03 || record[2] != 0x01 {
		t.Errorf("record header = % x, want 16 03 01", record[:3])
	}
	if int(binary.BigEndian.Uint16(record[3:5])) != len(record)-5 {
		t.Errorf("record length field %d != %d", binary.BigEndian.Uint16(record[3:5]), len(record)-5)
	}
	if !bytes.Contains(record, []byte("www.google.com")) {
		t.Error("SNI missing from ClientHello")
	}
	if !bytes.Equal(record[helloRandomOffset:helloRandomOffset+helloRandomLen], clientRandom[:]) {
		t.Error("returned clientRandom does not match the record")
	}

	zeroed := append([]byte(nil), record...)
	for i := helloRandomOffset; i < helloRandomOffset+helloRandomLen; i++ {
		zeroed[i] = 0
	}
	mac := hmac.New(sha256.New, key)
	mac.Write(zeroed)
	digest := mac.Sum(nil)
	if !bytes.Equal(clientRandom[:28], digest[:28]) {
		t.Error("first 28 bytes of the random must be the HMAC digest")
	}
	got := binary.LittleEndian.Uint32(clientRandom[28:]) ^ uint32(now.Unix())
	if got != binary.LittleEndian.Uint32(digest[28:]) {
		t.Error("last 4 bytes must be digest XOR unix time")
	}
}

func TestVerifyServerHello(t *testing.T) {
	key := mustHex(t, testKeyHex)
	var clientRandom [helloRandomLen]byte
	_, _ = rand.Read(clientRandom[:])

	good := buildServerHelloFlight(rand.Reader, clientRandom, key)
	if err := verifyServerHello(bytes.NewReader(good), clientRandom, key); err != nil {
		t.Fatalf("valid flight rejected: %v", err)
	}

	bad := append([]byte(nil), good...)
	bad[helloRandomOffset+3] ^= 0xff
	err := verifyServerHello(bytes.NewReader(bad), clientRandom, key)
	if err == nil || !strings.Contains(err.Error(), "server digest mismatch") {
		t.Errorf("tampered digest: err = %v", err)
	}

	otherKey := bytes.Repeat([]byte{7}, 16)
	err = verifyServerHello(bytes.NewReader(good), clientRandom, otherKey)
	if err == nil || !strings.Contains(err.Error(), "server digest mismatch") {
		t.Errorf("wrong key: err = %v", err)
	}

	var appFirst bytes.Buffer
	_ = writeRecord(&appFirst, tlsRecord{Type: recordApplication, Version: tlsVersion12, Data: []byte{1, 2, 3}})
	err = verifyServerHello(&appFirst, clientRandom, key)
	if err == nil || !strings.Contains(err.Error(), "unexpected record type") {
		t.Errorf("application record first: err = %v", err)
	}

	if err := verifyServerHello(bytes.NewReader(good[:20]), clientRandom, key); err == nil {
		t.Error("truncated flight accepted")
	}
}

func TestFakeTLSRecordsRoundTrip(t *testing.T) {
	var c2s, s2c bytes.Buffer
	client := newFakeTLS(rand.Reader, time.Now, rwPair{r: &s2c, w: &c2s})

	if _, err := client.Write([]byte("abc")); err != nil {
		t.Fatal(err)
	}
	first, err := readRecord(&c2s)
	if err != nil || first.Type != recordChangeCipherSpec {
		t.Fatalf("first record = %+v, %v; want ChangeCipherSpec", first, err)
	}
	second, err := readRecord(&c2s)
	if err != nil || second.Type != recordApplication || string(second.Data) != "abc" {
		t.Fatalf("second record = %+v, %v; want application 'abc'", second, err)
	}
	if _, err := client.Write([]byte("def")); err != nil {
		t.Fatal(err)
	}
	third, err := readRecord(&c2s)
	if err != nil || third.Type != recordApplication {
		t.Fatalf("ChangeCipherSpec must be sent only once; got %+v", third)
	}

	_ = writeRecord(&s2c, tlsRecord{Type: recordChangeCipherSpec, Version: tlsVersion12, Data: []byte{1}})
	_ = writeRecord(&s2c, tlsRecord{Type: recordApplication, Version: tlsVersion12, Data: []byte("xyz")})
	got := make([]byte, 3)
	if _, err := io.ReadFull(client, got); err != nil || string(got) != "xyz" {
		t.Fatalf("client read %q, %v", got, err)
	}

	_ = writeRecord(&s2c, tlsRecord{Type: recordAlert, Version: tlsVersion12, Data: []byte{2, 40}})
	if _, err := client.Read(got); err == nil || !strings.Contains(err.Error(), "unexpected record type") {
		t.Errorf("alert record: err = %v", err)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./pkg/core/mtproto/ -run 'TestBuildClientHello|TestVerifyServerHello|TestFakeTLS' -v`
Expected: build failure, `undefined: buildClientHello` and friends.

- [ ] **Step 3: Implement**

Create `pkg/core/mtproto/faketls.go`:

```go
// Ported from github.com/gotd/td v0.161.0, mtproxy/faketls (tls.go, record.go,
// client_hello.go, server_hello.go, faketls.go). MIT License, Copyright (c)
// 2020 Aleksandr Razumov. See LICENSE.gotd in this directory.

package mtproto

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"time"

	utls "github.com/refraction-networking/utls"
)

type recordType byte

const (
	recordChangeCipherSpec recordType = 0x14
	recordAlert            recordType = 0x15
	recordHandshake        recordType = 0x16
	recordApplication      recordType = 0x17
)

var (
	tlsVersion10 = [2]byte{0x03, 0x01}
	tlsVersion12 = [2]byte{0x03, 0x03}
)

const (
	tlsRecordHeaderLen = 5
	// helloRandomOffset locates the 32-byte random inside a ClientHello or
	// ServerHello record: 5 record header + 1 handshake type + 3 length + 2 version.
	helloRandomOffset   = 11
	helloRandomLen      = 32
	maxHandshakeRecords = 16
)

type tlsRecord struct {
	Type    recordType
	Version [2]byte
	Data    []byte
}

func readRecord(r io.Reader) (tlsRecord, error) {
	var hdr [tlsRecordHeaderLen]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return tlsRecord{}, err
	}
	rec := tlsRecord{Type: recordType(hdr[0])}
	copy(rec.Version[:], hdr[1:3])
	if rec.Version[0] != 0x03 || rec.Version[1] > 0x04 {
		return tlsRecord{}, fmt.Errorf("faketls: unknown record version % x", hdr[1:3])
	}
	rec.Data = make([]byte, binary.BigEndian.Uint16(hdr[3:5]))
	if _, err := io.ReadFull(r, rec.Data); err != nil {
		return tlsRecord{}, err
	}
	return rec, nil
}

func writeRecord(w io.Writer, rec tlsRecord) error {
	if len(rec.Data) > 0xffff {
		return errors.New("faketls: record too large")
	}
	buf := make([]byte, tlsRecordHeaderLen+len(rec.Data))
	buf[0] = byte(rec.Type)
	copy(buf[1:3], rec.Version[:])
	binary.BigEndian.PutUint16(buf[3:5], uint16(len(rec.Data)))
	copy(buf[tlsRecordHeaderLen:], rec.Data)
	n, err := w.Write(buf)
	if err == nil && n != len(buf) {
		err = io.ErrShortWrite
	}
	return err
}

// buildClientHello returns a Chrome-fingerprint ClientHello record for host
// whose random field carries HMAC-SHA256(key, record-with-zero-random) with
// the last 4 bytes XORed with the Unix time, as the proxy expects. The random
// is returned for verifying the server's reply.
func buildClientHello(rnd io.Reader, now time.Time, host string, key []byte) ([]byte, [helloRandomLen]byte, error) {
	var random [helloRandomLen]byte
	// A nil net.Conn is fine: BuildHandshakeState only assembles bytes.
	conn := utls.UClient(nil, &utls.Config{ServerName: host, Rand: rnd}, utls.HelloChrome_Auto)
	if err := conn.BuildHandshakeState(); err != nil {
		return nil, random, fmt.Errorf("faketls: build ClientHello: %w", err)
	}
	hello := conn.HandshakeState.Hello.Raw

	record := make([]byte, 0, tlsRecordHeaderLen+len(hello))
	record = append(record, byte(recordHandshake), tlsVersion10[0], tlsVersion10[1])
	record = binary.BigEndian.AppendUint16(record, uint16(len(hello)))
	record = append(record, hello...)
	if len(record) < helloRandomOffset+helloRandomLen {
		return nil, random, errors.New("faketls: ClientHello too short")
	}

	field := record[helloRandomOffset : helloRandomOffset+helloRandomLen]
	for i := range field {
		field[i] = 0
	}
	mac := hmac.New(sha256.New, key)
	mac.Write(record)
	copy(field, mac.Sum(nil))
	ts := binary.LittleEndian.Uint32(field[helloRandomLen-4:]) ^ uint32(now.Unix())
	binary.LittleEndian.PutUint32(field[helloRandomLen-4:], ts)
	copy(random[:], field)
	return record, random, nil
}

// verifyServerHello reads the proxy's reply flight (ServerHello, optional
// extra handshake records, ChangeCipherSpec, one application record) and
// checks the server random against HMAC-SHA256(key, clientRandom || flight
// with the server random zeroed).
func verifyServerHello(r io.Reader, clientRandom [helloRandomLen]byte, key []byte) error {
	var flight bytes.Buffer
	tee := io.TeeReader(r, &flight)

	rec, err := readRecord(tee)
	if err != nil {
		return fmt.Errorf("faketls: read ServerHello: %w", err)
	}
	if rec.Type != recordHandshake {
		return fmt.Errorf("faketls: unexpected record type 0x%02x, want handshake", byte(rec.Type))
	}
	if len(rec.Data) < 42 {
		return errors.New("faketls: ServerHello too short")
	}
	handshakeLen := int(rec.Data[1])<<16 | int(rec.Data[2])<<8 | int(rec.Data[3])
	if rec.Data[0] != 2 || handshakeLen != len(rec.Data)-4 {
		return errors.New("faketls: invalid ServerHello type or length")
	}

	sawChangeCipherSpec := false
	for i := 0; i < maxHandshakeRecords && !sawChangeCipherSpec; i++ {
		rec, err = readRecord(tee)
		if err != nil {
			return fmt.Errorf("faketls: read handshake flight: %w", err)
		}
		switch rec.Type {
		case recordHandshake:
		case recordChangeCipherSpec:
			if !bytes.Equal(rec.Data, []byte{1}) {
				return errors.New("faketls: invalid ChangeCipherSpec")
			}
			sawChangeCipherSpec = true
		default:
			return fmt.Errorf("faketls: unexpected record type 0x%02x in handshake flight", byte(rec.Type))
		}
	}
	if !sawChangeCipherSpec {
		return errors.New("faketls: no ChangeCipherSpec in handshake flight")
	}
	rec, err = readRecord(tee)
	if err != nil {
		return fmt.Errorf("faketls: read application record: %w", err)
	}
	if rec.Type != recordApplication {
		return fmt.Errorf("faketls: unexpected record type 0x%02x, want application data", byte(rec.Type))
	}

	packet := flight.Bytes()
	var got [helloRandomLen]byte
	copy(got[:], packet[helloRandomOffset:helloRandomOffset+helloRandomLen])
	for i := helloRandomOffset; i < helloRandomOffset+helloRandomLen; i++ {
		packet[i] = 0
	}
	mac := hmac.New(sha256.New, key)
	mac.Write(clientRandom[:])
	mac.Write(packet)
	if !hmac.Equal(mac.Sum(nil), got[:]) {
		return errors.New("faketls: server digest mismatch (wrong secret or cloak domain answered)")
	}
	return nil
}

// fakeTLS carries a byte stream inside TLS application records after the
// fake handshake. It is used as the conn of an obfuscated2 stream.
type fakeTLS struct {
	rnd     io.Reader
	now     func() time.Time
	conn    io.ReadWriter
	sentCCS bool
	readBuf bytes.Buffer
}

func newFakeTLS(rnd io.Reader, now func() time.Time, conn io.ReadWriter) *fakeTLS {
	return &fakeTLS{rnd: rnd, now: now, conn: conn}
}

// handshake sends the ClientHello and verifies the proxy's reply.
func (f *fakeTLS) handshake(host string, key []byte) error {
	record, clientRandom, err := buildClientHello(f.rnd, f.now(), host, key)
	if err != nil {
		return err
	}
	n, err := f.conn.Write(record)
	if err == nil && n != len(record) {
		err = io.ErrShortWrite
	}
	if err != nil {
		return fmt.Errorf("faketls: write ClientHello: %w", err)
	}
	return verifyServerHello(f.conn, clientRandom, key)
}

// Write sends p as one application record. The first call is preceded by a
// ChangeCipherSpec record, which real clients send and some proxies expect.
func (f *fakeTLS) Write(p []byte) (int, error) {
	if !f.sentCCS {
		if err := writeRecord(f.conn, tlsRecord{Type: recordChangeCipherSpec, Version: tlsVersion12, Data: []byte{0x01}}); err != nil {
			return 0, err
		}
		f.sentCCS = true
	}
	if err := writeRecord(f.conn, tlsRecord{Type: recordApplication, Version: tlsVersion12, Data: p}); err != nil {
		return 0, err
	}
	return len(p), nil
}

// Read returns application-record payload, skipping ChangeCipherSpec records.
// Read errors from the underlying conn are returned unwrapped so callers can
// tell EOF from other failures.
func (f *fakeTLS) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	for f.readBuf.Len() == 0 {
		rec, err := readRecord(f.conn)
		if err != nil {
			return 0, err
		}
		switch rec.Type {
		case recordApplication:
			f.readBuf.Write(rec.Data)
		case recordChangeCipherSpec:
		default:
			return 0, fmt.Errorf("faketls: unexpected record type 0x%02x", byte(rec.Type))
		}
	}
	return f.readBuf.Read(p)
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./pkg/core/mtproto/ -run 'TestBuildClientHello|TestVerifyServerHello|TestFakeTLS' -v`
Also cover bad record versions, zero-length reads, truncated record headers/bodies, additional handshake records, the handshake-record limit, and fragmented I/O. Make `fakeTLS.Read` return `(0, nil)` immediately for a zero-length buffer. Reject a first handshake message that is not ServerHello, inconsistent handshake lengths, and ChangeCipherSpec payloads other than `{1}`. The fake ServerHello fixture has a 38-byte body and a 42-byte handshake message.

Expected: all fake-TLS tests `PASS`. If `TestBuildClientHelloDigest` fails on the SNI check, print `record` as hex and confirm `utls.HelloChrome_Auto` emitted a `server_name` extension; the `ServerName` field of `utls.Config` must be set.

- [ ] **Step 5: Commit**

```bash
git add pkg/core/mtproto/faketls.go pkg/core/mtproto/faketls_test.go
git commit -m "mtproto: port fake TLS handshake and record layer from gotd"
```

---

### Task 6: Padded-intermediate framing and req_pq_multi

**Files:**
- Create: `pkg/core/mtproto/framing.go`
- Create: `pkg/core/mtproto/reqpq.go`
- Test: `pkg/core/mtproto/framing_test.go`
- Test: `pkg/core/mtproto/reqpq_test.go`

**Interfaces:**
- Produces: `func writePaddedFrame(rnd io.Reader, w io.Writer, payload []byte) error`; `func readPaddedFrame(r io.Reader) ([]byte, error)`; `const maxFrameLen = 1 << 20`; `const reqPQMultiConstructor uint32 = 0xbe7e8ef1`, `resPQConstructor uint32 = 0x05162463`; `type TransportError struct{Code int32}` with `Error()`; `func buildReqPQMulti(nonce [16]byte, now time.Time) []byte`; `func parseResPQ(frame []byte) ([16]byte, error)`.
- Test-only helper (reused by Task 7): `func buildResPQ(nonce [16]byte) []byte`.

Wire format ([Telegram transport specification](https://core.telegram.org/mtproto/mtproto-transports#padded-intermediate)): 4-byte little-endian length, payload, 0..15 random padding bytes; the length covers the padding. Return the entire frame from `readPaddedFrame`; `parseResPQ` uses the unencrypted message length to separate body and padding. Rounding the frame down to a multiple of four does not remove 4–15 bytes of padding. An unencrypted MTProto message is `auth_key_id int64 = 0`, `message_id int64`, `message_data_length int32`, then the TL object.

- [ ] **Step 1: Write the failing tests**

Create `pkg/core/mtproto/framing_test.go`:

```go
package mtproto

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"strings"
	"testing"
)

func TestPaddedFrameRoundTrip(t *testing.T) {
	for _, size := range []int{4, 8, 40, 84, 1024} {
		payload := make([]byte, size)
		_, _ = rand.Read(payload)
		for padLen := 0; padLen < 16; padLen++ { // deterministic coverage of every legal length
			var wire bytes.Buffer
			if err := writePaddedFrame(bytes.NewReader(append([]byte{byte(padLen)}, make([]byte, padLen)...)), &wire, payload); err != nil {
				t.Fatal(err)
			}
			raw := wire.Bytes()
			declared := int(binary.LittleEndian.Uint32(raw[:4]))
			if declared != len(raw)-4 {
				t.Fatalf("declared length %d, wire has %d payload bytes", declared, len(raw)-4)
			}
			if pad := declared - size; pad != padLen {
				t.Fatalf("padding %d bytes, want %d", pad, padLen)
			}
			got, err := readPaddedFrame(&wire)
			if err != nil {
				t.Fatal(err)
			}
			if len(got) != size+padLen || !bytes.Equal(got[:size], payload) {
				t.Fatalf("size %d: payload/padding mismatch", size)
			}
		}
	}
}

func TestWritePaddedFrameRejectsUnaligned(t *testing.T) {
	err := writePaddedFrame(rand.Reader, new(bytes.Buffer), []byte{1, 2, 3})
	if err == nil || !strings.Contains(err.Error(), "multiple of 4") {
		t.Fatalf("err = %v", err)
	}
}

func TestReadPaddedFrameKeepsFourByteFrames(t *testing.T) {
	wire := []byte{4, 0, 0, 0, 0x6c, 0xfe, 0xff, 0xff}
	got, err := readPaddedFrame(bytes.NewReader(wire))
	if err != nil || !bytes.Equal(got, wire[4:]) {
		t.Fatalf("got % x, %v", got, err)
	}
}

func TestReadPaddedFrameRejectsHugeLength(t *testing.T) {
	wire := []byte{0xff, 0xff, 0xff, 0x7f}
	if _, err := readPaddedFrame(bytes.NewReader(wire)); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("err = %v", err)
	}
}
```

Create `pkg/core/mtproto/reqpq_test.go`:

```go
package mtproto

import (
	"bytes"
	"encoding/binary"
	"errors"
	"strings"
	"testing"
	"time"
)

// buildResPQ fakes Telegram's answer to req_pq_multi: an unencrypted resPQ
// carrying the client nonce, a server nonce, a pq string and one fingerprint.
func buildResPQ(nonce [16]byte) []byte {
	body := binary.LittleEndian.AppendUint32(nil, resPQConstructor)
	body = append(body, nonce[:]...)
	body = append(body, bytes.Repeat([]byte{0x5a}, 16)...)                               // server_nonce
	body = append(body, 8, 0x17, 0xed, 0x48, 0x94, 0x1a, 0x08, 0xf9, 0x81, 0, 0, 0)     // pq: TL string, 8 bytes + 3 padding
	body = binary.LittleEndian.AppendUint32(body, 0x1cb5c415)                            // Vector<long>
	body = binary.LittleEndian.AppendUint32(body, 1)
	body = binary.LittleEndian.AppendUint64(body, 0xc3b42b026ce86b21)                    // server_public_key_fingerprints[0]
	msg := make([]byte, 20, 20+len(body))
	binary.LittleEndian.PutUint64(msg[8:16], uint64(time.Now().Unix())<<32|1)
	binary.LittleEndian.PutUint32(msg[16:20], uint32(len(body)))
	return append(msg, body...)
}

func TestBuildReqPQMulti(t *testing.T) {
	var nonce [16]byte
	for i := range nonce {
		nonce[i] = byte(i)
	}
	now := time.Unix(1_800_000_000, 0)
	msg := buildReqPQMulti(nonce, now)
	if len(msg) != 40 {
		t.Fatalf("len = %d, want 40", len(msg))
	}
	if binary.LittleEndian.Uint64(msg[0:8]) != 0 {
		t.Error("auth_key_id must be 0")
	}
	if got := binary.LittleEndian.Uint64(msg[8:16]); got != uint64(now.Unix())<<32|4 {
		t.Errorf("message_id = %x, want %x", got, uint64(now.Unix())<<32|4)
	}
	if binary.LittleEndian.Uint32(msg[16:20]) != 20 {
		t.Error("message_data_length must be 20")
	}
	if binary.LittleEndian.Uint32(msg[20:24]) != reqPQMultiConstructor {
		t.Errorf("constructor = %x", msg[20:24])
	}
	if !bytes.Equal(msg[24:40], nonce[:]) {
		t.Error("nonce mismatch")
	}
}

func TestBuildReqPQMultiFractionalMessageID(t *testing.T) {
	for _, nanos := range []int64{0, 1, 250_000_000, 999_999_999} {
		now := time.Unix(1_800_000_000, nanos)
		msg := buildReqPQMulti([16]byte{}, now)
		id := binary.LittleEndian.Uint64(msg[8:16])
		if id>>32 != uint64(now.Unix()) || id&3 != 0 || uint32(id) == 0 {
			t.Fatalf("invalid message ID %x for %v", id, now)
		}
		if nanos == 250_000_000 && uint32(id) != 1<<30 {
			t.Fatalf("fractional seconds lost: %x", id)
		}
	}
}

func TestParseResPQ(t *testing.T) {
	var nonce [16]byte
	nonce[0] = 0xab
	got, err := parseResPQ(buildResPQ(nonce))
	if err != nil || got != nonce {
		t.Fatalf("got %x, %v", got, err)
	}

	_, err = parseResPQ([]byte{0x6c, 0xfe, 0xff, 0xff})
	var te TransportError
	if !errors.As(err, &te) || te.Code != -404 || err.Error() != "transport error -404" {
		t.Errorf("transport error: %v", err)
	}

	garbage := buildResPQ(nonce)
	binary.LittleEndian.PutUint32(garbage[20:24], 0xdeadbeef)
	if _, err := parseResPQ(garbage); err == nil || !strings.Contains(err.Error(), "unexpected constructor 0xdeadbeef") {
		t.Errorf("garbage: %v", err)
	}

	if _, err := parseResPQ(make([]byte, 24)); err == nil || !strings.Contains(err.Error(), "too short") {
		t.Errorf("short: %v", err)
	}

	encrypted := buildResPQ(nonce)
	encrypted[0] = 1
	if _, err := parseResPQ(encrypted); err == nil || !strings.Contains(err.Error(), "auth_key_id") {
		t.Errorf("non-zero auth_key_id: %v", err)
	}
}
```

Append to `pkg/core/mtproto/reqpq_test.go`:

```go
func TestParseResPQBoundsAndPadding(t *testing.T) {
	var nonce [16]byte
	nonce[0] = 0xab
	valid := buildResPQ(nonce)
	for pad := 0; pad <= 15; pad++ {
		frame := append(append([]byte(nil), valid...), bytes.Repeat([]byte{0x77}, pad)...)
		if got, err := parseResPQ(frame); err != nil || got != nonce {
			t.Fatalf("padding %d: nonce=%x err=%v", pad, got, err)
		}
		transport := append([]byte{0x6c, 0xfe, 0xff, 0xff}, make([]byte, pad)...)
		var te TransportError
		if _, err := parseResPQ(transport); !errors.As(err, &te) || te.Code != -404 {
			t.Fatalf("padded transport error %d: %v", pad, err)
		}
	}
	for name, mutate := range map[string]func([]byte) []byte{
		"nonce-only": func(b []byte) []byte { return b[:40] },
		"missing fingerprint": func(b []byte) []byte { return b[:len(b)-8] },
		"oversized body": func(b []byte) []byte { binary.LittleEndian.PutUint32(b[16:20], 0xffffffff); return b },
		"unaligned body": func(b []byte) []byte { binary.LittleEndian.PutUint32(b[16:20], 63); return b },
		"wrong response ID": func(b []byte) []byte { b[8] = 0; return b },
		"invalid pq": func(b []byte) []byte { b[56] = 254; return b },
		"invalid vector": func(b []byte) []byte { b[68] = 0; return b },
		"oversized vector count": func(b []byte) []byte { binary.LittleEndian.PutUint32(b[72:76], 0xffffffff); return b },
		"excess padding": func(b []byte) []byte { return append(b, make([]byte, 16)...) },
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := parseResPQ(mutate(append([]byte(nil), valid...))); err == nil {
				t.Fatal("malformed resPQ accepted")
			}
		})
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./pkg/core/mtproto/ -run 'Frame|ReqPQ|ResPQ' -v`
Expected: build failure, `undefined: writePaddedFrame`, `undefined: resPQConstructor`.

- [ ] **Step 3: Implement framing**

Create `pkg/core/mtproto/framing.go`:

```go
// The padded-intermediate framing below follows github.com/gotd/td v0.161.0,
// proto/codec/padded_intermediate.go. MIT License, Copyright (c) 2020
// Aleksandr Razumov. See LICENSE.gotd in this directory.

package mtproto

import (
	"encoding/binary"
	"fmt"
	"io"
)

// maxFrameLen bounds a single frame so a hostile peer cannot make us allocate
// arbitrarily; a resPQ is under 100 bytes.
const maxFrameLen = 1 << 20

// writePaddedFrame sends payload as one padded-intermediate frame: a 4-byte
// little-endian length, the payload, and 0..15 random padding bytes covered by
// the length. Payload length must be a multiple of 4, as all TL objects are.
func writePaddedFrame(rnd io.Reader, w io.Writer, payload []byte) error {
	if len(payload)%4 != 0 {
		return fmt.Errorf("frame payload length %d is not a multiple of 4", len(payload))
	}
	var padByte [1]byte
	if _, err := io.ReadFull(rnd, padByte[:]); err != nil {
		return err
	}
	pad := int(padByte[0] % 16)
	frame := make([]byte, 4+len(payload)+pad)
	binary.LittleEndian.PutUint32(frame[:4], uint32(len(payload)+pad))
	copy(frame[4:], payload)
	if _, err := io.ReadFull(rnd, frame[4+len(payload):]); err != nil {
		return err
	}
	n, err := w.Write(frame)
	if err == nil && n != len(frame) {
		err = io.ErrShortWrite
	}
	return err
}

// readPaddedFrame returns the complete payload plus padding. The message
// decoder separates padding using message_data_length, not length modulo 4.
// Read errors are returned unwrapped so callers can recognise io.EOF.
func readPaddedFrame(r io.Reader) ([]byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	n := binary.LittleEndian.Uint32(hdr[:])
	if n < 4 {
		return nil, fmt.Errorf("frame length %d is too short", n)
	}
	if n > maxFrameLen {
		return nil, fmt.Errorf("frame length %d exceeds limit %d", n, maxFrameLen)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}
```

- [ ] **Step 4: Implement req_pq_multi**

Create `pkg/core/mtproto/reqpq.go`:

```go
package mtproto

import (
	"encoding/binary"
	"errors"
	"fmt"
	"time"
)

// TL constructors used by the probe. See https://core.telegram.org/mtproto/auth_key
const (
	reqPQMultiConstructor uint32 = 0xbe7e8ef1
	resPQConstructor      uint32 = 0x05162463
)

// Layout of the unencrypted message: auth_key_id(8) message_id(8)
// message_data_length(4) constructor(4) nonce(16).
const (
	unencryptedHeaderLen = 8 + 8 + 4
	reqPQMultiLen        = unencryptedHeaderLen + 4 + 16
)

// TransportError is a 4-byte MTProto transport-level error frame such as -404.
type TransportError struct{ Code int32 }

func (e TransportError) Error() string { return fmt.Sprintf("transport error %d", e.Code) }

// buildReqPQMulti encodes an unencrypted req_pq_multi#be7e8ef1 nonce:int128.
// The message_id approximates Unix time * 2^32, including fractional seconds.
// Client IDs are divisible by four and their low 32 bits must be nonzero.
func buildReqPQMulti(nonce [16]byte, now time.Time) []byte {
	msg := make([]byte, reqPQMultiLen)
	fraction := (uint64(now.Nanosecond()) << 32) / uint64(time.Second)
	fraction &^= 3
	if fraction == 0 {
		fraction = 4
	}
	binary.LittleEndian.PutUint64(msg[8:16], uint64(now.Unix())<<32|fraction)
	binary.LittleEndian.PutUint32(msg[16:20], reqPQMultiLen-unencryptedHeaderLen)
	binary.LittleEndian.PutUint32(msg[20:24], reqPQMultiConstructor)
	copy(msg[24:40], nonce[:])
	return msg
}

// parseResPQ validates the complete unencrypted resPQ TL object and returns
// its client nonce. Transport padding is outside message_data_length.
func parseResPQ(frame []byte) ([16]byte, error) {
	var nonce [16]byte
	if len(frame) >= 4 && len(frame) <= 19 {
		code := int32(binary.LittleEndian.Uint32(frame[:4]))
		if code < -1 { // -1 denotes a quick ACK, which this probe never requests.
			return nonce, TransportError{Code: code}
		}
	}
	if len(frame) < reqPQMultiLen {
		return nonce, fmt.Errorf("resPQ frame too short: %d bytes", len(frame))
	}
	if binary.LittleEndian.Uint64(frame[0:8]) != 0 {
		return nonce, errors.New("resPQ has a non-zero auth_key_id (unexpected encrypted message)")
	}
	if binary.LittleEndian.Uint64(frame[8:16])&3 != 1 {
		return nonce, errors.New("resPQ has an invalid response message_id")
	}
	n := uint64(binary.LittleEndian.Uint32(frame[16:20]))
	available := uint64(len(frame) - unencryptedHeaderLen)
	if n < 56 || n%4 != 0 || n > available || available-n > 15 {
		return nonce, errors.New("resPQ has an invalid message_data_length or padding")
	}
	body := frame[unencryptedHeaderLen : unencryptedHeaderLen+int(n)]
	if c := binary.LittleEndian.Uint32(body[:4]); c != resPQConstructor {
		return nonce, fmt.Errorf("unexpected constructor 0x%08x, want resPQ 0x%08x", c, resPQConstructor)
	}
	// resPQ: constructor, nonce:int128, server_nonce:int128, pq:bytes,
	// server_public_key_fingerprints:Vector<long>. pq is at most 8 bytes.
	pqLen := int(body[36])
	if pqLen < 1 || pqLen > 8 {
		return nonce, errors.New("resPQ has an invalid pq length")
	}
	vectorOffset := 36 + (1+pqLen+3)&^3
	if vectorOffset+8 > len(body) || binary.LittleEndian.Uint32(body[vectorOffset:]) != 0x1cb5c415 {
		return nonce, errors.New("resPQ has an invalid fingerprint vector")
	}
	count := uint64(binary.LittleEndian.Uint32(body[vectorOffset+4:]))
	if count == 0 || count*8 != uint64(len(body)-vectorOffset-8) {
		return nonce, errors.New("resPQ has an invalid fingerprint count")
	}
	copy(nonce[:], body[4:20])
	return nonce, nil
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `go test ./pkg/core/mtproto/ -run 'Frame|ReqPQ|ResPQ' -v`
Expected: all frame, request and response tests `PASS`.

- [ ] **Step 6: Commit**

```bash
git add pkg/core/mtproto/framing.go pkg/core/mtproto/reqpq.go pkg/core/mtproto/framing_test.go pkg/core/mtproto/reqpq_test.go
git commit -m "mtproto: add padded-intermediate framing and req_pq_multi"
```

---

### Task 7: Probe orchestration with an in-process fake proxy

**Files:**
- Create: `pkg/core/mtproto/prober.go`
- Test: `pkg/core/mtproto/testserver_test.go`
- Test: `pkg/core/mtproto/prober_test.go`

**Interfaces:**
- Consumes: everything from Tasks 2 to 6; `netbind.New(iface) (*netbind.Binder, error)` and `(*Binder).ApplyDialer(*net.Dialer)` (nil-safe); `protocol.ProbeOptions`, `protocol.ProbeResult` (Task 1).
- Produces: `func (m *MTProto) Probe(ctx context.Context, opts protocol.ProbeOptions) (protocol.ProbeResult, error)` (so `*MTProto` satisfies `protocol.Prober`); `const probeDC = 2`.
- Test-only: `type serverMode int` with `modeOK`, `modeHang`, `modeGarbage`, `modeTransportError`; `func startFakeProxy(t *testing.T, secret Secret, mode serverMode) *fakeProxy` with `port() string`.

Failure texts the tests assert, copied from the spec: `read resPQ: timeout`, `read resPQ: EOF (proxy closed connection; wrong secret?)`, `faketls: server digest mismatch`, `unexpected constructor`, `transport error -404`, `resPQ nonce mismatch`, and dial errors prefixed `dial `.

- [ ] **Step 1: Write the fake proxy**

Create `pkg/core/mtproto/testserver_test.go`:

```go
package mtproto

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

type serverMode int

const (
	modeOK             serverMode = iota // answer resPQ with the client's nonce
	modeHang                             // accept everything, never answer
	modeGarbage                          // answer with a wrong constructor
	modeTransportError                   // answer with a 4-byte -404 frame
)

// fakeProxy is a minimal MTProto proxy for tests: it speaks the server side
// of obfuscated2 and fake TLS, parses one req_pq_multi and answers according
// to its mode. A wrong client secret is simulated simply by starting the
// proxy with a different Secret than the client uses.
type fakeProxy struct {
	t      *testing.T
	ln     net.Listener
	secret Secret
	mode   serverMode
	wg     sync.WaitGroup
}

func startFakeProxy(t *testing.T, secret Secret, mode serverMode) *fakeProxy {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := &fakeProxy{t: t, ln: ln, secret: secret, mode: mode}
	p.wg.Add(1)
	go p.acceptLoop()
	t.Cleanup(func() {
		_ = ln.Close()
		p.wg.Wait()
	})
	return p
}

func (p *fakeProxy) port() string {
	_, port, _ := net.SplitHostPort(p.ln.Addr().String())
	return port
}

func (p *fakeProxy) acceptLoop() {
	defer p.wg.Done()
	for {
		conn, err := p.ln.Accept()
		if err != nil {
			return
		}
		p.wg.Add(1)
		go func() {
			defer p.wg.Done()
			defer conn.Close()
			p.serve(conn)
		}()
	}
}

// drainAndClose reads whatever the client already sent so that closing does
// not turn into a TCP reset; the client then sees a clean EOF like it would
// from a real proxy that dropped it.
func drainAndClose(conn net.Conn) {
	_ = conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	_, _ = io.Copy(io.Discard, conn)
}

func (p *fakeProxy) serve(conn net.Conn) {
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	var stream io.ReadWriter = conn

	if p.secret.Type == SecretFakeTLS {
		rec, err := readRecord(conn)
		if err != nil || rec.Type != recordHandshake {
			return
		}
		full := make([]byte, 0, tlsRecordHeaderLen+len(rec.Data))
		full = append(full, byte(rec.Type), rec.Version[0], rec.Version[1])
		full = binary.BigEndian.AppendUint16(full, uint16(len(rec.Data)))
		full = append(full, rec.Data...)
		var clientRandom [helloRandomLen]byte
		copy(clientRandom[:], full[helloRandomOffset:helloRandomOffset+helloRandomLen])

		// Validate the client digest the way a proxy does (timestamp skew ignored).
		zeroed := append([]byte(nil), full...)
		for i := helloRandomOffset; i < helloRandomOffset+helloRandomLen; i++ {
			zeroed[i] = 0
		}
		mac := hmac.New(sha256.New, p.secret.Key[:])
		mac.Write(zeroed)
		if !bytes.Equal(mac.Sum(nil)[:28], clientRandom[:28]) {
			// A real proxy would forward to the cloak host and the client would
			// see a genuine TLS ServerHello whose random fails the HMAC check.
			// Answer with our own key so the client observes the same mismatch.
			_, _ = conn.Write(buildServerHelloFlight(rand.Reader, clientRandom, p.secret.Key[:]))
			drainAndClose(conn)
			return
		}
		if _, err := conn.Write(buildServerHelloFlight(rand.Reader, clientRandom, p.secret.Key[:])); err != nil {
			return
		}
		stream = &fakeTLS{conn: conn, sentCCS: true}
	}

	var init [obfsInitLen]byte
	if _, err := io.ReadFull(stream, init[:]); err != nil {
		return
	}
	encrypt, decrypt, err := serverStreams(init, p.secret.Key)
	if err != nil {
		return
	}
	var plain [obfsInitLen]byte
	decrypt.XORKeyStream(plain[:], init[:])
	if [4]byte(plain[56:60]) != paddedIntermediateTag {
		// Wrong secret: the tag is noise. Real proxies just drop the connection.
		drainAndClose(conn)
		return
	}
	obfs := &obfuscated2{conn: stream, encrypt: encrypt, decrypt: decrypt}

	frame, err := readPaddedFrame(obfs)
	if err != nil {
		return
	}
	if len(frame) < reqPQMultiLen || len(frame)-reqPQMultiLen > 15 ||
		binary.LittleEndian.Uint64(frame[:8]) != 0 ||
		binary.LittleEndian.Uint64(frame[8:16])&3 != 0 ||
		uint32(binary.LittleEndian.Uint64(frame[8:16])) == 0 ||
		binary.LittleEndian.Uint32(frame[16:20]) != 20 ||
		binary.LittleEndian.Uint32(frame[20:24]) != reqPQMultiConstructor {
		p.t.Errorf("fake proxy: expected req_pq_multi, got % x", frame)
		return
	}
	var nonce [16]byte
	copy(nonce[:], frame[24:40])

	switch p.mode {
	case modeHang:
		_, _ = io.Copy(io.Discard, conn) // block until the client gives up
	case modeTransportError:
		_ = writePaddedFrame(rand.Reader, obfs, []byte{0x6c, 0xfe, 0xff, 0xff}) // int32 -404
	case modeGarbage:
		reply := buildResPQ(nonce)
		binary.LittleEndian.PutUint32(reply[20:24], 0xdeadbeef)
		_ = writePaddedFrame(rand.Reader, obfs, reply)
	default:
		_ = writePaddedFrame(rand.Reader, obfs, buildResPQ(nonce))
	}
}
```

- [ ] **Step 2: Write the failing probe tests**

Create `pkg/core/mtproto/prober_test.go`:

```go
package mtproto

import (
	"context"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/lilendian0x00/xray-knife/v11/pkg/core/protocol"
)

var _ protocol.Prober = (*MTProto)(nil)

func TestProbeAgainstFakeProxy(t *testing.T) {
	key := testKey(t)
	secured := Secret{Type: SecretSecured, Key: key}
	simple := Secret{Type: SecretSimple, Key: key}
	fake := Secret{Type: SecretFakeTLS, Key: key, CloakHost: "www.google.com"}
	otherSecured := Secret{Type: SecretSecured, Key: [16]byte{1, 2, 3}}
	otherFake := Secret{Type: SecretFakeTLS, Key: [16]byte{1, 2, 3}, CloakHost: "www.google.com"}

	cases := []struct {
		name    string
		server  Secret
		client  Secret
		mode    serverMode
		timeout time.Duration
		wantErr string
	}{
		{name: "secured ok", server: secured, client: secured},
		{name: "simple ok", server: simple, client: simple},
		{name: "faketls ok", server: fake, client: fake},
		{name: "secured wrong secret", server: otherSecured, client: secured, wantErr: "read resPQ: EOF (proxy closed connection; wrong secret?)"},
		{name: "faketls wrong secret", server: otherFake, client: fake, wantErr: "faketls: server digest mismatch"},
		{name: "hang", server: secured, client: secured, mode: modeHang, timeout: 300 * time.Millisecond, wantErr: "read resPQ: timeout"},
		{name: "garbage", server: secured, client: secured, mode: modeGarbage, wantErr: "unexpected constructor 0xdeadbeef"},
		{name: "transport error", server: secured, client: secured, mode: modeTransportError, wantErr: "transport error -404"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := startFakeProxy(t, tc.server, tc.mode)
			m := NewMTProto("tg://proxy?server=127.0.0.1&port=" + srv.port() + "&secret=" + tc.client.Hex())
			if err := m.Parse(); err != nil {
				t.Fatal(err)
			}
			timeout := tc.timeout
			if timeout == 0 {
				timeout = 5 * time.Second
			}
			res, err := m.Probe(context.Background(), protocol.ProbeOptions{Timeout: timeout})
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want containing %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if res.ConnectTime <= 0 || res.TTFB < res.ConnectTime || res.Delay < res.TTFB {
				t.Errorf("timings out of order: %+v", res)
			}
			want := tc.client.Type.String() + ", dc2 resPQ ok"
			if res.Detail != want {
				t.Errorf("Detail = %q, want %q", res.Detail, want)
			}
		})
	}
}

func TestProbeDialFailure(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	_ = ln.Close()

	m := NewMTProto("tg://proxy?server=127.0.0.1&port=" + port + "&secret=" + testKeyHex)
	if err := m.Parse(); err != nil {
		t.Fatal(err)
	}
	_, err = m.Probe(context.Background(), protocol.ProbeOptions{Timeout: 2 * time.Second})
	if err == nil || !strings.HasPrefix(err.Error(), "dial 127.0.0.1:"+port) {
		t.Fatalf("err = %v, want dial error", err)
	}
}

func TestProbeUnknownBindInterface(t *testing.T) {
	m := NewMTProto("tg://proxy?server=127.0.0.1&port=1&secret=" + testKeyHex)
	if err := m.Parse(); err != nil {
		t.Fatal(err)
	}
	_, err := m.Probe(context.Background(), protocol.ProbeOptions{Timeout: time.Second, BindInterface: "no-such-iface0"})
	if err == nil || !strings.Contains(err.Error(), "no-such-iface0") {
		t.Fatalf("err = %v, want interface error", err)
	}
}

// TestProbeLiveProxy runs against a real proxy only when XRAY_KNIFE_MTPROTO_LINK
// is set, e.g. XRAY_KNIFE_MTPROTO_LINK='tg://proxy?server=…&port=…&secret=…'.
func TestProbeLiveProxy(t *testing.T) {
	link := os.Getenv("XRAY_KNIFE_MTPROTO_LINK")
	if link == "" {
		t.Skip("set XRAY_KNIFE_MTPROTO_LINK to run against a real proxy")
	}
	m := NewMTProto(link)
	if err := m.Parse(); err != nil {
		t.Fatal(err)
	}
	res, err := m.Probe(context.Background(), protocol.ProbeOptions{Timeout: 15 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("%s connect=%s ttfb=%s delay=%s", res.Detail, res.ConnectTime, res.TTFB, res.Delay)
}
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `go test ./pkg/core/mtproto/ -run 'TestProbe' -v`
Expected: build failure, `m.Probe undefined`.

- [ ] **Step 4: Implement the prober**

Create `pkg/core/mtproto/prober.go`:

```go
package mtproto

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"syscall"
	"time"

	"github.com/lilendian0x00/xray-knife/v11/pkg/core/protocol"
	"github.com/lilendian0x00/xray-knife/v11/pkg/netbind"
)

const (
	// probeDC is the single Telegram data center requested by this probe.
	// A result describes this route only; other DCs may have different reachability.
	probeDC             = 2
	defaultProbeTimeout = 10 * time.Second
)

// Probe dials the proxy, completes the obfuscation handshake and performs one
// unencrypted req_pq_multi round trip. Success confirms a well-formed reply
// for DC 2, not authenticated Telegram identity; a proxy can synthesize resPQ.
// Timings are measured from before the dial.
func (m *MTProto) Probe(ctx context.Context, opts protocol.ProbeOptions) (protocol.ProbeResult, error) {
	return m.probe(ctx, opts, rand.Reader, time.Now)
}

func (m *MTProto) probe(ctx context.Context, opts protocol.ProbeOptions, rnd io.Reader, now func() time.Time) (protocol.ProbeResult, error) {
	var res protocol.ProbeResult
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = defaultProbeTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	binder, err := netbind.New(opts.BindInterface)
	if err != nil {
		return res, err
	}
	dialer := &net.Dialer{}
	binder.ApplyDialer(dialer)

	target := net.JoinHostPort(m.Address, m.Port)
	start := time.Now()
	conn, err := dialer.DialContext(ctx, "tcp", target)
	if err != nil {
		return res, fmt.Errorf("dial %s: %w", target, err)
	}
	defer conn.Close()
	res.ConnectTime = time.Since(start)
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()

	tc := &timedConn{Conn: conn}
	var stream io.ReadWriter = tc
	if m.Secret.Type == SecretFakeTLS {
		ft := newFakeTLS(rnd, now, tc)
		if err := ft.handshake(m.Secret.CloakHost, m.Secret.Key[:]); err != nil {
			return res, stageErr(ctx, "faketls handshake", err)
		}
		stream = ft
	}

	obfs, err := newObfuscated2(rnd, stream, m.Secret.Key, paddedIntermediateTag, probeDC)
	if err != nil {
		return res, err
	}
	if err := obfs.handshake(); err != nil {
		return res, stageErr(ctx, "obfuscated2 handshake", err)
	}

	var nonce [16]byte
	if _, err := io.ReadFull(rnd, nonce[:]); err != nil {
		return res, err
	}
	tc.arm(func() { res.TTFB = time.Since(start) })
	if err := writePaddedFrame(rnd, obfs, buildReqPQMulti(nonce, now())); err != nil {
		return res, stageErr(ctx, "write req_pq_multi", err)
	}
	frame, err := readPaddedFrame(obfs)
	if err != nil {
		return res, stageErr(ctx, "read resPQ", err)
	}
	got, err := parseResPQ(frame)
	if err != nil {
		return res, err
	}
	if got != nonce {
		return res, errors.New("resPQ nonce mismatch")
	}
	res.Delay = time.Since(start)
	res.Detail = fmt.Sprintf("%s, dc%d resPQ ok", m.Secret.Type, probeDC)
	return res, nil
}

// stageErr turns low-level I/O failures into the reasons users see. Errors
// that already carry meaning (digest mismatch, bad frame) pass through.
func stageErr(ctx context.Context, stage string, err error) error {
	switch {
	case errors.Is(ctx.Err(), context.Canceled):
		return fmt.Errorf("%s: %w", stage, context.Canceled)
	case errors.Is(ctx.Err(), context.DeadlineExceeded), errors.Is(err, os.ErrDeadlineExceeded):
		return fmt.Errorf("%s: timeout: %w", stage, context.DeadlineExceeded)
	case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF), errors.Is(err, syscall.ECONNRESET):
		return fmt.Errorf("%s: EOF (proxy closed connection; wrong secret?)", stage)
	}
	return fmt.Errorf("%s: %w", stage, err)
}

// timedConn calls onFirst once, on the first byte read after arm.
type timedConn struct {
	net.Conn
	onFirst func()
}

func (c *timedConn) arm(f func()) { c.onFirst = f }

func (c *timedConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 && c.onFirst != nil {
		c.onFirst()
		c.onFirst = nil
	}
	return n, err
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `go test ./pkg/core/mtproto/ -race -v`
Expected: every test `PASS`, `TestProbeLiveProxy` `SKIP`. The `hang` case takes about 300 ms; the `secured wrong secret` case takes about 200 ms (the fake proxy drains before closing).

If `secured wrong secret` reports `connection reset by peer`, the drain window is too short for the machine; raise `drainAndClose` to 500 ms. If `faketls ok` fails with `server digest mismatch`, check that `buildServerHelloFlight` is given `p.secret.Key[:]` and that the client validates against the same bytes.

- [ ] **Step 6: Commit**

```bash
git add pkg/core/mtproto/prober.go pkg/core/mtproto/prober_test.go pkg/core/mtproto/testserver_test.go
git commit -m "mtproto: probe proxies with a req_pq_multi round trip"
```

---

### Task 8: MTProto Core

**Files:**
- Create: `pkg/core/mtproto/mtproto.go`
- Test: `pkg/core/mtproto/mtproto_test.go`

**Interfaces:**
- Consumes: `IsProxyLink`, `NewMTProto` (Task 3).
- Produces: `var ErrNotProxyable error`; `type Core struct{}`; `func NewCore() *Core`; methods `Name() string`, `CreateProtocol(string) (protocol.Protocol, error)`, `MakeHttpClient(context.Context, protocol.Protocol, time.Duration) (*http.Client, protocol.Instance, error)`, `MakeInstance(context.Context, protocol.Protocol) (protocol.Instance, error)`, `SetInbound(protocol.Protocol) error`. Together these satisfy `core.Core`; the compile-time assertion lives in Task 9 because `pkg/core` imports this package.

- [ ] **Step 1: Write the failing tests**

Create `pkg/core/mtproto/mtproto_test.go`:

```go
package mtproto

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestCoreCreateProtocol(t *testing.T) {
	c := NewCore()
	if c.Name() != "mtproto" {
		t.Errorf("Name() = %q", c.Name())
	}
	p, err := c.CreateProtocol("  tg://proxy?server=a.b&port=1&secret=" + testKeyHex + "  ")
	if err != nil {
		t.Fatal(err)
	}
	m, ok := p.(*MTProto)
	if !ok {
		t.Fatalf("CreateProtocol returned %T", p)
	}
	if m.OrigLink != "tg://proxy?server=a.b&port=1&secret="+testKeyHex {
		t.Errorf("OrigLink not trimmed: %q", m.OrigLink)
	}
	if _, err := c.CreateProtocol("vless://uuid@host:443"); err == nil {
		t.Error("non-proxy link accepted")
	}
}

func TestCoreRefusesOutboundUse(t *testing.T) {
	c := NewCore()
	p := NewMTProto("tg://proxy?server=a.b&port=1&secret=" + testKeyHex)
	if _, _, err := c.MakeHttpClient(context.Background(), p, time.Second); !errors.Is(err, ErrNotProxyable) {
		t.Errorf("MakeHttpClient err = %v", err)
	}
	if _, err := c.MakeInstance(context.Background(), p); !errors.Is(err, ErrNotProxyable) {
		t.Errorf("MakeInstance err = %v", err)
	}
	if err := c.SetInbound(p); !errors.Is(err, ErrNotProxyable) {
		t.Errorf("SetInbound err = %v", err)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./pkg/core/mtproto/ -run 'TestCore' -v`
Expected: build failure, `undefined: NewCore`.

- [ ] **Step 3: Implement**

Create `pkg/core/mtproto/mtproto.go`:

```go
// Package mtproto tests Telegram MTProto proxies. It parses tg://proxy and
// t.me/proxy share links and verifies a proxy by completing its obfuscation
// handshake and one unencrypted MTProto round trip. MTProto proxies only relay
// Telegram traffic, so this package never acts as a general outbound.
package mtproto

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/lilendian0x00/xray-knife/v11/pkg/core/protocol"
)

// ErrNotProxyable is returned when an MTProto proxy is asked to act as a
// general-purpose outbound (proxy, tun, chain, scanner).
var ErrNotProxyable = errors.New("mtproto proxies only relay Telegram traffic and cannot be used as a general outbound")

// Core satisfies core.Core for MTProto proxy links. Only CreateProtocol does
// real work; reachability testing lives on MTProto.Probe.
type Core struct{}

func NewCore() *Core { return &Core{} }

func (c *Core) Name() string { return protocol.MTProtoIdentifier }

// CreateProtocol accepts tg://proxy?… and http(s)://t.me/proxy?… links.
func (c *Core) CreateProtocol(link string) (protocol.Protocol, error) {
	link = strings.TrimSpace(link)
	if !IsProxyLink(link) {
		return nil, fmt.Errorf("not an mtproto proxy link: %s", link)
	}
	return NewMTProto(link), nil
}

func (c *Core) MakeHttpClient(context.Context, protocol.Protocol, time.Duration) (*http.Client, protocol.Instance, error) {
	return nil, nil, ErrNotProxyable
}

func (c *Core) MakeInstance(context.Context, protocol.Protocol) (protocol.Instance, error) {
	return nil, ErrNotProxyable
}

func (c *Core) SetInbound(protocol.Protocol) error { return ErrNotProxyable }
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./pkg/core/mtproto/ -run 'TestCore' -v`
Expected: 2 tests `PASS`.

- [ ] **Step 5: Commit**

```bash
git add pkg/core/mtproto/mtproto.go pkg/core/mtproto/mtproto_test.go
git commit -m "mtproto: add Core that refuses outbound use"
```

---

### Task 9: Route MTProto links through AutomaticCore

**Files:**
- Modify: `pkg/core/factory.go:56-100`
- Test: `pkg/core/factory_test.go` (new)

**Interfaces:**
- Consumes: `mtproto.NewCore`, `mtproto.IsProxyLink`, `mtproto.ErrNotProxyable` (Tasks 3, 8).
- Produces: `AutomaticCore.mtprotoCore Core` field; `selectCoreForLink` returns it for MTProto links.

- [ ] **Step 1: Write the failing test**

Create `pkg/core/factory_test.go`:

```go
package core

import (
	"context"
	"errors"
	"testing"

	"github.com/lilendian0x00/xray-knife/v11/pkg/core/mtproto"
)

// The mtproto core must satisfy the Core contract; asserted here because
// pkg/core imports pkg/core/mtproto and not the other way round.
var _ Core = (*mtproto.Core)(nil)

func TestAutomaticCoreRoutesMTProtoLinks(t *testing.T) {
	c := NewAutomaticCore(false, false).(*AutomaticCore)
	const secret = "00112233445566778899aabbccddeeff"
	proxyLinks := []string{
		"tg://proxy?server=1.2.3.4&port=443&secret=" + secret,
		"https://t.me/proxy?server=1.2.3.4&port=443&secret=" + secret,
		"https://telegram.me/proxy?server=1.2.3.4&port=443&secret=" + secret,
		"http://telegram.dog/proxy?server=1.2.3.4&port=443&secret=" + secret,
	}
	for _, link := range proxyLinks {
		selected, err := c.selectCoreForLink(link)
		if err != nil {
			t.Fatalf("%s: %v", link, err)
		}
		if selected.Name() != "mtproto" {
			t.Errorf("%s routed to %s", link, selected.Name())
		}
		p, err := c.CreateProtocol(link)
		if err != nil {
			t.Fatalf("CreateProtocol(%s): %v", link, err)
		}
		if err := p.Parse(); err != nil {
			t.Fatalf("Parse(%s): %v", link, err)
		}
		if g := p.ConvertToGeneralConfig(); g.Protocol != "mtproto" || g.Address != "1.2.3.4" || g.Port != "443" {
			t.Errorf("%s: GeneralConfig = %+v", link, g)
		}
		if _, err := c.MakeInstance(context.Background(), p); !errors.Is(err, mtproto.ErrNotProxyable) {
			t.Errorf("%s: MakeInstance err = %v, want ErrNotProxyable", link, err)
		}
	}

	for _, link := range []string{
		"https://t.me/joinchat/abc",
		"tg://evil/proxy?server=a&port=1&secret=b",
		"tg://proxy/extra?server=a&port=1&secret=b",
		"https://user@t.me/proxy?server=a&port=1&secret=b",
		"https://example.com/proxy?server=a&port=1&secret=b",
		"https://sub.example.com/list.txt",
		"vless://uuid@host:443?type=tcp",
	} {
		selected, err := c.selectCoreForLink(link)
		if err == nil && selected.Name() == "mtproto" {
			t.Errorf("%s wrongly routed to mtproto", link)
		}
	}
}

func TestExplicitCoresStillRejectMTProto(t *testing.T) {
	link := "tg://proxy?server=1.2.3.4&port=443&secret=00112233445566778899aabbccddeeff"
	for _, ct := range []CoreType{XrayCoreType, SingboxCoreType} {
		if _, err := CoreFactory(ct, false, false).CreateProtocol(link); err == nil {
			t.Errorf("core %d accepted an mtproto link", ct)
		}
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./pkg/core/ -run 'TestAutomaticCoreRoutesMTProto|TestExplicitCores' -v`
Expected: `TestAutomaticCoreRoutesMTProtoLinks` fails with `unsupported protocol for automatic core: tg`. `TestExplicitCoresStillRejectMTProto` passes already.

- [ ] **Step 3: Implement**

In `pkg/core/factory.go`:

Add the import:

```go
	"github.com/lilendian0x00/xray-knife/v11/pkg/core/mtproto"
```

Change the struct and constructor:

```go
// AutomaticCore implementation of the Core interface
// Selects Core based on the config link
type AutomaticCore struct {
	xrayCore    Core
	singboxCore Core
	// mtprotoCore handles Telegram proxy links, which neither xray-core nor
	// sing-box can carry. It is only reachable through the automatic core.
	mtprotoCore Core
}
```

```go
func NewAutomaticCoreWith(opts FactoryOptions) Core {
	return &AutomaticCore{
		xrayCore:    xray.NewXrayService(opts.Verbose, opts.InsecureTLS, xray.WithBindInterface(opts.BindInterface)),
		singboxCore: singbox.NewSingboxService(opts.Verbose, opts.InsecureTLS, singbox.WithBindInterface(opts.BindInterface)),
		mtprotoCore: mtproto.NewCore(),
	}
}
```

At the top of `selectCoreForLink`, before `url.Parse`:

```go
func (c *AutomaticCore) selectCoreForLink(configLink string) (Core, error) {
	// MTProto links come as tg://proxy?… or https://t.me/proxy?…; the latter
	// would otherwise look like an ordinary https URL.
	if mtproto.IsProxyLink(configLink) {
		return c.mtprotoCore, nil
	}
	uri, err := url.Parse(configLink)
	...
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./pkg/core/ -v`
Expected: all `PASS`, including the existing identity tests.

- [ ] **Step 5: Commit**

```bash
git add pkg/core/factory.go pkg/core/factory_test.go
git commit -m "core: route MTProto proxy links to the mtproto core"
```

---

### Task 10: Connection fingerprint for MTProto

**Files:**
- Modify: `pkg/core/identity.go:44-60`
- Test: `pkg/core/identity_test.go` (append)

**Interfaces:**
- Consumes: `*mtproto.MTProto` fields `Address`, `Port`, `Secret.Hex()` (Tasks 2, 3).

- [ ] **Step 1: Write the failing test**

Append to `pkg/core/identity_test.go` (add `"encoding/hex"` to its imports):

```go
func TestConnectionFingerprintMTProto(t *testing.T) {
	c := NewAutomaticCore(false, false)
	const key = "00112233445566778899aabbccddeeff"
	raw, err := hex.DecodeString("dd" + key)
	if err != nil {
		t.Fatal(err)
	}
	b64 := base64.RawURLEncoding.EncodeToString(raw)

	same := []string{
		"tg://proxy?server=Proxy.Example.com&port=443&secret=dd" + key,
		"https://t.me/proxy?server=proxy.example.com&port=443&secret=DD" + strings.ToUpper(key) + "#renamed",
		"tg://proxy?secret=" + b64 + "&port=443&server=proxy.example.com",
		"tg://proxy?server=proxy.example.com&port=00443&secret=dd" + key,
	}
	want := fingerprint(t, c, same[0])
	for _, link := range same[1:] {
		if fingerprint(t, c, link) != want {
			t.Errorf("%s did not collapse onto %s", link, same[0])
		}
	}

	for name, other := range map[string]string{
		"secret":      "tg://proxy?server=proxy.example.com&port=443&secret=dd" + strings.Repeat("0", 32),
		"port":        "tg://proxy?server=proxy.example.com&port=444&secret=dd" + key,
		"server":      "tg://proxy?server=other.example.com&port=443&secret=dd" + key,
		"secret type": "tg://proxy?server=proxy.example.com&port=443&secret=" + key,
		"unknown option": same[0] + "&future-option=one",
	} {
		if fingerprint(t, c, other) == want {
			t.Errorf("distinct %s collapsed", name)
		}
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./pkg/core/ -run TestConnectionFingerprintMTProto -v`
Expected: FAIL. The `t.me` form and the base64 form do not collapse yet because the raw URL text is hashed.

- [ ] **Step 3: Implement**

In `pkg/core/identity.go` add the import `"github.com/lilendian0x00/xray-knife/v11/pkg/core/mtproto"` and a case in the `switch v := p.(type)` block, after the `*singbox.Socks` case:

```go
		case *mtproto.MTProto:
			// Preserve unknown query options, as required by ConnectionFingerprint.
			query, queryErr := url.ParseQuery(u.RawQuery)
			if queryErr != nil {
				return "", errors.New("cannot fingerprint malformed share link")
			}
			query.Set("server", strings.ToLower(v.Address))
			query.Set("port", v.Port) // Parse normalized it to decimal.
			query.Set("secret", v.Secret.Hex())
			u = &url.URL{Scheme: "tg", Host: "proxy", RawQuery: query.Encode()}
```

`canonicalURI` then sorts the query and drops the fragment; its `SplitHostPort` step fails on the host `proxy` and leaves it alone, which is fine.

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./pkg/core/ ./pkg/http/ -run 'Fingerprint|Dedup' -v`
Expected: all `PASS`, including `TestSemanticDeduplicateLinks*` in `pkg/http`.

- [ ] **Step 5: Commit**

```bash
git add pkg/core/identity.go pkg/core/identity_test.go
git commit -m "core: fingerprint MTProto proxies by server, port and secret"
```

---

### Task 11: Examiner probe path

**Files:**
- Create: `pkg/http/probe.go`
- Modify: `pkg/http/examiner.go:420-430` (insert one branch before `MakeHttpClient`)
- Test: `pkg/http/probe_test.go`

**Interfaces:**
- Consumes: `protocol.Prober`, `protocol.ProbeOptions`, `protocol.ProbeResult` (Task 1); `Result.appendReason`, `FailedDelay`, `stubCore`, `stubProtocol` from `pkg/http/examine_grade_test.go`.
- Produces: `func (e *Examiner) examineProbe(ctx context.Context, r Result, p protocol.Prober) (Result, error)`.

- [ ] **Step 1: Write the failing tests**

Create `pkg/http/probe_test.go`:

```go
package http

import (
	"context"
	"errors"
	"io"
	"log"
	stdhttp "net/http"
	"testing"
	"time"

	"github.com/lilendian0x00/xray-knife/v11/pkg/core/protocol"
)

// stubProber is a Protocol that grades itself through Prober with a scripted
// outcome, standing in for an MTProto proxy without any network.
type stubProber struct {
	stubProtocol
	res  protocol.ProbeResult
	err  error
	opts protocol.ProbeOptions // what the examiner passed, for assertions
	calls int
	failFirst bool
}

func (s *stubProber) Probe(_ context.Context, opts protocol.ProbeOptions) (protocol.ProbeResult, error) {
	s.opts = opts
	s.calls++
	if s.failFirst && s.calls == 1 {
		return protocol.ProbeResult{}, errors.New("temporary probe failure")
	}
	return s.res, s.err
}

func (s *stubProber) ConvertToGeneralConfig() protocol.GeneralConfig {
	return protocol.GeneralConfig{Protocol: "mtproto", Address: "1.2.3.4", Port: "443", TLS: "faketls"}
}

type proberCore struct {
	stubCore
	p *stubProber
}

func (c proberCore) CreateProtocol(string) (protocol.Protocol, error) { return c.p, nil }

func (c proberCore) MakeHttpClient(context.Context, protocol.Protocol, time.Duration) (*stdhttp.Client, protocol.Instance, error) {
	return nil, nil, errors.New("unexpected HTTP path for Prober")
}

const probeLink = "tg://proxy?server=1.2.3.4&port=443&secret=00112233445566778899aabbccddeeff"

func newProbeExaminer(t *testing.T, p *stubProber, mutate func(*Examiner)) *Examiner {
	t.Helper()
	e, err := NewExaminer(Options{MaxDelay: 1000, Timeout: 2500, Logger: log.New(io.Discard, "", 0)})
	if err != nil {
		t.Fatal(err)
	}
	e.Core = proberCore{p: p}
	if mutate != nil {
		mutate(e)
	}
	return e
}

func TestExamineConfigUsesProber(t *testing.T) {
	p := &stubProber{res: protocol.ProbeResult{
		ConnectTime: 20 * time.Millisecond,
		TTFB:        50 * time.Millisecond,
		Delay:       80 * time.Millisecond,
		Detail:      "faketls, dc2 resPQ ok",
	}}
	e := newProbeExaminer(t, p, func(e *Examiner) { e.BindInterface = "eth-test" })

	r, err := e.ExamineConfig(context.Background(), probeLink)
	if err != nil {
		t.Fatal(err)
	}
	if r.Status != "passed" || r.Delay != 80 || r.ConnectTime != 20 || r.TTFB != 50 || r.Reason != "faketls, dc2 resPQ ok" {
		t.Errorf("result = %+v", r)
	}
	if r.HTTPCode != -1 || r.DownloadSpeed != 0 || r.UploadSpeed != 0 || r.RealIPAddr != "null" || r.IpAddrLoc != "null" {
		t.Errorf("HTTP-only fields must keep their defaults: %+v", r)
	}
	if r.SuccessCount != 1 || r.TotalCount != 1 {
		t.Errorf("counts = %d/%d, want 1/1", r.SuccessCount, r.TotalCount)
	}
	if r.ProtocolInfo.Protocol != "mtproto" || r.TLS != "faketls" || r.ConfigLink != probeLink {
		t.Errorf("protocol info = %+v, tls = %q, link = %q", r.ProtocolInfo, r.TLS, r.ConfigLink)
	}
	if p.opts.Timeout != 2500*time.Millisecond || p.opts.BindInterface != "eth-test" {
		t.Errorf("probe options = %+v", p.opts)
	}
}

func TestExamineConfigProberTimeout(t *testing.T) {
	p := &stubProber{res: protocol.ProbeResult{Delay: 1500 * time.Millisecond, Detail: "secured, dc2 resPQ ok"}}
	e := newProbeExaminer(t, p, nil) // MaxDelay is 1000 ms

	r, err := e.ExamineConfig(context.Background(), probeLink)
	if err == nil {
		t.Fatal("expected an error for a slow probe")
	}
	if r.Status != "timeout" || r.Reason != "config delay is more than the maximum allowed delay" || r.Delay != 1500 || r.SuccessCount != 0 || r.TotalCount != 1 {
		t.Errorf("result = %+v", r)
	}
}

func TestExamineConfigProberFailure(t *testing.T) {
	probeErr := errors.New("faketls: server digest mismatch (wrong secret or cloak domain answered)")
	p := &stubProber{err: probeErr}
	e := newProbeExaminer(t, p, nil)

	r, err := e.ExamineConfig(context.Background(), probeLink)
	if !errors.Is(err, probeErr) {
		t.Fatalf("err = %v, want the probe error", err)
	}
	if r.Status != "failed" || r.Reason != probeErr.Error() || r.Delay != FailedDelay {
		t.Errorf("result = %+v", r)
	}
}

func TestExamineConfigProberNotesSkippedSpeedtest(t *testing.T) {
	p := &stubProber{res: protocol.ProbeResult{Delay: 10 * time.Millisecond, Detail: "simple, dc2 resPQ ok"}}
	e := newProbeExaminer(t, p, func(e *Examiner) { e.DoSpeedtest = true; e.DoIPInfo = true })

	r, err := e.ExamineConfig(context.Background(), probeLink)
	if err != nil {
		t.Fatal(err)
	}
	want := "simple, dc2 resPQ ok; speedtest and ip lookup not applicable to mtproto"
	if r.Status != "passed" || r.Reason != want {
		t.Errorf("status = %q reason = %q, want passed / %q", r.Status, r.Reason, want)
	}
}

func TestExamineConfigWithRetriesStopsOnPassedProbe(t *testing.T) {
	p := &stubProber{res: protocol.ProbeResult{Delay: 30 * time.Millisecond, Detail: "simple, dc2 resPQ ok"}}
	e := newProbeExaminer(t, p, func(e *Examiner) { e.Retries = 2 })
	r, err := e.ExamineConfigWithRetries(context.Background(), probeLink)
	if err != nil || r.Status != "passed" || r.Delay != 30 || p.calls != 1 {
		t.Fatalf("result = %+v, err = %v", r, err)
	}
}
```

Append a retry test that sets `failFirst=true`, `Retries=2`, and a successful scripted result. Assert `Status="passed"`, the successful delay and reason, and `p.calls==2`. Add an all-fail case asserting `1+Retries` attempts, plus a canceled-context case asserting no additional retries. The current retry policy stops at the first pass; it does not measure every attempt to find the fastest successful one.

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./pkg/http/ -run 'Prober|Probe' -v`
Expected: FAIL with the explicit unexpected-HTTP-path sentinel from `proberCore.MakeHttpClient`. Do not rely on a nil-client panic as the failing assertion.

- [ ] **Step 3: Implement the probe path**

Create `pkg/http/probe.go`:

```go
package http

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/lilendian0x00/xray-knife/v11/pkg/core/protocol"
)

// examineProbe grades a protocol that verifies reachability natively instead
// of carrying HTTP (see protocol.Prober). It follows the single-endpoint HTTP
// contract: "passed" within MaxDelay, "timeout" above it, "failed" on error,
// with the same error returns so retries and callers behave identically.
func (e *Examiner) examineProbe(ctx context.Context, r Result, p protocol.Prober) (Result, error) {
	r.TotalCount = 1
	pr, err := p.Probe(ctx, protocol.ProbeOptions{
		Timeout:       time.Duration(e.Timeout) * time.Millisecond,
		BindInterface: e.BindInterface,
	})
	if err != nil {
		r.Status = "failed"
		r.Reason = err.Error()
		return r, err
	}

	r.Delay = pr.Delay.Milliseconds()
	r.ConnectTime = pr.ConnectTime.Milliseconds()
	r.TTFB = pr.TTFB.Milliseconds()
	r.Reason = pr.Detail
	if r.Delay > int64(e.MaxDelay) {
		r.Status = "timeout"
		r.Reason = "config delay is more than the maximum allowed delay"
		return r, errors.New(r.Reason)
	}
	r.Status = "passed"
	r.SuccessCount = 1
	if e.DoSpeedtest || e.DoIPInfo {
		// There is no HTTP path through this kind of proxy, so the fields stay
		// at their defaults; say so instead of failing silently.
		r.appendReason(fmt.Sprintf("speedtest and ip lookup not applicable to %s", r.ProtocolInfo.Protocol))
	}
	return r, nil
}
```

In `pkg/http/examiner.go`, inside `ExamineConfig`, directly after the line `r.TLS = generalConfig.TLS` and before the `MakeHttpClient` call, insert:

```go
	// Protocols that cannot carry HTTP (MTProto proxies) grade themselves.
	if prober, ok := proto.(protocol.Prober); ok {
		return e.examineProbe(ctx, r, prober)
	}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./pkg/http/ -v -run 'Prober|Probe|Grade|Dedup'`
Expected: all `PASS`. The existing grade tests must be unaffected because `stubProtocol` does not implement `Prober`.

- [ ] **Step 5: Commit**

```bash
git add pkg/http/probe.go pkg/http/probe_test.go pkg/http/examiner.go
git commit -m "http: grade Prober protocols without an HTTP client"
```

---

### Task 12: Ping mode for Prober protocols

**Files:**
- Modify: `cmd/http/http.go:244-313` (`handlePingMode`)

**Interfaces:**
- Consumes: `protocol.Prober`, `protocol.ProbeOptions` (Task 1); `Examiner.BindInterface`.

There is no unit test for `handlePingMode` today (it loops on a ticker until Ctrl+C), so this task is verified by running the binary against the fake proxy pattern: a closed port must produce `Request failed: dial …` lines rather than an HTTP client error.

- [ ] **Step 1: Add the import**

In `cmd/http/http.go` add to the imports:

```go
	"github.com/lilendian0x00/xray-knife/v11/pkg/core/protocol"
```

- [ ] **Step 2: Replace the client setup with a `measure` closure**

In `handlePingMode`, replace this block:

```go
	// Create HTTP client and instance ONCE before the ticker loop
	timeout := time.Duration(config.Timeout) * time.Millisecond
	if timeout == 0 {
		timeout = time.Duration(config.MaximumAllowedDelay) * time.Millisecond
	}
	client, instance, err := examiner.Core.MakeHttpClient(ctx, pinger, timeout)
	if err != nil {
		return fmt.Errorf("failed to create HTTP client: %w", err)
	}
	defer instance.Close()
```

with:

```go
	timeout := time.Duration(config.Timeout) * time.Millisecond
	if timeout == 0 {
		timeout = time.Duration(config.MaximumAllowedDelay) * time.Millisecond
	}

	// measure performs one ping and returns its latency in milliseconds.
	var measure func() (int64, error)
	if prober, ok := pinger.(protocol.Prober); ok {
		// Protocols without an HTTP path (MTProto) probe natively on every tick.
		opts := protocol.ProbeOptions{Timeout: timeout, BindInterface: examiner.BindInterface}
		measure = func() (int64, error) {
			res, err := prober.Probe(ctx, opts)
			if err != nil {
				return 0, err
			}
			return res.Delay.Milliseconds(), nil
		}
	} else {
		// Create HTTP client and instance ONCE before the ticker loop
		client, instance, err := examiner.Core.MakeHttpClient(ctx, pinger, timeout)
		if err != nil {
			return fmt.Errorf("failed to create HTTP client: %w", err)
		}
		defer instance.Close()
		measure = func() (int64, error) {
			delay, _, _, err := pkghttp.MeasureDelay(ctx, client, config.DestURL, config.HTTPMethod)
			return delay, err
		}
	}
```

- [ ] **Step 3: Use the closure in the loop**

In the `case <-ticker.C:` branch replace:

```go
			delay, _, _, err := pkghttp.MeasureDelay(ctx, client, config.DestURL, config.HTTPMethod)
```

with:

```go
			delay, err := measure()
```

- [ ] **Step 4: Build and smoke-test**

Run: `go build ./... && go vet ./cmd/...`
Expected: clean.

Build first, then run for 3 seconds against a confirmed closed loopback port (compilation must not consume the observation window):

```bash
go build -o /tmp/xray-knife-mtproto-review .
timeout --signal=INT 3 /tmp/xray-knife-mtproto-review http --ping -c 'tg://proxy?server=127.0.0.1&port=9&secret=00112233445566778899aabbccddeeff'
```

The timeout utility normally exits 124 after stopping the command; inspect its output and distinguish that expected exit from an application failure.

Expected: lines of the form `Request failed: dial 127.0.0.1:9: … connection refused`, then the `ping statistics` footer. No `failed to create HTTP client` error. (`timeout` is GNU coreutils; on macOS use `gtimeout` or press Ctrl+C.)

- [ ] **Step 5: Commit**

```bash
git add cmd/http/http.go
git commit -m "http: ping Prober protocols natively"
```

---

### Task 13: `net tcp` accepts every protocol the automatic core knows

**Files:**
- Modify: `cmd/net/tcp.go`

- [ ] **Step 1: Switch the core**

Replace the import `"github.com/lilendian0x00/xray-knife/v11/pkg/core/xray"` with `"github.com/lilendian0x00/xray-knife/v11/pkg/core"`, and in `RunE` replace:

```go
			x := xray.NewXrayService(false, false)
```
```go
			parsed, err := x.CreateProtocol(cfg.configLink)
```

with:

```go
			c := core.NewAutomaticCore(false, false)
```
```go
			parsed, err := c.CreateProtocol(cfg.configLink)
```

Before `generalDetails := parsed.ConvertToGeneralConfig()`, add the missing parse call:

```go
			if err := parsed.Parse(); err != nil {
				return fmt.Errorf("couldn't parse the config: %w", err)
			}
```

Replace `generalDetails.Address + ":" + generalDetails.Port` with `net.JoinHostPort(generalDetails.Address, generalDetails.Port)` so IPv6 endpoints work. `CreateProtocol` only constructs a parser; it does not populate the endpoint.

Add `cmd/net/tcp_test.go`: execute `newTcpCommand()` against a loopback listener using a valid MTProto link, assert success; malformed secret must fail before dialing. Also cover IPv6 loopback when available (skip if `::1` cannot bind).

Also change the flag help text from `"The xray config link"` to `"The config link (any supported protocol, including tg://proxy)"`.

- [ ] **Step 2: Build and smoke-test**

Run: `go build ./... && go vet ./cmd/net/`
Expected: clean.

Run, with any TCP listener on a known local port (for example `python3 -m http.server 8099 &`):

```bash
go run . net tcp -c 'tg://proxy?server=127.0.0.1&port=8099&secret=00112233445566778899aabbccddeeff'
```

Expected: `Established TCP connection in Nms`. Kill the listener afterwards.

- [ ] **Step 3: Commit**

```bash
git add cmd/net/tcp.go cmd/net/tcp_test.go
git commit -m "net: resolve tcp targets through the automatic core"
```

---

### Task 14: Outbound cores and chains refuse MTProto links

**Files:**
- Modify: `pkg/proxy/chain.go` (`resolveFixedChain`, `selectChainFromPool`, `selectExitHopFromPool`)
- Modify: `pkg/core/xray/protocol.go`, `pkg/core/singbox/protocol.go` (`CreateProtocol`)
- Test: `pkg/core/factory_test.go` (explicit-core sentinel assertions)
- Test: `pkg/proxy/chain_test.go` (new)

**Interfaces:**
- Consumes: `protocol.MTProtoIdentifier` (Task 1), `core.NewAutomaticCore` (Task 9 routing).
- Uses `mtproto.IsProxyLink` before core-specific parsing. `pkg/proxy.Service` constructs explicit xray/sing-box cores, so a post-parse MTProto type check alone never runs in production.

- [ ] **Step 1: Write the failing tests**

Create `pkg/proxy/chain_test.go`:

```go
package proxy

import (
	"strings"
	"testing"

	"github.com/lilendian0x00/xray-knife/v11/pkg/core"
)

const (
	chainVless   = "vless://11111111-1111-1111-1111-111111111111@1.2.3.4:443?encryption=none&security=tls&type=tcp#a"
	chainTrojan  = "trojan://password@5.6.7.8:443?security=tls&type=tcp#b"
	chainTrojan2 = "trojan://password@7.7.7.7:443?security=tls&type=tcp#c"
	chainMTProto = "tg://proxy?server=9.9.9.9&port=443&secret=dd00112233445566778899aabbccddeeff"
)

func TestResolveFixedChainRejectsMTProto(t *testing.T) {
	c := core.NewAutomaticCore(false, false)
	_, err := resolveFixedChain(c, chainVless+"|"+chainMTProto, "")
	if err == nil || !strings.Contains(err.Error(), "chain hop 1: mtproto cannot be a chain hop: it only relays Telegram traffic") {
		t.Fatalf("err = %v", err)
	}
	hops, err := resolveFixedChain(c, chainVless+"|"+chainTrojan, "")
	if err != nil || len(hops) != 2 {
		t.Fatalf("valid chain: err = %v, hops = %d", err, len(hops))
	}
}

func TestSelectChainFromPoolSkipsMTProto(t *testing.T) {
	c := core.NewAutomaticCore(false, false)
	for i := 0; i < 20; i++ { // the pool is shuffled; run enough times to hit every order
		hops, err := selectChainFromPool(c, []string{chainMTProto, chainVless, chainMTProto, chainTrojan}, 2)
		if err != nil {
			t.Fatal(err)
		}
		for _, h := range hops {
			if h.ConvertToGeneralConfig().Protocol == "mtproto" {
				t.Fatal("mtproto hop selected from pool")
			}
		}
	}
	if _, err := selectChainFromPool(c, []string{chainMTProto, chainMTProto, chainVless}, 2); err == nil {
		t.Fatal("a pool with one usable hop must not produce a 2-hop chain")
	}
}

func TestSelectExitHopFromPoolSkipsMTProto(t *testing.T) {
	c := core.NewAutomaticCore(false, false)
	fixed, err := resolveFixedChain(c, chainVless+"|"+chainTrojan, "")
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 20; i++ {
		chain, err := selectExitHopFromPool(c, []string{chainMTProto, chainTrojan2}, fixed[:1], "")
		if err != nil {
			t.Fatal(err)
		}
		if exit := chain[len(chain)-1].ConvertToGeneralConfig(); exit.Protocol != "trojan" || exit.Address != "7.7.7.7" {
			t.Fatalf("exit hop = %+v", exit)
		}
	}
	if _, err := selectExitHopFromPool(c, []string{chainMTProto}, fixed[:1], ""); err == nil {
		t.Fatal("a pool of only mtproto links must not yield an exit hop")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./pkg/proxy/ -run 'Chain|Pool' -v`
Expected: the automatic-core fixed-chain test accepts an unsupported hop; explicit-core tests return a generic parse error instead of the chain-specific reason. MTProto-only/insufficient-usable-pool cases expose the missing skip behavior without relying on random order.

- [ ] **Step 3: Implement**

Add `"github.com/lilendian0x00/xray-knife/v11/pkg/core/mtproto"` to both explicit core parser files. At the beginning of each `CreateProtocol`, after trimming the link and before scheme dispatch, add:

```go
	if mtproto.IsProxyLink(configLink) {
		return nil, mtproto.ErrNotProxyable
	}
```

Both explicit cores still reject these links; now single-outbound proxy/tun, rotation and scanner callers receive a useful reason at `CreateProtocol`, before `MakeInstance` or `MakeHttpClient`. Extend `TestExplicitCoresStillRejectMTProto` to require `errors.Is(err, mtproto.ErrNotProxyable)` for both `tg://` and `https://t.me/proxy` links. Confirm through caller tests that the scanner and proxy service preserve the wrapped reason. Do not change the selected outbound engine to the automatic core.

In `pkg/proxy/chain.go`, import `mtproto`. In `resolveFixedChain`, after trimming/skipping an empty link and **before** `c.CreateProtocol(link)`, add:

```go
		if mtproto.IsProxyLink(link) {
			return nil, fmt.Errorf("chain hop %d: mtproto cannot be a chain hop: it only relays Telegram traffic", i)
		}
```

In `selectChainFromPool` and `selectExitHopFromPool`, before each `c.CreateProtocol(link)`, add:

```go
		if mtproto.IsProxyLink(link) {
			continue
		}
```

Run the chain test cases above with **each** of `core.NewAutomaticCore`, explicit xray and explicit sing-box cores. The explicit cores are what the service actually uses. Include MTProto-only pools and the mixed pool containing fewer usable links than requested; these make skip coverage deterministic instead of relying on 20 random shuffles.

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./pkg/proxy/ -run 'Chain|Pool' -v`
Expected: 3 tests `PASS`.

- [ ] **Step 5: Commit**

```bash
git add pkg/proxy/chain.go pkg/proxy/chain_test.go pkg/core/xray/protocol.go pkg/core/singbox/protocol.go pkg/core/factory_test.go
git commit -m "proxy: refuse MTProto hops in chains"
```

---

### Task 15: Docs and final verification

**Files:**
- Modify: `README.md:32`
- Modify: `docs/zh_README.md:32`
- Modify: `docs/superpowers/specs/2026-09-15-mtproto-testing-design.md` (status line after completion)
- Test: `pkg/http/prescan_test.go`, `pkg/subscription/subscription_test.go`, `cmd/subs/fetch_test.go`, and result persistence/serialization tests in `pkg/http`
- Test: `pkg/core/mtproto` cancellation, nonce-mismatch and fragmented/short-I/O cases; web HTTP-test flow

- [ ] **Step 1: README**

In `README.md`, directly below the line 32 bullet (`**🚀 Dual-Core Engine**`), add a new bullet:

```markdown
- **✈️ MTProto Proxy Testing**: Tests Telegram `tg://proxy` and `t.me/proxy` links natively (obfuscated2 and fake-TLS secrets) with a real MTProto round trip, so `http` reports them alongside your other configs. MTProto proxies only relay Telegram traffic, so they are test-only and cannot be used as an outbound.
```

In `docs/zh_README.md` add below line 32:

```markdown
- **✈️ MTProto 代理测试**: 原生测试 Telegram `tg://proxy` 与 `t.me/proxy` 链接（支持 obfuscated2 和 fake-TLS 密钥），通过真实的 MTProto 往返验证可用性，`http` 命令会与其他配置一并输出结果。MTProto 代理仅转发 Telegram 流量，因此只能测试，不能作为出口使用。
```

After all implementation and verification steps pass, replace the spec’s current `Status:` line with `Status: implemented`. A plan review leaves it in draft.

- [ ] **Step 2: Integration coverage and full verification**

Add offline integration assertions beyond the package-local probe:

- `pkg/http/prescan_test.go`: MTProto endpoints are parsed as TCP (including IPv6), equivalent links share one endpoint, and malformed links are bypassed for examiner grading.
- `pkg/subscription/subscription_test.go` and `cmd/subs/fetch_test.go`: plain and base64 subscriptions preserve both link forms; parsed DB rows use `protocol="mtproto"` and the normalized fingerprint. Test `--protocol mtproto` selection with a temporary database.
- `pkg/http`: save/reload a native-probe result through the existing DB writer; JSON and CSV retain status, reason and timings, with HTTP/IP/speed defaults. Never use the user's real database.
- Web: submit an MTProto link to the HTTP testing flow against a local fake endpoint; verify protocol badge, status/reason, timing columns and unmeasured-speed display. Use a stub or failed local probe for this path; a live Telegram proxy is not required.
- Cancellation: use server synchronization channels to cancel during fake-TLS handshake and response reads for all three secret types. Assert prompt return and `errors.Is(err, context.Canceled)`, separately from deadline expiry. Add a wrong-nonce fake-server mode and verify rejection.
- I/O: test readers that fragment headers/payloads and writers that return short writes. Every write helper must fail with `io.ErrShortWrite` when `n < len(p)` and `err == nil`; do not silently report handshake/frame success after partial writes.

Only mark the spec `Status: implemented` after implementation and the relevant checks pass; leave it in draft during a plan review.


Run each and confirm the expected output:

```bash
gofmt -l ./pkg ./cmd                      # expected: no output
go vet ./...                              # expected: clean
go build ./...                            # expected: success
go mod tidy -diff                         # expected: no output (no new modules)
go test -race ./pkg/core/... ./pkg/http/ ./pkg/proxy/ ./pkg/subscription/ ./cmd/...
```

Expected: all new tests pass. Record any existing failures and reproduce them on the same base revision in a separate temporary checkout before classifying them as pre-existing. Do not stash or alter unrelated user changes. Unset `XRAY_KNIFE_MTPROTO_LINK` for offline verification; run the live check separately. Compare module/format checks against the pre-implementation baseline if it was already dirty.

End-to-end smoke test against a closed port (must grade as `failed` with a dial reason, not `broken`):

```bash
go run . http -c 'tg://proxy?server=127.0.0.1&port=9&secret=00112233445566778899aabbccddeeff'
```

Expected output includes the protocol details (Protocol `mtproto`, Secret Type `simple`) and a dial failure starting with `dial 127.0.0.1:9`. The single-config CLI prints the returned error, not a status row; assert `Status="failed"` in the examiner test or inspect saved batch results.

Semantic dedup smoke test, two spellings of one proxy:

```bash
printf 'tg://proxy?server=127.0.0.1&port=9&secret=dd00112233445566778899aabbccddeeff\nhttps://t.me/proxy?server=127.0.0.1&port=9&secret=3QARIjNEVWZ3iJmqu8zd7v8\n' > /tmp/mt.txt
go run . http -f /tmp/mt.txt
```

Expected: a log line `Semantic dedup removed 1 duplicate config link(s)` and one result.

Optional live check when a real proxy link is at hand:

```bash
XRAY_KNIFE_MTPROTO_LINK='tg://proxy?server=…&port=…&secret=…' go test ./pkg/core/mtproto/ -run TestProbeLiveProxy -v
```

Expected: `PASS` with a log line such as `faketls, dc2 resPQ ok connect=… ttfb=… delay=…`.

- [ ] **Step 3: Commit**

```bash
# Stage only the integration test files created/edited by this task, after reviewing their diffs.
git add README.md docs/zh_README.md docs/superpowers/specs/2026-09-15-mtproto-testing-design.md
git commit -m "docs: describe MTProto proxy testing"
```

---

## Self-review notes

Spec coverage, by spec section:

| Spec section | Task |
|---|---|
| Link and secret parsing | 2, 3 |
| Probe algorithm (dial, handshakes, req_pq_multi, resPQ, timings) | 4, 5, 6, 7 |
| `pkg/core/mtproto` files and `LICENSE.gotd` | 2–8 (LICENSE in 4) |
| `pkg/core/protocol` additions | 1 |
| `pkg/core/factory.go` routing, explicit cores keep rejecting | 9 |
| `pkg/http` probe branch, statuses, speedtest note, ping mode | 11, 12 |
| `pkg/core/identity.go` | 10 |
| Prescan, subscription, DB, web UI | explicit integration coverage in Task 15; the dedup smoke test alone does not cover these paths |
| `pkg/proxy` chain rejection | 14 |
| `cmd/net/tcp.go` | 13 |
| Docs | 15 |
| Testing: offline fake proxy, env-gated live test | 7 |

Type consistency checklist: `Secret.Hex()`, `SecretType.String()`, `paddedIntermediateTag`, `obfsInitLen`, `clientStreams`, `serverStreams` (test-only), `rwPair` (test-only), `helloRandomOffset`, `helloRandomLen`, `tlsRecord`, `readRecord`, `writeRecord`, `buildServerHelloFlight` (test-only), `writePaddedFrame`, `readPaddedFrame`, `reqPQMultiLen`, `buildResPQ` (test-only), `TransportError`, `stageErr`, `timedConn`, `ErrNotProxyable`, `IsProxyLink`, `examineProbe` must remain signature-consistent as the additional cases above are implemented.


## Review corrections (2026-09-15)

- Fix the impossible clear-prefix decryption assertion; require an independent wire vector.
- Preserve 0–15 transport padding bytes until message decoding; validate the complete `resPQ` envelope and TL fields, including length and vector bounds.
- Include fractional time in client message IDs; retain cancellation identity separately from timeout errors.
- Normalize decimal ports, reject malformed/duplicate required query parameters, and preserve unknown fingerprint options.
- Parse `net tcp` links before reading endpoints and use IPv6-safe address construction.
- Reject MTProto before explicit-core parsing in outbound/chain paths; test the engines the service actually uses.
- Replace the nil HTTP-client failure with an explicit sentinel and test the real stop-on-first-pass retry policy.
- Add missing persistence, subscription, prescan, web, cancellation and malformed-wire coverage; correct smoke-test expectations and preserve unrelated working-tree changes.

Wire references: [Telegram transports](https://core.telegram.org/mtproto/mtproto-transports), [message identifiers](https://core.telegram.org/mtproto/description#message-identifier-msg-id), [authorization handshake](https://core.telegram.org/mtproto/auth_key), [gotd fake-TLS client](https://github.com/gotd/td/blob/v0.161.0/mtproxy/faketls/client_hello.go), [gotd fake-TLS server verification](https://github.com/gotd/td/blob/v0.161.0/mtproxy/faketls/server_hello.go). A matching unencrypted `resPQ` is a reachability check, not proof of Telegram identity or reachability to every DC.
