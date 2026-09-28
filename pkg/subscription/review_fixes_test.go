package subscription

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Scalars keep their source text: yaml.v3 alone reads 0123 as 123 and
// 00000000 as 0.
func TestClashScalarsKeepText(t *testing.T) {
	doc := `proxies:
  - {name: a, type: trojan, server: example.com, port: 443, password: 0123}
  - {name: b, type: ss, server: example.com, port: 8388, cipher: aes-128-gcm, password: 1.10}
  - name: c
    type: vless
    server: example.com
    port: 443
    uuid: 5f0c4b4e-0000-4000-8000-000000000000
    tls: true
    servername: www.example.com
    reality-opts: {public-key: abc, short-id: 00000000}
  - {name: d, type: trojan, server: example.com, port: 443, password: 123456789012345678901234}
`
	res, err := DecodeDetailed([]byte(doc), DecodeOptions{})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"trojan://0123@", "sid=00000000", "trojan://123456789012345678901234@"} {
		found := false
		for _, l := range res.Links {
			found = found || strings.Contains(l, want)
		}
		if !found {
			t.Errorf("no link contains %q: %v", want, res.Links)
		}
	}
}

func TestClashAliasesAndMerges(t *testing.T) {
	doc := `base: &b {type: ss, server: 1.2.3.4, port: 443, cipher: aes-128-gcm, password: p}
one: &one {name: one, type: socks5, server: 9.9.9.9, port: 1080}
proxies:
  - *one
  - {<<: *b, name: merged, port: 8443}
`
	res, err := DecodeDetailed([]byte(doc), DecodeOptions{})
	if err != nil || len(res.Links) != 2 {
		t.Fatalf("%v %+v", err, res)
	}
	if !strings.Contains(res.Links[1], "@1.2.3.4:8443") {
		t.Errorf("merge key: own port must win over the merged one: %s", res.Links[1])
	}

	// An alias bomb under proxies stops at the node budget.
	var b strings.Builder
	b.WriteString("a: &a [x, x, x, x, x, x, x, x, x, x]\n")
	prev := "a"
	for i := 0; i < 8; i++ {
		name := fmt.Sprintf("l%d", i)
		fmt.Fprintf(&b, "%s: &%s [*%s, *%s, *%s, *%s, *%s, *%s, *%s, *%s, *%s, *%s]\n", name, name, prev, prev, prev, prev, prev, prev, prev, prev, prev, prev)
		prev = name
	}
	fmt.Fprintf(&b, "proxies: [*%s]\n", prev)
	if _, err := Decode([]byte(b.String()), DecodeOptions{}); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("alias bomb: %v", err)
	}
}

func TestStructuredSizeCap(t *testing.T) {
	var b strings.Builder
	b.WriteString("proxies:\n")
	for b.Len() < 9<<20 {
		b.WriteString("  - {name: n, type: ss, server: 1.2.3.4, port: 443, cipher: aes-128-gcm, password: p}\n")
	}
	if _, err := Decode([]byte(b.String()), DecodeOptions{}); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("9 MiB Clash document: %v, want ErrTooLarge", err)
	}
	small := "proxies:\n  - {name: n, type: socks5, server: 1.2.3.4, port: 1080}\n"
	if _, err := Decode([]byte(small), DecodeOptions{MaxStructuredBytes: 16}); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("custom cap: %v", err)
	}
	if _, err := Decode([]byte(small), DecodeOptions{MaxStructuredBytes: -1}); err == nil {
		t.Fatal("negative cap accepted")
	}
}

func TestXrayFlatCredentialsAndSingboxHopOnly(t *testing.T) {
	doc := `{"outbounds":[
 {"protocol":"socks","tag":"s","settings":{"address":"1.2.3.4","port":1080,"user":"alice","pass":"secret"}},
 {"protocol":"http","tag":"h","settings":{"address":"1.2.3.4","port":8080,"user":"bob","pass":"pw"}}]}`
	res, err := DecodeDetailed([]byte(doc), DecodeOptions{})
	if err != nil || !strings.Contains(res.Links[0], "alice:secret@") || !strings.Contains(res.Links[1], "bob:pw@") {
		t.Fatalf("flat credentials lost: %v %v", err, res)
	}

	sb := `{"outbounds":[{"type":"hysteria2","tag":"hop","server":"example.com","server_ports":["20000:30000"],"password":"pw","tls":{"enabled":true,"server_name":"example.com"}}]}`
	res, err = DecodeDetailed([]byte(sb), DecodeOptions{})
	if err != nil || len(res.Links) != 1 || !strings.Contains(res.Links[0], "@example.com:20000") || !strings.Contains(res.Links[0], "mport=20000-30000") {
		t.Fatalf("hop-only hysteria2: %v %+v", err, res)
	}
}

func TestSkipReasonsSanitizedAndFetchPartial(t *testing.T) {
	doc := "proxies:\n  - {name: x, type: \"ssr\\e[2J\\e]0;pwned\\a\", server: 1.2.3.4, port: 443}\n  - {name: y, type: \"" + strings.Repeat("z", 500) + "\", server: 1.2.3.4, port: 443}\n"
	res, err := DecodeDetailed([]byte(doc), DecodeOptions{})
	if !errors.Is(err, ErrNoSupportedProxies) {
		t.Fatal(err)
	}
	for reason := range res.Skipped {
		if strings.ContainsAny(reason, "\x1b\a") || len(reason) > 200 {
			t.Errorf("unsafe reason %q", reason)
		}
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(doc)) }))
	defer srv.Close()
	fr, err := Fetch(context.Background(), srv.Client(), srv.URL, FetchOptions{})
	if !errors.Is(err, ErrNoSupportedProxies) || fr == nil || fr.Format != FormatClash || len(fr.Skipped) != 2 {
		t.Fatalf("Fetch: %v %+v", err, fr)
	}
}

// mihomo's hysteria "auth" is base64; auth-str is the plain password.
func TestClashHysteriaAuth(t *testing.T) {
	doc := "proxies:\n  - {name: h, type: hysteria, server: h.example.com, port: 443, auth: cGFzc3dvcmQ=, up: 10, down: 50}\n"
	res, err := DecodeDetailed([]byte(doc), DecodeOptions{})
	if err != nil || !strings.Contains(res.Links[0], "auth=password") {
		t.Fatalf("%v %+v", err, res)
	}
}
