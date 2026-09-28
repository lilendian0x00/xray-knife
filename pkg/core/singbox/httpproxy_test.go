package singbox

import (
	"strings"
	"testing"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/auth"
)

func TestIsHTTPProxyLink(t *testing.T) {
	for link, want := range map[string]bool{
		"http://u:p@1.2.3.4:8080#name":                   true,
		"https://u:p@proxy.example.com:443?sni=a.com":    true,
		"http://[2001:db8::1]:3128/":                     true,
		"HTTP://1.2.3.4:80":                              true,
		"https://example.com/sub.txt":                    false, // subscription URL
		"https://t.me/proxy?server=a&port=1&secret=b":    false, // MTProto
		"http://example.com":                             false, // no port: a web page
		"https://sub.example.com:8443/api/v1/client/sub": false,
		"socks://1.2.3.4:1080":                           false,
	} {
		if got := IsHTTPProxyLink(link); got != want {
			t.Errorf("IsHTTPProxyLink(%q) = %v, want %v", link, got, want)
		}
	}
}

func TestHTTPProxyParse(t *testing.T) {
	c := NewSingboxService(false, false)
	h := parseLink(t, c, "https://us%40er:p%3Ass@[2001:db8::1]:8443?peer=a.com&skip-cert-verify=true&fp=chrome#Name 100%").(*HTTPProxy)
	if !h.TLS || h.Username != "us@er" || h.Password != "p:ss" || h.Address != "2001:db8::1" || h.Port != "8443" ||
		h.SNI != "a.com" || !h.Insecure || h.Remark != "Name 100%" {
		t.Fatalf("%+v", h)
	}
	if g := h.ConvertToGeneralConfig(); g.Protocol != "http" || g.TLS != "tls" || g.Address != "2001:db8::1" || g.Port != "8443" {
		t.Fatalf("general config = %+v", g)
	}
	out, err := h.CraftOutboundOptions(false)
	if err != nil {
		t.Fatal(err)
	}
	o := out.Options.(*option.HTTPOutboundOptions)
	if out.Type != C.TypeHTTP || o.Server != "2001:db8::1" || o.TLS == nil || !o.TLS.Enabled || !o.TLS.Insecure || o.TLS.ServerName != "a.com" {
		t.Fatalf("outbound = %+v %+v", out, o.TLS)
	}
	plain := parseLink(t, c, "http://1.2.3.4:3128").(*HTTPProxy)
	if out, _ := plain.CraftOutboundOptions(false); out.Options.(*option.HTTPOutboundOptions).TLS != nil {
		t.Fatal("plain http proxy got TLS")
	}
	for _, bad := range []string{"https://example.com/sub.txt", "http://example.com"} {
		p, err := c.CreateProtocol(bad)
		if err != nil {
			continue
		}
		if err := p.Parse(); err == nil || !strings.Contains(err.Error(), "not an http(s) proxy link") {
			t.Errorf("%s: err = %v", bad, err)
		}
	}
}

func TestEndToEndHTTPProxy(t *testing.T) {
	skipUnderRace(t)
	target := startTarget(t)
	users := []auth.User{{Username: "u@x", Password: "p:w"}}

	port := freePort(t)
	startServer(t, option.Inbound{Type: C.TypeHTTP, Options: &option.HTTPMixedInboundOptions{
		ListenOptions: loopbackListen(port), Users: users,
	}})
	fetchThrough(t, NewSingboxService(false, false), "http://u%40x:p%3Aw@127.0.0.1:"+port+"#plain", target)

	tlsPort := freePort(t)
	startServer(t, option.Inbound{Type: C.TypeHTTP, Options: &option.HTTPMixedInboundOptions{
		ListenOptions: loopbackListen(tlsPort), Users: users, InboundTLSOptionsContainer: serverTLS(t),
	}})
	fetchThrough(t, NewSingboxService(false, false), "https://u%40x:p%3Aw@127.0.0.1:"+tlsPort+"?sni=example.com&insecure=1#tls", target)
}
