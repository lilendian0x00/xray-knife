package subscription

import (
	"encoding/base64"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/lilendian0x00/xray-knife/v11/pkg/core"
	"github.com/lilendian0x00/xray-knife/v11/pkg/core/protocol"
)

const (
	uuid1 = "11111111-1111-1111-1111-111111111111"
	wgKey = "aa+bb/cc=="
	wgPub = "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo="
)

const clashFixture = `mixed-port: 7890
allow-lan: false
proxies:
  - name: vmess-ws
    type: vmess
    server: v.example.com
    port: 443
    uuid: ` + uuid1 + `
    alterId: 0
    cipher: auto
    tls: true
    servername: sni.example.com
    network: ws
    ws-opts:
      path: /ws
      headers:
        Host: cdn.example.com
  - name: vless-reality
    type: vless
    server: 1.2.3.4
    port: 443
    uuid: ` + uuid1 + `
    flow: xtls-rprx-vision
    network: tcp
    tls: true
    servername: www.microsoft.com
    client-fingerprint: chrome
    reality-opts:
      public-key: PBK
      short-id: abcd
  - name: trojan-grpc
    type: trojan
    server: t.example.com
    port: 443
    password: "p@ss:word"
    sni: t.example.com
    network: grpc
    grpc-opts:
      grpc-service-name: svc
    skip-cert-verify: true
  - {name: ss-obfs, type: ss, server: 5.6.7.8, port: 8388, cipher: aes-256-gcm, password: secret, plugin: obfs, plugin-opts: {mode: http, host: bing.com}}
  - {name: ss2022, type: ss, server: "2001:db8::1", port: 443, cipher: 2022-blake3-aes-128-gcm, password: "YWJj+ZGVm/Zw=="}
  - name: hy2
    type: hysteria2
    server: h.example.com
    port: 443
    password: hy2pass
    obfs: salamander
    obfs-password: obfspw
    ports: 20000-30000
    sni: h.example.com
    skip-cert-verify: true
  - {name: tuic, type: tuic, server: q.example.com, port: 443, uuid: ` + uuid1 + `, password: tpw, alpn: [h3], congestion-controller: bbr, udp-relay-mode: native, sni: q.example.com}
  - {name: anytls, type: anytls, server: a.example.com, port: 443, password: apw, sni: a.example.com, skip-cert-verify: true}
  - name: wg
    type: wireguard
    server: 162.159.192.1
    port: 2408
    ip: 172.16.0.2
    ipv6: fd01::2
    private-key: "` + wgKey + `"
    public-key: "` + wgPub + `"
    reserved: [1, 2, 3]
    mtu: 1280
  - {name: socks, type: socks5, server: 9.9.9.9, port: 1080, username: u, password: p}
  - {name: http, type: http, server: 8.8.8.8, port: 8080, username: u, password: p, tls: true}
  - {name: hysteria-v1, type: hysteria, server: h1.example.com, port: 443, auth-str: pw, up: "30 Mbps", down: 100, sni: h1.example.com, obfs: xobfs}
  - {name: ssh, type: ssh, server: s.example.com, port: 2222, username: u, password: p, host-key: ["ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl"]}
  - {name: ssr, type: ssr, server: 1.1.1.1, port: 1, cipher: none, password: x, protocol: origin, obfs: plain}
  - {name: snell, type: snell, server: 1.1.1.1, port: 1, psk: x}
  - {name: shadowtls, type: ss, server: 1.1.1.1, port: 1, cipher: aes-128-gcm, password: x, plugin: shadow-tls}
  - {name: DIRECT, type: direct}
proxy-groups:
  - {name: auto, type: url-test, proxies: [vmess-ws], url: "http://www.gstatic.com/generate_204", interval: 300}
rules:
  - MATCH,auto
`

const singboxFixture = `{
  "log": {"level": "warn"},
  "dns": {"servers": [{"type": "https", "server": "1.1.1.1"}]},
  "outbounds": [
    {"type": "selector", "tag": "proxy", "outbounds": ["sb-vless"]},
    {"type": "vless", "tag": "sb-vless", "server": "1.2.3.4", "server_port": 443, "uuid": "` + uuid1 + `", "flow": "xtls-rprx-vision",
     "tls": {"enabled": true, "server_name": "www.microsoft.com", "utls": {"enabled": true, "fingerprint": "chrome"}, "reality": {"enabled": true, "public_key": "PBK", "short_id": "ab"}}},
    {"type": "vmess", "tag": "sb-vmess", "server": "v.example.com", "server_port": 443, "uuid": "` + uuid1 + `", "security": "auto", "alter_id": 0,
     "tls": {"enabled": true, "server_name": "v.example.com"}, "transport": {"type": "ws", "path": "/ws", "headers": {"Host": "cdn.example.com"}}},
    {"type": "trojan", "tag": "sb-trojan", "server": "t.example.com", "server_port": 443, "password": "pw",
     "tls": {"enabled": true, "server_name": "t.example.com", "insecure": true}, "transport": {"type": "grpc", "service_name": "svc"}},
    {"type": "shadowsocks", "tag": "sb-ss", "server": "5.6.7.8", "server_port": 8388, "method": "chacha20-ietf-poly1305", "password": "pw", "plugin": "obfs-local", "plugin_opts": "obfs=http;obfs-host=bing.com"},
    {"type": "hysteria2", "tag": "sb-hy2", "server": "h.example.com", "server_port": 443, "server_ports": ["20000:30000"], "password": "pw",
     "obfs": {"type": "salamander", "password": "op"}, "tls": {"enabled": true, "server_name": "h.example.com", "alpn": ["h3"]}},
    {"type": "tuic", "tag": "sb-tuic", "server": "q.example.com", "server_port": 443, "uuid": "` + uuid1 + `", "password": "pw",
     "congestion_control": "bbr", "udp_relay_mode": "native", "tls": {"enabled": true, "server_name": "q.example.com", "alpn": ["h3"]}},
    {"type": "anytls", "tag": "sb-anytls", "server": "a.example.com", "server_port": 443, "password": "pw", "tls": {"enabled": true, "server_name": "a.example.com"}},
    {"type": "socks", "tag": "sb-socks", "server": "9.9.9.9", "server_port": 1080, "version": "5", "username": "u", "password": "p"},
    {"type": "ssh", "tag": "sb-ssh", "server": "s.example.com", "server_port": 22, "user": "u", "password": "p", "host_key": ["ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl"]},
    {"type": "shadowtls", "tag": "sb-stls", "server": "1.1.1.1", "server_port": 443, "version": 3, "password": "x"},
    {"type": "direct", "tag": "direct"}
  ],
  "endpoints": [
    {"type": "wireguard", "tag": "sb-wg", "address": ["172.16.0.2/32"], "private_key": "` + wgKey + `", "mtu": 1280,
     "peers": [{"address": "162.159.192.1", "port": 2408, "public_key": "` + wgPub + `", "allowed_ips": ["0.0.0.0/0"], "reserved": [1, 2, 3]}]}
  ],
  "route": {"final": "proxy"}
}`

const xrayFixture = `{
  "log": {"loglevel": "warning"},
  "inbounds": [{"protocol": "socks", "port": 10808, "listen": "127.0.0.1"}],
  "outbounds": [
    {"protocol": "vless", "tag": "x-vless", "settings": {"vnext": [{"address": "1.2.3.4", "port": 443, "users": [{"id": "` + uuid1 + `", "flow": "xtls-rprx-vision", "encryption": "none"}]}]},
     "streamSettings": {"network": "tcp", "security": "reality", "realitySettings": {"serverName": "www.microsoft.com", "publicKey": "PBK", "shortId": "ab", "fingerprint": "chrome"}}},
    {"protocol": "vmess", "tag": "x-vmess", "settings": {"vnext": [{"address": "v.example.com", "port": 443, "users": [{"id": "` + uuid1 + `", "alterId": 0, "security": "auto"}]}]},
     "streamSettings": {"network": "ws", "security": "tls", "wsSettings": {"path": "/ws", "headers": {"Host": "cdn.example.com"}}, "tlsSettings": {"serverName": "v.example.com"}}},
    {"protocol": "trojan", "tag": "x-trojan", "settings": {"servers": [{"address": "t.example.com", "port": 443, "password": "pw"}]},
     "streamSettings": {"network": "xhttp", "security": "tls", "xhttpSettings": {"path": "/x", "host": "t.example.com", "mode": "auto"}, "tlsSettings": {"serverName": "t.example.com", "alpn": ["h2"]}}},
    {"protocol": "shadowsocks", "tag": "x-ss", "settings": {"servers": [{"address": "5.6.7.8", "port": 8388, "method": "aes-128-gcm", "password": "pw"}]}},
    {"protocol": "socks", "tag": "x-socks", "settings": {"servers": [{"address": "9.9.9.9", "port": 1080, "users": [{"user": "u", "pass": "p"}]}]}},
    {"protocol": "wireguard", "tag": "x-wg", "settings": {"secretKey": "` + wgKey + `", "address": ["172.16.0.2/32"], "peers": [{"endpoint": "162.159.192.1:2408", "publicKey": "` + wgPub + `"}], "reserved": [1, 2, 3]}},
    {"protocol": "hysteria", "tag": "x-hy2", "settings": {"version": 2, "address": "h.example.com", "port": 443},
     "streamSettings": {"network": "hysteria", "security": "tls", "tlsSettings": {"serverName": "h.example.com"}, "hysteriaSettings": {"version": 2, "auth": "pw"},
       "finalmask": {"udp": [{"type": "salamander", "settings": {"password": "op"}}]}}},
    {"protocol": "vless", "tag": "x-flat", "settings": {"address": "2.2.2.2", "port": 80, "id": "` + uuid1 + `"}, "streamSettings": {"network": "grpc", "grpcSettings": {"serviceName": "g", "multiMode": true}}},
    {"protocol": "shadowsocksr", "tag": "x-ssr"},
    {"protocol": "freedom", "tag": "direct"},
    {"protocol": "blackhole", "tag": "block"}
  ]
}`

// parsed parses a link with the automatic core, as testers do.
func parsed(t *testing.T, link string) protocol.Protocol {
	t.Helper()
	c := core.NewAutomaticCore(false, false)
	p, err := c.CreateProtocol(link)
	if err != nil {
		t.Fatalf("CreateProtocol(%s): %v", link, err)
	}
	if err := p.Parse(); err != nil {
		t.Fatalf("Parse(%s): %v", link, err)
	}
	return p
}

func byName(t *testing.T, links []string) map[string]protocol.GeneralConfig {
	t.Helper()
	out := map[string]protocol.GeneralConfig{}
	for _, l := range links {
		g := parsed(t, l).ConvertToGeneralConfig()
		out[g.Remark] = g
	}
	return out
}

func expect(t *testing.T, got map[string]protocol.GeneralConfig, name string, check func(protocol.GeneralConfig) bool) {
	t.Helper()
	g, ok := got[name]
	if !ok {
		t.Errorf("%s: no link produced", name)
		return
	}
	if !check(g) {
		t.Errorf("%s: unexpected fields %+v", name, g)
	}
}

func TestDecodeClash(t *testing.T) {
	for _, body := range []string{clashFixture, base64.StdEncoding.EncodeToString([]byte(clashFixture))} {
		res, err := DecodeDetailed([]byte(body), DecodeOptions{})
		if err != nil {
			t.Fatal(err)
		}
		if res.Format != FormatClash || len(res.Links) != 13 {
			t.Fatalf("format %s, %d links: %v", res.Format, len(res.Links), res.Links)
		}
		wantSkipped := map[string]int{
			"unsupported clash proxy type ssr":          1,
			"unsupported clash proxy type snell":        1,
			"unsupported shadowsocks plugin shadow-tls": 1,
		}
		if !reflect.DeepEqual(res.Skipped, wantSkipped) {
			t.Fatalf("skipped = %v", res.Skipped)
		}
	}

	res, _ := DecodeDetailed([]byte(clashFixture), DecodeOptions{})
	got := byName(t, res.Links)
	expect(t, got, "vmess-ws", func(g protocol.GeneralConfig) bool {
		return g.Protocol == "vmess" && g.Address == "v.example.com" && g.Port == "443" && g.Network == "ws" &&
			g.Path == "/ws" && g.Host == "cdn.example.com" && g.SNI == "sni.example.com" && g.TLS == "tls"
	})
	expect(t, got, "vless-reality", func(g protocol.GeneralConfig) bool {
		return g.Protocol == "vless" && g.Address == "1.2.3.4" && g.TLS == "reality" && g.SNI == "www.microsoft.com"
	})
	expect(t, got, "trojan-grpc", func(g protocol.GeneralConfig) bool {
		return g.Protocol == "trojan" && g.ID == "p@ss:word" && g.ServiceName == "svc" && g.Type == "grpc"
	})
	expect(t, got, "ss2022", func(g protocol.GeneralConfig) bool {
		return g.Address == "2001:db8::1" && g.ID == "YWJj+ZGVm/Zw=="
	})
	expect(t, got, "wg", func(g protocol.GeneralConfig) bool {
		return g.Protocol == "wireguard" && g.Address == "162.159.192.1" && g.Port == "2408"
	})
	expect(t, got, "http", func(g protocol.GeneralConfig) bool {
		return g.Protocol == "http" && g.Address == "8.8.8.8" && g.Port == "8080" && g.TLS == "tls"
	})
	expect(t, got, "ssh", func(g protocol.GeneralConfig) bool {
		return g.Protocol == "ssh" && g.Address == "s.example.com" && g.Port == "2222"
	})
	for _, name := range []string{"ss-obfs", "hy2", "tuic", "anytls", "socks", "hysteria-v1"} {
		expect(t, got, name, func(g protocol.GeneralConfig) bool { return g.Address != "" && g.Port != "" })
	}
	for _, l := range res.Links {
		switch {
		case strings.Contains(l, "#hy2"):
			for _, want := range []string{"obfs=salamander", "obfs-password=obfspw", "mport=20000-30000", "insecure=1"} {
				if !strings.Contains(l, want) {
					t.Errorf("hy2 link %s lacks %s", l, want)
				}
			}
		case strings.Contains(l, "#ss-obfs"):
			if !strings.Contains(l, "plugin=obfs-local%3Bobfs%3Dhttp%3Bobfs-host%3Dbing.com") {
				t.Errorf("ss plugin lost: %s", l)
			}
		case strings.HasPrefix(l, "https://"):
			if l != "https://u:p@8.8.8.8:8080#http" {
				t.Errorf("http proxy link = %s", l)
			}
		}
	}
}

func TestDecodeSingbox(t *testing.T) {
	res, err := DecodeDetailed([]byte(singboxFixture), DecodeOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if res.Format != FormatSingbox || len(res.Links) != 10 {
		t.Fatalf("format %s, %d links: %v", res.Format, len(res.Links), res.Links)
	}
	if !reflect.DeepEqual(res.Skipped, map[string]int{"unsupported sing-box outbound type shadowtls": 1}) {
		t.Fatalf("skipped = %v", res.Skipped)
	}
	got := byName(t, res.Links)
	expect(t, got, "sb-vless", func(g protocol.GeneralConfig) bool { return g.TLS == "reality" && g.SNI == "www.microsoft.com" })
	expect(t, got, "sb-vmess", func(g protocol.GeneralConfig) bool { return g.Network == "ws" && g.Host == "cdn.example.com" })
	expect(t, got, "sb-trojan", func(g protocol.GeneralConfig) bool { return g.ServiceName == "svc" })
	expect(t, got, "sb-wg", func(g protocol.GeneralConfig) bool { return g.Address == "162.159.192.1" && g.Port == "2408" })
	for _, name := range []string{"sb-ss", "sb-hy2", "sb-tuic", "sb-anytls", "sb-socks", "sb-ssh"} {
		expect(t, got, name, func(g protocol.GeneralConfig) bool { return g.Address != "" && g.Port != "" })
	}
}

func TestDecodeXray(t *testing.T) {
	res, err := DecodeDetailed([]byte(xrayFixture), DecodeOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if res.Format != FormatXray || len(res.Links) != 8 {
		t.Fatalf("format %s, %d links: %v", res.Format, len(res.Links), res.Links)
	}
	if !reflect.DeepEqual(res.Skipped, map[string]int{"unsupported xray outbound protocol shadowsocksr": 1}) {
		t.Fatalf("skipped = %v", res.Skipped)
	}
	got := byName(t, res.Links)
	expect(t, got, "x-vless", func(g protocol.GeneralConfig) bool { return g.TLS == "reality" })
	expect(t, got, "x-trojan", func(g protocol.GeneralConfig) bool { return g.Type == "xhttp" && g.Path == "/x" })
	expect(t, got, "x-flat", func(g protocol.GeneralConfig) bool {
		return g.Address == "2.2.2.2" && g.ServiceName == "g" && g.Mode == "multi"
	})
	expect(t, got, "x-hy2", func(g protocol.GeneralConfig) bool { return g.Protocol == "hysteria2" && g.SNI == "h.example.com" })

	// v2rayN "custom config" subscriptions: an array of full configs, each
	// named by "remarks".
	array := `[{"remarks": "DE 1", "outbounds": [{"protocol": "trojan", "settings": {"servers": [{"address": "t.example.com", "port": 443, "password": "pw"}]},
	  "streamSettings": {"security": "tls", "tlsSettings": {"serverName": "t.example.com"}}}, {"protocol": "freedom"}]},
	 {"remarks": "US 2", "outbounds": [{"protocol": "shadowsocks", "settings": {"servers": [{"address": "5.6.7.8", "port": 1, "method": "aes-128-gcm", "password": "pw"}]}}]}]`
	res, err = DecodeDetailed([]byte(array), DecodeOptions{})
	if err != nil || res.Format != FormatXray || len(res.Links) != 2 {
		t.Fatalf("array: %v, %+v", err, res)
	}
	names := byName(t, res.Links)
	if _, ok := names["DE 1"]; !ok {
		t.Errorf("remarks not used as names: %v", res.Links)
	}
}

func TestDecodeStructuredLimitsAndFailures(t *testing.T) {
	if _, err := Decode([]byte(clashFixture), DecodeOptions{MaxLinks: 2}); !errors.Is(err, ErrTooManyLinks) {
		t.Fatalf("link limit: %v", err)
	}
	if _, err := Decode([]byte(singboxFixture), DecodeOptions{MaxBytes: 64}); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("size limit: %v", err)
	}
	onlySSR := "proxies:\n  - {name: a, type: ssr, server: 1.1.1.1, port: 1}\n"
	res, err := DecodeDetailed([]byte(onlySSR), DecodeOptions{})
	if !errors.Is(err, ErrNoSupportedProxies) || !errors.Is(err, ErrInvalidFormat) {
		t.Fatalf("all-unsupported source: %v", err)
	}
	if res == nil || res.Skipped["unsupported clash proxy type ssr"] != 1 || len(res.SkipSummary()) != 1 {
		t.Fatalf("skip report missing: %+v", res)
	}
	for _, body := range []string{"proxies: [", `{"outbounds": [{"type": "direct"}]}`, `[1, 2]`, `{"inbounds": []}`} {
		if _, err := Decode([]byte(body), DecodeOptions{}); !errors.Is(err, ErrInvalidFormat) {
			t.Errorf("%q: err = %v", body, err)
		}
	}
	// A malformed entry is skipped, not fatal.
	mixed := "proxies:\n  - {name: ok, type: socks5, server: 1.1.1.1, port: 1080}\n  - {name: bad, type: vmess, server: '', port: 0}\n"
	res, err = DecodeDetailed([]byte(mixed), DecodeOptions{})
	if err != nil || len(res.Links) != 1 || res.Skipped["missing server"] != 1 {
		t.Fatalf("mixed source: %v, %+v", err, res)
	}
}

// Plain lists keep their format tag; structured detection must not claim them.
func TestDecodeFormatTags(t *testing.T) {
	res, err := DecodeDetailed([]byte("vless://a@h:1\n"), DecodeOptions{})
	if err != nil || res.Format != FormatPlain {
		t.Fatalf("plain: %v, %+v", err, res)
	}
	res, err = DecodeDetailed([]byte(base64.StdEncoding.EncodeToString([]byte("vless://a@h:1\n"))), DecodeOptions{})
	if err != nil || res.Format != FormatBase64 {
		t.Fatalf("base64: %v, %+v", err, res)
	}
}
