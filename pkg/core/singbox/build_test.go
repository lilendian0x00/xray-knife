package singbox

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/lilendian0x00/xray-knife/v11/pkg/core/fragment"
	"github.com/lilendian0x00/xray-knife/v11/pkg/core/protocol"

	"github.com/sagernet/sing-box/option"
)

const testUUID = "b831381d-6324-4d53-ad4f-8cda48b30811"

// vmessLink encodes a v2rayN-style base64 JSON vmess link.
func vmessLink(t *testing.T, fields map[string]any) string {
	t.Helper()
	raw, err := json.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	return "vmess://" + base64.StdEncoding.EncodeToString(raw)
}

func parseLink(t *testing.T, c *Core, link string) protocol.Protocol {
	t.Helper()
	p, err := c.CreateProtocol(link)
	if err != nil {
		t.Fatalf("CreateProtocol(%q): %v", link, err)
	}
	if err := p.Parse(); err != nil {
		t.Fatalf("Parse(%q): %v", link, err)
	}
	return p
}

// skipUnderRace skips tests that start sing-box instances when the race
// detector is on: sing-box 1.14's NetworkManager writes its "started" flag in
// Start while the interface monitor goroutine reads it (route/network.go),
// which the detector reports no matter what the caller does.
func skipUnderRace(t *testing.T) {
	t.Helper()
	if raceEnabled {
		t.Skip("sing-box NetworkManager.Start races with its interface monitor (upstream)")
	}
}

func freePort(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	return strconv.Itoa(port)
}

// TestCraftedOutboundsBuild runs every protocol × transport the parsers
// produce through box.New and Start, offline. It pins the "unknown transport
// type: tcp", missing inbound registry and by-value option bugs.
func TestCraftedOutboundsBuild(t *testing.T) {
	realityKey := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	ss2022Key := base64.StdEncoding.EncodeToString([]byte("0123456789abcdef"))
	cases := []struct {
		name    string
		link    string
		needs   string // "quic", "gvisor" or "utls"
		wantErr string
	}{
		{name: "vless tcp", link: "vless://" + testUUID + "@127.0.0.1:443?type=tcp&security=none#a"},
		{name: "vless raw", link: "vless://" + testUUID + "@127.0.0.1:443?type=raw&security=none"},
		{name: "vless no type", link: "vless://" + testUUID + "@127.0.0.1:443?security=tls&sni=example.com"},
		{name: "vless tcp tls fp", link: "vless://" + testUUID + "@example.com:443?type=tcp&security=tls&sni=example.com&fp=firefox"},
		{name: "vless reality vision", needs: "utls", link: "vless://" + testUUID + "@127.0.0.1:443?type=tcp&security=reality&pbk=" + realityKey + "&sid=abcd&sni=example.com&fp=chrome&flow=xtls-rprx-vision"},
		{name: "vless ws no host", link: "vless://" + testUUID + "@127.0.0.1:80?type=ws&path=%2Fws&security=none"},
		{name: "vless ws early data", link: "vless://" + testUUID + "@127.0.0.1:80?type=ws&path=%2Fws%3Fed%3D2048&host=example.com"},
		{name: "vless grpc tls", link: "vless://" + testUUID + "@127.0.0.1:443?type=grpc&serviceName=%2Fsvc&security=tls&sni=example.com"},
		{name: "vless httpupgrade", link: "vless://" + testUUID + "@127.0.0.1:80?type=httpupgrade&path=%2Fup&host=example.com"},
		{name: "vless h2 tls", link: "vless://" + testUUID + "@127.0.0.1:443?type=h2&path=%2Fh2&host=a.com,b.com&security=tls"},
		{name: "vless quic", needs: "quic", link: "vless://" + testUUID + "@127.0.0.1:443?type=quic&security=tls&sni=example.com"},
		{name: "vless xhttp rejected", link: "vless://" + testUUID + "@127.0.0.1:443?type=xhttp&security=tls", wantErr: "not supported by sing-box"},
		{name: "vless tcp http header rejected", link: "vless://" + testUUID + "@127.0.0.1:443?type=tcp&headerType=http", wantErr: "header obfuscation"},
		{name: "vmess tcp", link: vmessLink(t, map[string]any{"v": "2", "add": "127.0.0.1", "port": "443", "id": testUUID, "aid": "0", "net": "tcp", "type": "none"})},
		{name: "vmess numeric port tls", link: vmessLink(t, map[string]any{"v": 2, "add": "127.0.0.1", "port": 443, "id": testUUID, "aid": 0, "net": "tcp", "tls": "tls", "sni": "example.com"})},
		{name: "vmess ws", link: vmessLink(t, map[string]any{"add": "127.0.0.1", "port": "80", "id": testUUID, "net": "ws", "path": "/ws", "host": ""})},
		{name: "vmess grpc", link: vmessLink(t, map[string]any{"add": "127.0.0.1", "port": "443", "id": testUUID, "net": "grpc", "path": "svc", "tls": "tls"})},
		{name: "trojan default tcp tls", link: "trojan://secret@127.0.0.1:443?sni=example.com#t"},
		{name: "trojan ws", link: "trojan://secret@127.0.0.1:443?type=ws&path=%2Fws&security=tls"},
		{name: "trojan flow ignored", link: "trojan://secret@127.0.0.1:443?flow=xtls-rprx-vision&security=tls"},
		{name: "ss sip002", link: "ss://" + base64.RawURLEncoding.EncodeToString([]byte("aes-128-gcm:pw")) + "@127.0.0.1:8388#s"},
		{name: "ss 2022 plain", link: "ss://2022-blake3-aes-128-gcm:" + strings.ReplaceAll(ss2022Key, "/", "%2F") + "@127.0.0.1:8388"},
		{name: "ss legacy", link: "ss://" + base64.StdEncoding.EncodeToString([]byte("aes-128-gcm:pw@127.0.0.1:8388")) + "#legacy"},
		{name: "ss obfs plugin", link: "ss://" + base64.RawURLEncoding.EncodeToString([]byte("aes-128-gcm:pw")) + "@127.0.0.1:8388/?plugin=obfs-local%3Bobfs%3Dhttp%3Bobfs-host%3Dexample.com"},
		{name: "socks", link: "socks://user:pass@127.0.0.1:1080"},
		{name: "socks5 alias", link: "socks5://127.0.0.1:1080"},
		{name: "hysteria2 port hopping", needs: "quic", link: "hysteria2://pass@127.0.0.1:443,20000-20010/?sni=example.com&insecure=1"},
		{name: "wireguard", needs: "gvisor", link: "wireguard://WJD7jPqCgI%2BXxujP3d%2FaqzUOJUjjWvlFIoHnK0AQGmk%3D@127.0.0.1:5279?address=172.16.0.2&reserved=98,233,215&publickey=bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=&mtu=1280&keepalive=5"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			switch {
			case tc.needs == "quic" && !testWithQUIC:
				t.Skip("needs -tags with_quic")
			case tc.needs == "gvisor" && !testWithGvisor:
				t.Skip("needs -tags with_gvisor")
			case tc.needs == "utls" && !utlsAvailable:
				t.Skip("needs -tags with_utls")
			}
			c := NewSingboxService(false, false)
			p := parseLink(t, c, tc.link)
			inst, err := c.MakeInstance(context.Background(), p)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("MakeInstance err = %v, want %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("MakeInstance: %v", err)
			}
			if raceEnabled {
				inst.Close() // box.New ran; Start is skipped, see skipUnderRace
				return
			}
			if err := inst.Start(); err != nil {
				inst.Close()
				t.Fatalf("Start: %v", err)
			}
			if err := inst.Close(); err != nil {
				t.Fatalf("Close: %v", err)
			}
		})
	}
}

func TestRealityWithoutUTLSFailsClearly(t *testing.T) {
	_, err := buildTLS(tlsParams{Security: "reality"}, false)
	if err == nil || !strings.Contains(err.Error(), "with_utls") {
		t.Fatalf("err = %v, want a with_utls hint", err)
	}
	// Plain TLS must still work without uTLS (go install builds).
	opts, err := buildTLS(tlsParams{Security: "tls", Fingerprint: "chrome"}, false)
	if err != nil || opts.UTLS != nil {
		t.Fatalf("plain TLS without uTLS: %+v, %v", opts, err)
	}
}

// TestCraftOutboundOptionsFor checks the export mode keeps REALITY and uTLS
// fingerprints whatever this binary was built with.
func TestCraftOutboundOptionsFor(t *testing.T) {
	c := NewSingboxService(false, false)
	realityKey := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	reality := parseLink(t, c, "vless://"+testUUID+"@1.2.3.4:443?security=reality&pbk="+realityKey+"&sid=ab&sni=a.com&fp=firefox").(Protocol)
	out, err := CraftOutboundOptionsFor(reality, false, true)
	if err != nil {
		t.Fatal(err)
	}
	tls := out.Options.(*option.VLESSOutboundOptions).TLS
	if tls.Reality == nil || !tls.Reality.Enabled || tls.UTLS == nil || tls.UTLS.Fingerprint != "firefox" {
		t.Fatalf("exported REALITY TLS = %+v", tls)
	}
	// Without assumeUTLS it matches CraftOutboundOptions, i.e. the build.
	_, errRuntime := reality.CraftOutboundOptions(false)
	_, errFor := CraftOutboundOptionsFor(reality, false, false)
	if (errRuntime == nil) != (errFor == nil) || (errRuntime == nil) != UTLSAvailable() {
		t.Fatalf("runtime err %v, For(false) err %v, uTLS %v", errRuntime, errFor, UTLSAvailable())
	}

	for _, link := range []string{
		"trojan://pw@1.2.3.4:443?sni=a.com",
		vmessLink(t, map[string]any{"add": "1.2.3.4", "port": "443", "id": testUUID, "net": "ws", "tls": "tls"}),
		"anytls://pw@1.2.3.4:443?sni=a.com",
	} {
		out, err := CraftOutboundOptionsFor(parseLink(t, c, link).(Protocol), false, true)
		if err != nil {
			t.Fatalf("%s: %v", link, err)
		}
		tls := out.Options.(option.OutboundTLSOptionsWrapper).TakeOutboundTLSOptions()
		if tls.UTLS == nil || tls.UTLS.Fingerprint != "chrome" {
			t.Errorf("%s: exported TLS = %+v, want the chrome default", link, tls)
		}
	}
	// Protocols without uTLS are crafted as usual.
	ss := parseLink(t, c, "ss://"+base64.RawURLEncoding.EncodeToString([]byte("aes-128-gcm:pw"))+"@1.2.3.4:8388").(Protocol)
	if out, err := CraftOutboundOptionsFor(ss, false, true); err != nil || out.Type != "shadowsocks" {
		t.Fatalf("ss: %+v, %v", out, err)
	}
}

// TestInboundsStart builds each local listener the proxy can use, starts it
// and checks the port accepts connections.
func TestInboundsStart(t *testing.T) {
	skipUnderRace(t)
	cases := []struct {
		name string
		in   func(port string) protocol.Protocol
	}{
		{name: "socks auth", in: func(port string) protocol.Protocol {
			return &Socks{Address: "127.0.0.1", Port: port, Username: "u", Password: "p"}
		}},
		{name: "mixed localhost", in: func(port string) protocol.Protocol {
			return &Http{Address: "localhost", Port: port}
		}},
		{name: "vless", in: func(port string) protocol.Protocol {
			return &Vless{Address: "127.0.0.1", Port: port, ID: testUUID, Type: "tcp"}
		}},
		{name: "vmess ws", in: func(port string) protocol.Protocol {
			return &Vmess{Address: "127.0.0.1", Port: port, ID: testUUID, Network: "ws", Path: "/ws"}
		}},
		{name: "trojan", in: func(port string) protocol.Protocol {
			return &Trojan{Address: "127.0.0.1", Port: port, Password: "pw", Type: "tcp"}
		}},
		{name: "shadowsocks", in: func(port string) protocol.Protocol {
			return &Shadowsocks{Address: "127.0.0.1", Port: port, Encryption: "aes-128-gcm", Password: "pw"}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			port := freePort(t)
			c := NewSingboxService(false, false, WithInbound(tc.in(port)))
			out := parseLink(t, c, "socks://127.0.0.1:1")
			inst, err := c.MakeInstance(context.Background(), out)
			if err != nil {
				t.Fatalf("MakeInstance: %v", err)
			}
			defer inst.Close()
			if err := inst.Start(); err != nil {
				t.Fatalf("Start: %v", err)
			}
			conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", port), 2*time.Second)
			if err != nil {
				t.Fatalf("inbound not listening: %v", err)
			}
			conn.Close()
		})
	}
}

func TestInboundErrorsSurface(t *testing.T) {
	c := NewSingboxService(false, false, WithInbound(&Socks{Address: "not-an-ip.example", Port: "1080"}))
	out := parseLink(t, c, "socks://127.0.0.1:1")
	if _, err := c.MakeInstance(context.Background(), out); err == nil || !strings.Contains(err.Error(), "listen address") {
		t.Fatalf("err = %v, want a listen address error", err)
	}
	if err := c.SetInbound(&Hysteria2{}); err == nil {
		t.Fatal("hysteria2 inbound accepted")
	}
}

func TestListenAddr(t *testing.T) {
	cases := map[string]string{
		"":          "127.0.0.1",
		"localhost": "127.0.0.1",
		"127.0.0.1": "127.0.0.1",
		"[::1]":     "::1",
		"::":        "::",
		"0.0.0.0":   "0.0.0.0",
	}
	for in, want := range cases {
		got, err := listenAddr(in)
		if err != nil || netip.Addr(*got).String() != want {
			t.Errorf("listenAddr(%q) = %v, %v; want %s", in, got, err, want)
		}
	}
	for _, bad := range []string{"example.com", "127.0.0.1:80", "300.1.1.1"} {
		if _, err := listenAddr(bad); err == nil {
			t.Errorf("listenAddr(%q) accepted; it would widen to all interfaces", bad)
		}
	}
}

func TestPasswordsAreDecoded(t *testing.T) {
	c := NewSingboxService(false, false)
	trojan := parseLink(t, c, "trojan://p%40ss%2Fw%C3%B6rd@127.0.0.1:443?security=tls").(*Trojan)
	if trojan.Password != "p@ss/wörd" {
		t.Errorf("trojan password = %q", trojan.Password)
	}
	hy2 := parseLink(t, c, "hysteria2://user:p%40ss@127.0.0.1:443/?sni=a.com").(*Hysteria2)
	if hy2.Password != "user:p@ss" {
		t.Errorf("hysteria2 password = %q", hy2.Password)
	}
	remark := parseLink(t, c, "trojan://pw@127.0.0.1:443#Speed 100%").(*Trojan)
	if remark.Remark != "Speed 100%" {
		t.Errorf("raw %% remark = %q", remark.Remark)
	}
	twice := parseLink(t, c, "trojan://pw@127.0.0.1:443#a%2541").(*Trojan)
	if twice.Remark != "a%41" {
		t.Errorf("remark decoded twice: %q", twice.Remark)
	}
}

func TestHysteria2Parse(t *testing.T) {
	c := NewSingboxService(false, false)
	cases := []struct {
		link      string
		wantPort  string
		wantPorts []string
	}{
		{link: "hysteria2://pw@example.com/?sni=a.com", wantPort: "443"},
		{link: "hy2://pw@example.com:8443", wantPort: "8443"},
		{link: "hysteria2://pw@example.com:443,20000-30000/?sni=a.com#hop", wantPort: "443", wantPorts: []string{"443:443", "20000:30000"}},
		{link: "hysteria2://pw@[2001:db8::1]:443,5000-5010", wantPort: "443", wantPorts: []string{"443:443", "5000:5010"}},
		{link: "hysteria2://pw@example.com:443?mport=20000-30000", wantPort: "443", wantPorts: []string{"443:443", "20000:30000"}},
	}
	for _, tc := range cases {
		h := parseLink(t, c, tc.link).(*Hysteria2)
		if h.Port != tc.wantPort || strings.Join(h.ServerPorts, ",") != strings.Join(tc.wantPorts, ",") {
			t.Errorf("%s: port %q ports %v, want %q %v", tc.link, h.Port, h.ServerPorts, tc.wantPort, tc.wantPorts)
		}
	}
	h := parseLink(t, c, "hysteria2://pw@[2001:db8::1]:443").(*Hysteria2)
	if h.SNI != "2001:db8::1" {
		t.Errorf("IPv6 default SNI = %q, want the bare address", h.SNI)
	}
	out, err := h.CraftOutboundOptions(false)
	if err != nil || out.Options.(*option.Hysteria2OutboundOptions).Server != "2001:db8::1" {
		t.Fatalf("craft: %+v, %v", out, err)
	}
}

func TestShadowsocksParse(t *testing.T) {
	c := NewSingboxService(false, false)
	cases := []struct {
		link, method, password, plugin string
		wantErr                        string
	}{
		{link: "ss://" + base64.RawURLEncoding.EncodeToString([]byte("aes-128-gcm:p?>~ss")) + "@1.2.3.4:8388", method: "aes-128-gcm", password: "p?>~ss"},
		{link: "ss://" + base64.StdEncoding.EncodeToString([]byte("chacha20-ietf-poly1305:pw")) + "@1.2.3.4:8388", method: "chacha20-ietf-poly1305", password: "pw"},
		{link: "ss://YWVzLTEyOC1nY206cHc%3D@1.2.3.4:8388", method: "aes-128-gcm", password: "pw"},
		{link: "ss://2022-blake3-aes-128-gcm:YWJj+ZGVm%2Fg%3D%3D@1.2.3.4:8388", method: "2022-blake3-aes-128-gcm", password: "YWJj+ZGVm/g=="},
		{link: "ss://" + base64.StdEncoding.EncodeToString([]byte("aes-256-gcm:p@ss:w@1.2.3.4:8388")) + "#legacy", method: "aes-256-gcm", password: "p@ss:w"},
		{link: "ss://" + base64.RawURLEncoding.EncodeToString([]byte("aes-128-gcm:pw")) + "@1.2.3.4:8388/?plugin=simple-obfs%3Bobfs%3Dtls", method: "aes-128-gcm", password: "pw", plugin: "obfs-local"},
		{link: "ss://" + base64.RawURLEncoding.EncodeToString([]byte("aes-128-gcm:pw")) + "@1.2.3.4:8388/?plugin=kcptun", wantErr: "not supported"},
		{link: "ss://garbage", wantErr: "invalid shadowsocks link"},
		// Raw ';' in plugin= (common in the wild) must not drop the plugin.
		{link: "ss://" + base64.RawURLEncoding.EncodeToString([]byte("aes-128-gcm:pw")) + "@1.2.3.4:8388/?plugin=obfs-local;obfs=http;obfs-host=a.com#x", method: "aes-128-gcm", password: "pw", plugin: "obfs-local"},
		{link: "ss://" + base64.RawURLEncoding.EncodeToString([]byte("aes-128-gcm:pw")) + "@1.2.3.4:8388/?plugin=kcptun;key=x", wantErr: "not supported"},
		{link: "ss://" + base64.RawURLEncoding.EncodeToString([]byte("aes-128-gcm:pw")) + "@1.2.3.4:8388/?group=g&plugin=v2ray-plugin;tls;host=a.com", method: "aes-128-gcm", password: "pw", plugin: "v2ray-plugin"},
	}
	for _, tc := range cases {
		p, err := c.CreateProtocol(tc.link)
		if err != nil {
			t.Fatal(err)
		}
		err = p.Parse()
		if tc.wantErr != "" {
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("%s: err = %v, want %q", tc.link, err, tc.wantErr)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: %v", tc.link, err)
			continue
		}
		ss := p.(*Shadowsocks)
		if ss.Encryption != tc.method || ss.Password != tc.password || ss.Plugin != tc.plugin {
			t.Errorf("%s: got %q %q %q", tc.link, ss.Encryption, ss.Password, ss.Plugin)
		}
	}
}

func TestWireguardParse(t *testing.T) {
	c := NewSingboxService(false, false)
	w := parseLink(t, c, "wireguard://priv+key=@1.2.3.4:51820?publickey=abc+def=&address=10.0.0.2,fd00::2&reserved=1,2,3#wg").(*Wireguard)
	if w.SecretKey != "priv+key=" || w.PublicKey != "abc+def=" {
		t.Fatalf("keys lost '+': secret %q public %q", w.SecretKey, w.PublicKey)
	}
	out, err := w.CraftOutboundOptions(false)
	if err != nil {
		t.Fatal(err)
	}
	wg := out.Options.(*option.WireGuardEndpointOptions)
	if len(wg.Address) != 2 || wg.Address[0].String() != "10.0.0.2/32" || wg.Address[1].String() != "fd00::2/128" {
		t.Fatalf("addresses = %v", wg.Address)
	}
	if g := w.ConvertToGeneralConfig(); g.Address != "1.2.3.4" || g.Port != "51820" || g.OrigLink == "" || g.Remark != "wg" {
		t.Fatalf("general config = %+v", g)
	}

	// Raw (unescaped) standard base64 keys: '/' must not end the authority.
	raw := parseLink(t, c, "wireguard://ab/cd+ef/gh=@[2001:db8::1]:2408/?publickey=pu/b+k=&address=172.16.0.2/32#r%20aw").(*Wireguard)
	if raw.SecretKey != "ab/cd+ef/gh=" || raw.PublicKey != "pu/b+k=" || raw.Endpoint != "[2001:db8::1]:2408" || raw.Remark != "r aw" {
		t.Fatalf("raw keys: %+v", raw)
	}
	if out, err := raw.CraftOutboundOptions(false); err != nil || out.Options.(*option.WireGuardEndpointOptions).Peers[0].Address != "2001:db8::1" {
		t.Fatalf("raw keys craft: %v", err)
	}
	for _, bad := range []string{"wireguard://1.2.3.4:51820?publickey=p", "wireguard://k@1.2.3.4?publickey=p"} {
		p, _ := c.CreateProtocol(bad)
		if err := p.Parse(); err == nil {
			t.Errorf("%s accepted", bad)
		}
	}

	for _, bad := range []string{
		"wireguard://k@1.2.3.4:51820?publickey=p&address=10.0.0.2/32&reserved=1,2,3,4",
		"wireguard://k@1.2.3.4:51820?publickey=p&address=10.0.0.2/32&reserved=1,999,3",
		"wireguard://k@1.2.3.4:51820?publickey=p",
	} {
		w := parseLink(t, c, bad).(*Wireguard)
		if _, err := w.CraftOutboundOptions(false); err == nil {
			t.Errorf("%s: accepted", bad)
		}
	}
}

func TestCraftDoesNotMutate(t *testing.T) {
	c := NewSingboxService(false, false)
	v := parseLink(t, c, "vless://"+testUUID+"@127.0.0.1:443?type=grpc&serviceName=%2Fsvc&security=tls").(*Vless)
	if _, err := v.CraftOutboundOptions(false); err != nil {
		t.Fatal(err)
	}
	if v.ServiceName != "/svc" {
		t.Fatalf("CraftOutboundOptions changed ServiceName to %q", v.ServiceName)
	}
}

func TestDefaultALPNIsEmpty(t *testing.T) {
	opts, err := buildTLS(tlsParams{Security: "tls"}, false)
	if err != nil || len(opts.ALPN) != 0 {
		t.Fatalf("ALPN = %v, %v; want none so gRPC/h2 can negotiate h2", opts.ALPN, err)
	}
	opts, _ = buildTLS(tlsParams{Security: "tls", ALPN: "h2,http/1.1"}, false)
	if strings.Join(opts.ALPN, ",") != "h2,http/1.1" {
		t.Fatalf("explicit ALPN = %v", opts.ALPN)
	}
}

func TestVmessErrorsDoNotLeakUUID(t *testing.T) {
	c := NewSingboxService(false, false)
	v := parseLink(t, c, vmessLink(t, map[string]any{"add": "127.0.0.1", "port": "notaport", "id": testUUID, "net": "tcp"})).(*Vmess)
	_, err := v.CraftOutboundOptions(false)
	if err == nil || strings.Contains(err.Error(), testUUID) {
		t.Fatalf("err = %v", err)
	}
}

func TestChainDirection(t *testing.T) {
	c := NewSingboxService(false, false)
	hops := []protocol.Protocol{
		parseLink(t, c, "socks://127.0.0.1:1001"),
		parseLink(t, c, "socks://127.0.0.1:1002"),
		parseLink(t, c, "socks://127.0.0.1:1003"),
	}
	outs, exit, err := c.craftChain(hops)
	if err != nil {
		t.Fatal(err)
	}
	if exit != "chain-2" {
		t.Fatalf("exit tag = %q, want chain-2", exit)
	}
	for i, want := range []string{"", "chain-0", "chain-1"} {
		if got := outs[i].Options.(*option.SOCKSOutboundOptions).Detour; got != want {
			t.Errorf("hop %d detour = %q, want %q", i, got, want)
		}
	}
}

func TestFragmentOnEntryHopOnly(t *testing.T) {
	f := &fragment.Options{Packets: "tlshello", Length: fragment.Range{Min: 100, Max: 200}, Interval: fragment.Range{Min: 10, Max: 20}}
	c := NewSingboxService(false, false, WithFragment(f))
	f.Packets = "mutated after WithFragment"

	link := "vless://" + testUUID + "@127.0.0.1:443?type=tcp&security=tls&sni=example.com"
	outs, _, err := c.craftChain([]protocol.Protocol{parseLink(t, c, link), parseLink(t, c, link)})
	if err != nil {
		t.Fatal(err)
	}
	entry := outs[0].Options.(*option.VLESSOutboundOptions).TLS
	if !entry.Fragment || !entry.RecordFragment || time.Duration(entry.FragmentFallbackDelay) != 20*time.Millisecond {
		t.Fatalf("entry TLS = %+v, want fragment + record fragment + 20ms", entry)
	}
	if exit := outs[1].Options.(*option.VLESSOutboundOptions).TLS; exit.Fragment || exit.RecordFragment {
		t.Fatalf("exit hop fragmented: %+v", exit)
	}

	c = NewSingboxService(false, false, WithFragment(&fragment.Options{Packets: "1-3", Length: fragment.Range{Min: 1, Max: 5}}))
	out, err := c.craftOutbound(parseLink(t, c, link), "x", true)
	if err != nil {
		t.Fatal(err)
	}
	if tls := out.Options.(*option.VLESSOutboundOptions).TLS; !tls.Fragment || tls.RecordFragment {
		t.Fatalf("packet-range TLS = %+v, want segment fragmentation only", tls)
	}
	// Non-TLS and QUIC outbounds are left alone.
	plain, err := c.craftOutbound(parseLink(t, c, "vless://"+testUUID+"@127.0.0.1:80?type=ws"), "x", true)
	if err != nil || plain.Options.(*option.VLESSOutboundOptions).TLS != nil {
		t.Fatalf("plain outbound: %+v, %v", plain, err)
	}
	hy2, err := c.craftOutbound(parseLink(t, c, "hysteria2://pw@127.0.0.1:443"), "x", true)
	if err != nil || hy2.Options.(*option.Hysteria2OutboundOptions).TLS.Fragment {
		t.Fatalf("hysteria2 outbound fragmented: %v", err)
	}
}

func TestForeignProtocolIsAnError(t *testing.T) {
	c := NewSingboxService(false, false)
	if _, err := c.MakeInstance(context.Background(), foreignProtocol{}); err == nil {
		t.Fatal("foreign protocol accepted")
	}
	if err := c.SetInbound(foreignProtocol{}); err == nil {
		t.Fatal("foreign inbound accepted")
	}
}

type foreignProtocol struct{}

func (foreignProtocol) Parse() error       { return nil }
func (foreignProtocol) DetailsStr() string { return "" }
func (foreignProtocol) GetLink() string    { return "" }
func (foreignProtocol) ConvertToGeneralConfig() protocol.GeneralConfig {
	return protocol.GeneralConfig{}
}

// TestWireguardHttpClientBuilds covers the WireGuard client path, which adds
// DNS client options (prefer IPv4) so the endpoint resolves names itself.
func TestWireguardHttpClientBuilds(t *testing.T) {
	if !testWithGvisor {
		t.Skip("needs -tags with_gvisor")
	}
	skipUnderRace(t)
	c := NewSingboxService(false, false)
	p := parseLink(t, c, "wireguard://WJD7jPqCgI%2BXxujP3d%2FaqzUOJUjjWvlFIoHnK0AQGmk%3D@127.0.0.1:5279?address=172.16.0.2/32&publickey=bmXOC%2BF1FxEMF9dyiK2H5%2F1SUtzH0JuVo51h2wPfgyo%3D")
	client, instance, err := c.MakeHttpClient(context.Background(), p, time.Second)
	if err != nil {
		t.Fatalf("MakeHttpClient: %v", err)
	}
	defer instance.Close()
	if client == nil {
		t.Fatal("nil client")
	}
}

func TestFragmentREALITYIsRejected(t *testing.T) {
	realityKey := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	reality := "vless://" + testUUID + "@1.2.3.4:443?security=reality&pbk=" + realityKey + "&sid=ab&sni=a.com&fp=chrome"
	f, _ := fragment.Parse("tlshello,100-200,10-20")
	c := NewSingboxService(false, false, WithFragment(f))
	// Build-independent: craft as a uTLS build would.
	hop := parseLink(t, c, reality).(Protocol)
	out, err := CraftOutboundOptionsFor(hop, false, true)
	if err != nil {
		t.Fatal(err)
	}
	if err := applyFragment(out, f); err == nil || !strings.Contains(err.Error(), "--core xray") {
		t.Fatalf("REALITY + fragment: err = %v, want a --core xray hint", err)
	}
	if tls := out.Options.(*option.VLESSOutboundOptions).TLS; tls.Fragment || tls.RecordFragment {
		t.Fatalf("REALITY TLS got fragment flags: %+v", tls)
	}
	// Without --fragment REALITY builds as usual.
	if err := applyFragment(out, nil); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		link       string
		want       bool
		reasonPart string
	}{
		{link: "vless://" + testUUID + "@1.2.3.4:443?security=tls&sni=a.com", want: true},
		{link: "anytls://pw@1.2.3.4:443?sni=a.com", want: true},
		{link: reality, reasonPart: "--core xray"},
		{link: "vless://" + testUUID + "@1.2.3.4:80?security=none", reasonPart: "no TLS"},
		{link: "ss://" + base64.RawURLEncoding.EncodeToString([]byte("aes-128-gcm:pw")) + "@1.2.3.4:8388", reasonPart: "no TLS"},
		{link: "hysteria2://pw@1.2.3.4:443", reasonPart: "QUIC"},
		{link: "tuic://" + testUUID + ":pw@1.2.3.4:443", reasonPart: "QUIC"},
	} {
		ok, reason := FragmentSupported(parseLink(t, c, tc.link))
		if ok != tc.want || !strings.Contains(reason, tc.reasonPart) {
			t.Errorf("FragmentSupported(%s) = %v, %q", tc.link, ok, reason)
		}
	}
	if ok, _ := FragmentSupported(foreignProtocol{}); ok {
		t.Error("foreign protocol reported supported")
	}
}

func TestShadowsocksRawSemicolonPluginOptions(t *testing.T) {
	c := NewSingboxService(false, false)
	ss := parseLink(t, c, "ss://"+base64.RawURLEncoding.EncodeToString([]byte("aes-128-gcm:pw"))+"@1.2.3.4:8388/?plugin=obfs-local;obfs=http;obfs-host=a.com").(*Shadowsocks)
	if ss.PluginOptions != "obfs=http;obfs-host=a.com" {
		t.Fatalf("plugin options = %q", ss.PluginOptions)
	}
	out, err := ss.CraftOutboundOptions(false)
	if err != nil {
		t.Fatal(err)
	}
	if o := out.Options.(*option.ShadowsocksOutboundOptions); o.Plugin != "obfs-local" || o.PluginOptions != "obfs=http;obfs-host=a.com" {
		t.Fatalf("crafted plugin = %q %q", o.Plugin, o.PluginOptions)
	}
}
