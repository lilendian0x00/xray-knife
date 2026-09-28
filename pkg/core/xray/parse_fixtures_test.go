package xray

import (
	"encoding/base64"
	"encoding/json"
	"net/url"
	"strings"
	"testing"
)

func parseLink(t *testing.T, link string) Protocol {
	t.Helper()
	p, err := (&Core{}).CreateProtocol(link)
	if err != nil {
		t.Fatalf("CreateProtocol(%q): %v", link, err)
	}
	xp := p.(Protocol)
	if err := xp.Parse(); err != nil {
		t.Fatalf("Parse(%q): %v", link, err)
	}
	return xp
}

func buildOK(t *testing.T, p Protocol) map[string]interface{} {
	t.Helper()
	ob, err := p.BuildOutboundDetourConfig(false)
	if err != nil {
		t.Fatalf("BuildOutboundDetourConfig: %v", err)
	}
	if _, err := ob.Build(); err != nil {
		t.Fatalf("outbound Build: %v", err)
	}
	var settings map[string]interface{}
	if ob.Settings != nil {
		if err := json.Unmarshal(*ob.Settings, &settings); err != nil {
			t.Fatalf("settings are not valid JSON: %v\n%s", err, *ob.Settings)
		}
	}
	return settings
}

func TestParseDecodesPasswords(t *testing.T) {
	tr := parseLink(t, "trojan://p%40ss%21@example.com:443?sni=example.com#r").(*Trojan)
	if tr.Password != "p@ss!" {
		t.Errorf("trojan password = %q, want p@ss!", tr.Password)
	}
	tr2 := parseLink(t, "trojan://user:pa%3Ass@example.com:443").(*Trojan)
	if tr2.Password != "user:pa:ss" {
		t.Errorf("trojan user:pass = %q", tr2.Password)
	}
	hy := parseLink(t, "hysteria2://user:pa%40ss@example.com:443?sni=example.com").(*Hysteria2)
	if hy.Password != "user:pa@ss" {
		t.Errorf("hysteria2 auth = %q", hy.Password)
	}
	ob, err := hy.BuildOutboundDetourConfig(false)
	if err != nil || ob.StreamSetting.HysteriaSettings.Auth != "user:pa@ss" {
		t.Errorf("hysteria2 auth not decoded in config: %v", err)
	}
}

func TestParseAddressesAreUnbracketed(t *testing.T) {
	for _, link := range []string{
		"vless://00000000-0000-0000-0000-000000000000@[2001:db8::1]:443?security=none",
		"trojan://pass@[2001:db8::1]:443",
		"ss://" + base64.RawURLEncoding.EncodeToString([]byte("aes-128-gcm:pass")) + "@[2001:db8::1]:443",
		"hysteria2://pass@[2001:db8::1]:443",
	} {
		g := parseLink(t, link).ConvertToGeneralConfig()
		if g.Address != "2001:db8::1" || g.Port != "443" {
			t.Errorf("%s: address/port = %q/%q", link, g.Address, g.Port)
		}
	}
	hy := parseLink(t, "hysteria2://pass@[2001:db8::1]:443").(*Hysteria2)
	if hy.SNI != "2001:db8::1" {
		t.Errorf("hysteria2 default SNI = %q, want the unbracketed address", hy.SNI)
	}
	v := parseLink(t, "vless://00000000-0000-0000-0000-000000000000@[2001:db8::1]:443?security=none").(*Vless)
	v.OrigLink = ""
	if !strings.Contains(v.GetLink(), "@[2001:db8::1]:443") {
		t.Errorf("GetLink double-brackets IPv6: %s", v.GetLink())
	}

	wg := parseLink(t, "wireguard://c2VjcmV0@[2001:db8::1]:51820?publickey=cHVi&address=10.0.0.2#w").ConvertToGeneralConfig()
	if wg.Address != "2001:db8::1" || wg.Port != "51820" || wg.Remark != "w" {
		t.Errorf("wireguard general config = %+v", wg)
	}
}

func TestParseRemarks(t *testing.T) {
	for link, want := range map[string]string{
		"vless://00000000-0000-0000-0000-000000000000@1.2.3.4:443#Speed 100%":                      "Speed 100%",
		"vless://00000000-0000-0000-0000-000000000000@1.2.3.4:443#a%2541":                          "a%41", // decoded once only
		"trojan://pass@1.2.3.4:443#%F0%9F%87%A9%F0%9F%87%AA DE":                                    "\U0001F1E9\U0001F1EA DE",
		"ss://" + base64.RawURLEncoding.EncodeToString([]byte("aes-128-gcm:p")) + "@1.2.3.4:1#50%": "50%",
		"socks://1.2.3.4:1080#my%20socks":                                                          "my socks",
	} {
		g := parseLink(t, link).ConvertToGeneralConfig()
		if g.Remark != want {
			t.Errorf("%s: remark = %q, want %q", link, g.Remark, want)
		}
	}
}

func TestParseVlessDefaultsAndHosts(t *testing.T) {
	v := parseLink(t, "vless://00000000-0000-0000-0000-000000000000@1.2.3.4:80?security=none").(*Vless)
	if v.Type != "tcp" {
		t.Errorf("type = %q, want tcp default", v.Type)
	}
	buildOK(t, v)

	for _, host := range []string{"a.example.com,b.example.com", "my_host.example.com", "cdn.example.com:8080"} {
		v := parseLink(t, "vless://00000000-0000-0000-0000-000000000000@1.2.3.4:80?type=tcp&headerType=http&host="+url.QueryEscape(host)).(*Vless)
		buildOK(t, v)
	}
	if _, err := (&Core{}).CreateProtocol("vless://x@1.2.3.4:80?host=a%20b"); err == nil {
		p := NewVless("vless://x@1.2.3.4:80?host=a%20b")
		if err := p.Parse(); err == nil {
			t.Error("host with a space accepted")
		}
	}

	up := parseLink(t, "VLESS://00000000-0000-0000-0000-000000000000@1.2.3.4:443?security=none")
	if _, ok := up.(*Vless); !ok {
		t.Error("upper-case scheme not routed to VLESS")
	}

	if _, err := parseLink(t, "vless://00000000-0000-0000-0000-000000000000@1.2.3.4:443?type=xhttp&extra=%7Bbroken").BuildOutboundDetourConfig(false); err == nil {
		t.Error("invalid xhttp extra accepted")
	}
	_, err := parseLink(t, "vless://00000000-0000-0000-0000-000000000000@1.2.3.4:443?type=h2").BuildOutboundDetourConfig(false)
	if err == nil || !strings.Contains(err.Error(), "sing-box") {
		t.Errorf("h2 transport error = %v, want a pointer to sing-box", err)
	}
}

func TestBuildDoesNotMutate(t *testing.T) {
	v := parseLink(t, "vless://00000000-0000-0000-0000-000000000000@1.2.3.4:443?type=grpc&serviceName=%2Fsvc&flow=xtls-rprx-vision&security=tls&sni=a.com").(*Vless)
	before := *v
	buildOK(t, v)
	if *v != before {
		t.Errorf("Build mutated the VLESS receiver:\nbefore %+v\nafter  %+v", before, *v)
	}
	vm := &Vmess{Network: "grpc", Path: "/svc", Port: "443", ID: "id", Address: "1.2.3.4", TLS: "tls"}
	buildOK(t, vm)
	if vm.Path != "/svc" || vm.TlsFingerprint != "" || vm.Aid != nil {
		t.Errorf("Build mutated the VMess receiver: %+v", vm)
	}
}

func TestTrojanFlowDropped(t *testing.T) {
	settings := buildOK(t, parseLink(t, "trojan://pass@1.2.3.4:443?security=tls&sni=a.com&flow=xtls-rprx-vision"))
	server := settings["servers"].([]interface{})[0].(map[string]interface{})
	if _, ok := server["flow"]; ok {
		t.Error("trojan flow sent to xray-core (it hard-errors on it)")
	}
}

func TestShadowsocksForms(t *testing.T) {
	legacy := "ss://" + base64.StdEncoding.EncodeToString([]byte("aes-256-gcm:p@ss:w0rd@1.2.3.4:8388")) + "#legacy"
	padded := "ss://" + url.QueryEscape(base64.URLEncoding.EncodeToString([]byte("aes-128-gcm:pw"))) + "@1.2.3.4:8388"
	cases := []struct {
		link, method, password, address, port, remark string
	}{
		{legacy, "aes-256-gcm", "p@ss:w0rd", "1.2.3.4", "8388", "legacy"},
		{padded, "aes-128-gcm", "pw", "1.2.3.4", "8388", ""},
		{"ss://2022-blake3-aes-128-gcm:YWJj+ZGVm/Zw==@1.2.3.4:443", "2022-blake3-aes-128-gcm", "YWJj+ZGVm/Zw==", "1.2.3.4", "443", ""},
		{"ss://" + base64.StdEncoding.EncodeToString([]byte("aes-128-gcm:a/b?c")) + "@1.2.3.4:443/?plugin=obfs-local%3Bobfs%3Dhttp", "aes-128-gcm", "a/b?c", "1.2.3.4", "443", ""},
	}
	for _, tc := range cases {
		s := parseLink(t, tc.link).(*Shadowsocks)
		if s.Encryption != tc.method || s.Password != tc.password || s.Address != tc.address || s.Port != tc.port || s.Remark != tc.remark {
			t.Errorf("%s:\n got %s|%s|%s|%s|%s", tc.link, s.Encryption, s.Password, s.Address, s.Port, s.Remark)
		}
	}
	pl := parseLink(t, cases[3].link).(*Shadowsocks)
	if pl.Plugin != "obfs-local;obfs=http" {
		t.Errorf("plugin = %q", pl.Plugin)
	}
	if _, err := pl.BuildOutboundDetourConfig(false); err == nil {
		t.Error("xray built a plugin link without the plugin")
	}
	for _, bad := range []string{"ss:", "ss:a", "ss://", "ss://@", "ss://bm9jb2xvbg@1.2.3.4:1"} {
		if err := (&Shadowsocks{OrigLink: bad}).Parse(); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestSpecialCharactersStayValidJSON(t *testing.T) {
	ss := &Shadowsocks{Address: "1.2.3.4", Port: "443", Encryption: "aes-128-gcm", Password: `pa"ss\word`}
	settings := buildOK(t, ss)
	if got := settings["servers"].([]interface{})[0].(map[string]interface{})["password"]; got != ss.Password {
		t.Errorf("password = %v", got)
	}
	socks := &Socks{Address: "1.2.3.4", Port: "1080", Username: `us"er`, Password: `p\w`}
	buildOK(t, socks)
	in, err := (&Socks{Address: "127.0.0.1", Port: "1080", Username: `us"er`, Password: `p\w`}).BuildInboundDetourConfig()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := in.Build(); err != nil {
		t.Fatalf("socks inbound with special characters: %v", err)
	}
}

func TestInboundListenAddress(t *testing.T) {
	cases := map[string]string{
		"":          "127.0.0.1",
		"localhost": "127.0.0.1",
		"127.0.0.1": "127.0.0.1",
		"0.0.0.0":   "0.0.0.0",
		"[::1]":     "::1",
		"::":        "::",
	}
	for in, want := range cases {
		got, err := listenAddress(in)
		if err != nil || got != want {
			t.Errorf("listenAddress(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	if _, err := listenAddress("proxy.example.com"); err == nil {
		t.Error("hostname accepted as listen address")
	}
	for _, p := range []Protocol{
		&Socks{Address: "localhost", Port: "1080"},
		&Http{Address: "localhost", Port: "8080"},
		&Vless{Address: "[::1]", Port: "443", ID: "00000000-0000-0000-0000-000000000000", Type: "tcp"},
	} {
		in, err := p.BuildInboundDetourConfig()
		if err != nil {
			t.Fatalf("%T: %v", p, err)
		}
		if ip := in.ListenOn.Address.IP(); ip == nil || !ip.IsLoopback() {
			t.Errorf("%T listens on %v, want loopback", p, in.ListenOn.Address)
		}
	}
}

func TestVmessInboundAndDisplay(t *testing.T) {
	v := &Vmess{Address: "127.0.0.1", Port: "10000", ID: "00000000-0000-0000-0000-000000000000", Network: "tcp"}
	in, err := v.BuildInboundDetourConfig()
	if err != nil {
		t.Fatalf("VMess inbound without alterId: %v", err)
	}
	if _, err := in.Build(); err != nil {
		t.Fatalf("VMess inbound Build: %v", err)
	}
	if strings.Contains(v.DetailsStr(), "<nil>") {
		t.Errorf("DetailsStr shows <nil>: %s", v.DetailsStr())
	}
	if g := v.ConvertToGeneralConfig(); g.TLS != "none" {
		t.Errorf("GeneralConfig.TLS = %q, want none", g.TLS)
	}
	j := `{"v":"2","add":"[2001:db8::1]","port":443,"id":"u","net":"ws","host":"a.com","path":"/","tls":"tls","ps":""}`
	p := parseLink(t, "vmess://"+base64.RawURLEncoding.EncodeToString([]byte(j))+"#from-fragment").(*Vmess)
	if p.Address != "2001:db8::1" || p.Remark != "from-fragment" {
		t.Errorf("vmess address/remark = %q/%q", p.Address, p.Remark)
	}
	buildOK(t, p)
}

func TestHysteria2Forms(t *testing.T) {
	h := parseLink(t, "hysteria2://pass@example.com?sni=example.com").(*Hysteria2)
	if h.Port != "443" {
		t.Errorf("default port = %q, want 443", h.Port)
	}
	hop := parseLink(t, "hysteria2://pass@example.com:443,20000-30000/?sni=example.com#hop").(*Hysteria2)
	if hop.Port != "443" || hop.Ports != "443,20000-30000" || hop.Remark != "hop" {
		t.Errorf("port hopping = %q/%q/%q", hop.Port, hop.Ports, hop.Remark)
	}
	obfs := parseLink(t, "hy2://pass@1.2.3.4:443?obfs=salamander&obfs-password=secret&pinSHA256="+strings.Repeat("ab", 32)).(*Hysteria2)
	ob, err := obfs.BuildOutboundDetourConfig(false)
	if err != nil {
		t.Fatal(err)
	}
	if ob.StreamSetting.FinalMask == nil || len(ob.StreamSetting.FinalMask.Udp) != 1 || ob.StreamSetting.FinalMask.Udp[0].Type != "salamander" {
		t.Errorf("salamander obfs not mapped to finalmask: %+v", ob.StreamSetting.FinalMask)
	}
	if ob.StreamSetting.TLSSettings.PinnedPeerCertSha256 == "" {
		t.Error("pinSHA256 not mapped")
	}
	if _, err := ob.Build(); err != nil {
		t.Fatalf("hysteria2 with salamander does not build: %v", err)
	}
}

func TestWireguardParsing(t *testing.T) {
	w := parseLink(t, "wireguard://a+b/c=@1.2.3.4:51820?publickey=abc+def=&address=10.0.0.2,fd00::2&reserved=1,2,3").(*Wireguard)
	if w.SecretKey != "a+b/c=" || w.PublicKey != "abc+def=" {
		t.Errorf("keys lost '+': secret %q public %q", w.SecretKey, w.PublicKey)
	}
	addrs, err := w.localAddresses()
	if err != nil || strings.Join(addrs, ",") != "10.0.0.2/32,fd00::2/128" {
		t.Errorf("addresses = %v, %v", addrs, err)
	}
	w.Reserved = "1,2,3,4"
	if _, err := w.BuildOutboundDetourConfig(false); err == nil {
		t.Error("4-byte reserved accepted")
	}
	noAddr := parseLink(t, "wireguard://c2VjcmV0@1.2.3.4:51820?publickey=cHVi").(*Wireguard)
	if _, err := noAddr.BuildOutboundDetourConfig(false); err == nil {
		t.Error("wireguard link without address built")
	}
}

func TestSocksAliases(t *testing.T) {
	for _, link := range []string{"socks5://user:pass@1.2.3.4:1080", "socks5h://1.2.3.4:1080"} {
		if _, ok := parseLink(t, link).(*Socks); !ok {
			t.Errorf("%s not parsed as SOCKS", link)
		}
	}
}
