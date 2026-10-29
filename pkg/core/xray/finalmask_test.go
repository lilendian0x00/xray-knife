package xray

import (
	"encoding/base64"
	"net/url"
	"strings"
	"testing"
)

const (
	fragmentFM = `{"tcp":[{"type":"fragment","settings":{"packets":"tlshello","length":"100-200","delay":"10-20"}}]}`
	noiseFM    = `{"udp":[{"type":"noise","settings":{"noise":[{"rand":"10-20","delay":"5"}]}}]}`
)

func TestFinalMaskFromLink(t *testing.T) {
	link := "vless://00000000-0000-0000-0000-000000000000@1.2.3.4:443?security=tls&sni=example.com&fm=" + url.QueryEscape(fragmentFM)
	v := &Vless{OrigLink: link}
	if err := v.Parse(); err != nil {
		t.Fatal(err)
	}
	ob, err := v.BuildOutboundDetourConfig(false)
	if err != nil {
		t.Fatal(err)
	}
	if fm := ob.StreamSetting.FinalMask; fm == nil || len(fm.Tcp) != 1 || fm.Tcp[0].Type != "fragment" {
		t.Fatalf("finalmask = %+v", fm)
	}
	if _, err := ob.Build(); err != nil {
		t.Fatalf("outbound with fm does not build: %v", err)
	}

	// The link written back keeps fm byte for byte.
	v.OrigLink = ""
	again := &Vless{OrigLink: v.GetLink()}
	if err := again.Parse(); err != nil || again.FinalMask != fragmentFM {
		t.Errorf("round trip fm = %q, %v", again.FinalMask, err)
	}

	// --fragment adds its mask after the link's own.
	c := NewXrayService(false, false, WithFragment(mustFragment(t, "tlshello,10-20,1")))
	if err := c.prepareEntry(ob, "1.2.3.4"); err != nil {
		t.Fatal(err)
	}
	if n := len(ob.StreamSetting.FinalMask.Tcp); n != 2 {
		t.Errorf("tcp masks with --fragment = %d, want 2", n)
	}

	tr := &Trojan{OrigLink: "trojan://pw@1.2.3.4:443?security=tls&sni=example.com&fm=" + url.QueryEscape(fragmentFM)}
	if err := tr.Parse(); err != nil {
		t.Fatal(err)
	}
	if ob, err := tr.BuildOutboundDetourConfig(false); err != nil || ob.StreamSetting.FinalMask == nil {
		t.Errorf("trojan fm not applied: %v", err)
	}

	bad := &Vless{OrigLink: "vless://00000000-0000-0000-0000-000000000000@1.2.3.4:443?security=tls&sni=example.com&fm=%7Bnope"}
	if err := bad.Parse(); err != nil {
		t.Fatal(err)
	}
	if _, err := bad.BuildOutboundDetourConfig(false); err == nil {
		t.Error("invalid fm JSON was accepted")
	}
}

// --fragment noise goes above a link's udphop or xicmp mask: those dial
// themselves, and xray-core fails every dial unless they come last.
func TestFragmentNoiseBeforeDialMask(t *testing.T) {
	for typ, settings := range map[string]string{
		"udphop": `{"mode":"intervalRemote","interval":"5-10","remotePorts":"20000-20010"}`,
		"xicmp":  `{"dgram":true,"ips":["1.2.3.4"]}`,
	} {
		fm := `{"udp":[{"type":"salamander","settings":{"password":"x"}},{"type":"` + typ + `","settings":` + settings + `}]}`
		h := &Hysteria2{OrigLink: "hy2://pw@1.2.3.4:443?sni=a.com&fm=" + url.QueryEscape(fm)}
		if err := h.Parse(); err != nil {
			t.Fatal(err)
		}
		ob, err := h.BuildOutboundDetourConfig(false)
		if err != nil {
			t.Fatal(err)
		}
		c := NewXrayService(false, false, WithFragment(mustFragment(t, "tlshello,10-20,1", "rand:10-20:5")))
		if err := c.prepareEntry(ob, "1.2.3.4"); err != nil {
			t.Fatal(err)
		}
		var got []string
		for _, m := range ob.StreamSetting.FinalMask.Udp {
			got = append(got, m.Type)
		}
		if want := "salamander noise " + typ; strings.Join(got, " ") != want {
			t.Errorf("udp masks = %v, want %s", got, want)
		}
		if _, err := ob.Build(); err != nil {
			t.Errorf("%s: does not build: %v", typ, err)
		}
	}
}

func TestFinalMaskVmessJSON(t *testing.T) {
	for _, fm := range []string{fragmentFM, `"` + `{\"tcp\":[{\"type\":\"fragment\",\"settings\":{\"packets\":\"tlshello\",\"length\":\"100-200\",\"delay\":\"10-20\"}}]}` + `"`} {
		js := `{"v":"2","add":"1.2.3.4","port":"443","id":"00000000-0000-0000-0000-000000000000","net":"tcp","tls":"tls","sni":"example.com","fm":` + fm + `}`
		v := &Vmess{OrigLink: "vmess://" + base64.StdEncoding.EncodeToString([]byte(js))}
		if err := v.Parse(); err != nil {
			t.Fatal(err)
		}
		ob, err := v.BuildOutboundDetourConfig(false)
		if err != nil {
			t.Fatal(err)
		}
		if f := ob.StreamSetting.FinalMask; f == nil || len(f.Tcp) != 1 || f.Tcp[0].Type != "fragment" {
			t.Errorf("vmess fm %s: finalmask = %+v", fm, f)
		}
	}
}

func TestFinalMaskHysteria2(t *testing.T) {
	both := `{"udp":[{"type":"salamander","settings":{"password":"x"}},{"type":"noise","settings":{"noise":[{"rand":"10-20","delay":"5"}]}}]}`
	h := &Hysteria2{OrigLink: "hy2://pw@1.2.3.4:443?sni=a.com&obfs=salamander&obfs-password=x&fm=" + url.QueryEscape(both)}
	if err := h.Parse(); err != nil {
		t.Fatal(err)
	}
	ob, err := h.BuildOutboundDetourConfig(false)
	if err != nil {
		t.Fatal(err)
	}
	if udp := ob.StreamSetting.FinalMask.Udp; len(udp) != 2 || udp[0].Type != "salamander" || udp[1].Type != "noise" {
		t.Fatalf("hysteria2 masks = %+v, want fm's salamander then noise", udp)
	}
	if _, err := ob.Build(); err != nil {
		t.Fatalf("hysteria2 with fm does not build: %v", err)
	}
	if !h.NeedsXray(false) {
		t.Error("noise in fm should need xray")
	}

	salamander := func(settings string) string {
		return url.QueryEscape(`{"udp":[{"type":"salamander","settings":` + settings + `}]}`)
	}
	const obfs = "hy2://pw@1.2.3.4:443?obfs=salamander&obfs-password=x"
	const quic = `{"quicParams":{"congestion":"bbr"}}`
	for link, want := range map[string]bool{
		// The salamander that panels repeat in fm is what obfs already says.
		obfs + "&fm=" + salamander(`{"password":"x"}`):              false,
		"hy2://pw@1.2.3.4:443?fm=" + salamander(`{"password":"x"}`): true,
		"hy2://pw@1.2.3.4:443?fm=" + url.QueryEscape(quic):          true,
		"hy2://pw@1.2.3.4:443":                                      false,
		"hy2://pw@1.2.3.4:443?fm=" + url.QueryEscape(`{"udp":[]}`):  false,
		// sing-box only has obfs and obfs-password: gecko, another password
		// or a second salamander need xray.
		obfs + "&fm=" + salamander(`{"password":"x","packetSize":"200-1200"}`): true,
		obfs + "&fm=" + salamander(`{"password":"y"}`):                         true,
		obfs + "&fm=" + url.QueryEscape(`{"udp":[{"type":"salamander","settings":{"password":"x"}},{"type":"salamander","settings":{"password":"x"}}]}`): true,
		obfs + "&fm=" + url.QueryEscape(`{}`): true,
		// xray cannot skip certificate checks, and noise and quicParams are
		// client-side: links that ask for insecure stay on sing-box.
		"hy2://pw@1.2.3.4:443?insecure=1&fm=" + url.QueryEscape(quic):                     false,
		obfs + "&insecure=1&fm=" + url.QueryEscape(both):                                  false,
		obfs + "&insecure=1&pinSHA256=ab&fm=" + url.QueryEscape(both):                     true,
		"hy2://pw@1.2.3.4:443?insecure=1&fm=" + salamander(`{"password":"x"}`):            true,
		obfs + "&insecure=1&fm=" + salamander(`{"password":"x","packetSize":"200-1200"}`): true,
	} {
		h := &Hysteria2{OrigLink: link}
		if err := h.Parse(); err != nil {
			t.Fatal(err)
		}
		if got := h.NeedsXray(false); got != want {
			t.Errorf("%s: NeedsXray = %v, want %v", link, got, want)
		}
	}

	// A global --insecure counts like insecure=1.
	h = &Hysteria2{OrigLink: "hy2://pw@1.2.3.4:443?fm=" + url.QueryEscape(quic)}
	if err := h.Parse(); err != nil {
		t.Fatal(err)
	}
	if h.NeedsXray(true) {
		t.Error("quicParams with --insecure should stay on sing-box")
	}
}

func TestFinalMaskWireguard(t *testing.T) {
	w := &Wireguard{OrigLink: "wireguard://c2VjcmV0@1.2.3.4:51820?publickey=cHVi&address=10.0.0.2&fm=" + url.QueryEscape(noiseFM)}
	if err := w.Parse(); err != nil {
		t.Fatal(err)
	}
	ob, err := w.BuildOutboundDetourConfig(false)
	if err != nil {
		t.Fatal(err)
	}
	if ob.StreamSetting == nil || ob.StreamSetting.FinalMask == nil || ob.StreamSetting.FinalMask.Udp[0].Type != "noise" {
		t.Fatalf("wireguard stream = %+v", ob.StreamSetting)
	}
	if _, err := ob.Build(); err != nil {
		t.Fatalf("wireguard with fm does not build: %v", err)
	}
}

func TestFinalMaskStaysOnXray(t *testing.T) {
	v := &Vless{OrigLink: "vless://00000000-0000-0000-0000-000000000000@1.2.3.4:443?security=tls&sni=example.com&type=ws&fm=" + url.QueryEscape(fragmentFM)}
	if err := v.Parse(); err != nil {
		t.Fatal(err)
	}
	if reason := SingboxReason(v, true); reason != "" {
		t.Errorf("insecure link with fm moved to sing-box: %s", reason)
	}
	plain := &Vless{OrigLink: "vless://00000000-0000-0000-0000-000000000000@1.2.3.4:80?security=none&type=ws&fm=" + url.QueryEscape(fragmentFM)}
	if err := plain.Parse(); err != nil {
		t.Fatal(err)
	}
	if reason := SingboxReason(plain, false); reason != "" {
		t.Errorf("plaintext link with fm moved to sing-box: %s", reason)
	}
}

// Every mask type and option xray-core 26.10.21 accepts must reach the
// outbound and build.
func TestFinalMaskEveryType(t *testing.T) {
	tcp := map[string]string{
		"filter":        `{"allowedSourceIPs":["1.2.3.4/32"],"blockedSourceIPs":["10.0.0.0/8"]}`,
		"header-custom": `{"clients":[[{"type":"str","packet":"GET / HTTP/1.1\r\n"},{"rand":4,"randRange":"48-57"},{"type":"hex","packet":"0d0a"},{"type":"base64","packet":"DQo="}]],"servers":[[{"packet":[72,84,84,80]}]],"errors":[[{"type":"str","packet":"HTTP/1.1 404 Not Found\r\n\r\n"}]]}`,
		"fragment":      `{"packets":"1-3","lengths":["10-20","30-40"],"delays":["5-10"],"maxSplit":"2-4"}`,
		"sudoku":        `{"password":"pw","ascii":"prefer_ascii","paddingMin":2,"paddingMax":7}`,
		"xmc":           `{"hostname":"mc.example.com","password":"pw","profiles":[{"username":"Steve","uuid":"8667ba71-b85a-4004-af54-457a9734eed7","texturesValue":"e30=","texturesSignature":"c2ln"}]}`,
	}
	udp := map[string]string{
		"filter":           `{"allowedSourceIPs":["1.2.3.4"]}`,
		"header-custom":    `{"mode":"standalone","client":[{"type":"str","packet":"FM"},{"rand":2}],"server":[{"type":"hex","packet":"beef"}]}`,
		"mkcp-legacy":      `{}`,
		"mkcp-legacy seed": `{"value":"seed"}`,
		"mkcp-legacy dns":  `{"header":"dns","value":"example.com"}`,
		"noise":            `{"reset":"5-10","noise":[{"rand":"10-20","delay":"5"},{"type":"str","packet":"hello","delay":"1-3"},{"type":"hex","packet":"abcd"}]}`,
		"salamander":       `{"password":"pw","packetSize":"200-1200"}`,
		"sudoku":           `{"password":"pw"}`,
		"xdns":             `{"domains":[{"names":["t.example.com"]}],"resolvers":[{"addrs":["1.1.1.1","tcp://8.8.8.8:53","https://dns.google/dns-query"]}],"extraPoll":1}`,
		"xicmp":            `{"dgram":true,"ips":["1.2.3.4"]}`,
		"realm":            `{"url":"realm://token@realm.example.com/id","stunServers":["stun.l.google.com:19302"]}`,
		"udphop":           `{"mode":"intervalRemote,perConnRemote","interval":"5-10","remotePorts":"20000-20010"}`,
	}
	for _, header := range []string{"srtp", "utp", "wechat", "dtls", "wireguard"} {
		udp["mkcp-legacy "+header] = `{"header":"` + header + `"}`
	}
	build := func(name, link string) {
		t.Helper()
		p, err := (&Core{}).CreateProtocol(link)
		if err != nil {
			t.Fatal(err)
		}
		if err := p.Parse(); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		ob, err := p.(Protocol).BuildOutboundDetourConfig(false)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if ob.StreamSetting.FinalMask == nil {
			t.Fatalf("%s: no finalmask", name)
		}
		if _, err := ob.Build(); err != nil {
			t.Errorf("%s: does not build: %v", name, err)
		}
	}
	for name, settings := range tcp {
		typ, _, _ := strings.Cut(name, " ")
		fm := `{"tcp":[{"type":"` + typ + `","settings":` + settings + `}]}`
		build("tcp "+name, "vless://00000000-0000-0000-0000-000000000000@1.2.3.4:443?security=tls&sni=example.com&fm="+url.QueryEscape(fm))
	}
	for name, settings := range udp {
		typ, _, _ := strings.Cut(name, " ")
		fm := `{"udp":[{"type":"` + typ + `","settings":` + settings + `}]}`
		build("udp "+name, "hy2://pw@1.2.3.4:443?sni=a.com&fm="+url.QueryEscape(fm))
	}
	build("quicParams", "hy2://pw@1.2.3.4:443?sni=a.com&fm="+url.QueryEscape(`{"quicParams":{"congestion":"force-brutal","brutalUp":"100mbps","brutalDown":"200mbps","bbrProfile":"aggressive","maxIdleTimeout":30,"keepAlivePeriod":10,"maxIncomingStreams":16}}`))
	build("shadowsocks", "ss://"+base64.RawURLEncoding.EncodeToString([]byte("aes-128-gcm:pw"))+"@1.2.3.4:8388/?fm="+url.QueryEscape(fragmentFM))
	build("vmess kcp", "vmess://"+base64.StdEncoding.EncodeToString([]byte(`{"v":"2","add":"1.2.3.4","port":"443","id":"00000000-0000-0000-0000-000000000000","net":"kcp","fm":`+noiseFM+`}`)))
}

func TestKCPLegacyParams(t *testing.T) {
	masks := func(link string) []string {
		t.Helper()
		p, err := (&Core{}).CreateProtocol(link)
		if err != nil {
			t.Fatal(err)
		}
		if err := p.Parse(); err != nil {
			t.Fatal(err)
		}
		ob, err := p.(Protocol).BuildOutboundDetourConfig(false)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ob.Build(); err != nil {
			t.Fatalf("%s does not build: %v", link, err)
		}
		var got []string
		if fm := ob.StreamSetting.FinalMask; fm != nil {
			for _, m := range fm.Udp {
				got = append(got, m.Type+string(*m.Settings))
			}
		}
		return got
	}
	vless := "vless://00000000-0000-0000-0000-000000000000@10.0.0.1:443?security=none&type=kcp"
	for link, want := range map[string]string{
		// No header or seed is still the original obfuscation, as in v2rayN.
		vless:                      `mkcp-legacy{"value":""}`,
		vless + "&headerType=none": `mkcp-legacy{"value":""}`,
		vless + "&fm=%7B%7D":       "",
		vless + "&seed=s":          `mkcp-legacy{"value":"s"}`,
		vless + "&headerType=srtp": `mkcp-legacy{"value":""} mkcp-legacy{"header":"srtp"}`,
		vless + "&headerType=wechat-video&seed=s": `mkcp-legacy{"value":"s"} mkcp-legacy{"header":"wechat"}`,
		// fm replaces what the legacy params imply.
		vless + "&headerType=srtp&seed=s&fm=" + url.QueryEscape(noiseFM): `noise{"noise":[{"rand":"10-20","delay":"5"}]}`,
		"vmess://" + base64.StdEncoding.EncodeToString([]byte(`{"v":"2","add":"10.0.0.1","port":"443","id":"00000000-0000-0000-0000-000000000000","net":"kcp","type":"dtls","path":"s"}`)): `mkcp-legacy{"value":"s"} mkcp-legacy{"header":"dtls"}`,
	} {
		if got := strings.Join(masks(link), " "); got != want {
			t.Errorf("%s:\n got %s\nwant %s", link, got, want)
		}
	}
}

func TestFinalMaskInbound(t *testing.T) {
	v := &Vless{OrigLink: "vless://00000000-0000-0000-0000-000000000000@127.0.0.1:10443?security=none&fm=" + url.QueryEscape(fragmentFM)}
	if err := v.Parse(); err != nil {
		t.Fatal(err)
	}
	in, err := v.BuildInboundDetourConfig()
	if err != nil {
		t.Fatal(err)
	}
	if fm := in.StreamSetting.FinalMask; fm == nil || len(fm.Tcp) != 1 {
		t.Fatalf("inbound finalmask = %+v", fm)
	}
	if _, err := in.Build(); err != nil {
		t.Fatalf("inbound with fm does not build: %v", err)
	}
}

func TestFinalMaskShadowsocksLink(t *testing.T) {
	s := &Shadowsocks{Address: "1.2.3.4", Port: "8388", Encryption: "aes-128-gcm", Password: "pw", Plugin: "obfs-local;obfs=http", FinalMask: fragmentFM}
	again := &Shadowsocks{OrigLink: s.GetLink()}
	if err := again.Parse(); err != nil {
		t.Fatal(err)
	}
	if again.FinalMask != fragmentFM || again.Plugin != s.Plugin {
		t.Errorf("round trip = %q, %q", again.FinalMask, again.Plugin)
	}
}
