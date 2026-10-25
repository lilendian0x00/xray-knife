package xray

import (
	"encoding/base64"
	"net/url"
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
	if !h.NeedsXray() {
		t.Error("noise in fm should need xray")
	}

	for link, want := range map[string]bool{
		// The salamander that panels repeat in fm is what obfs already says.
		"hy2://pw@1.2.3.4:443?obfs=salamander&obfs-password=x&fm=" + url.QueryEscape(`{"udp":[{"type":"salamander","settings":{"password":"x"}}]}`): false,
		"hy2://pw@1.2.3.4:443?fm=" + url.QueryEscape(`{"udp":[{"type":"salamander","settings":{"password":"x"}}]}`):                                 true,
		"hy2://pw@1.2.3.4:443?fm=" + url.QueryEscape(`{"quicParams":{"congestion":"bbr"}}`):                                                         true,
		"hy2://pw@1.2.3.4:443": false,
	} {
		h := &Hysteria2{OrigLink: link}
		if err := h.Parse(); err != nil {
			t.Fatal(err)
		}
		if got := h.NeedsXray(); got != want {
			t.Errorf("%s: NeedsXray = %v, want %v", link, got, want)
		}
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
}
