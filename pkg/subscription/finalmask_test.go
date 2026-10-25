package subscription

import (
	"net/url"
	"strings"
	"testing"

	"github.com/lilendian0x00/xray-knife/v11/pkg/core/xray"
)

func TestXrayFinalMaskCarriedToLinks(t *testing.T) {
	config := `{"outbounds": [
    {"protocol": "vless", "tag": "fm-vless", "settings": {"vnext": [{"address": "1.2.3.4", "port": 443, "users": [{"id": "` + uuid1 + `", "encryption": "none"}]}]},
     "streamSettings": {"network": "tcp", "security": "tls", "tlsSettings": {"serverName": "a.com"},
       "finalmask": {"tcp": [{"type": "fragment", "settings": {"packets": "tlshello", "length": "100-200", "delay": "10-20"}}]}}},
    {"protocol": "hysteria", "tag": "fm-hy2", "settings": {"version": 2, "address": "h.example.com", "port": 443},
     "streamSettings": {"network": "hysteria", "security": "tls", "tlsSettings": {"serverName": "h.example.com"}, "hysteriaSettings": {"version": 2, "auth": "pw"},
       "finalmask": {"udp": [{"type": "salamander", "settings": {"password": "op"}}, {"type": "noise", "settings": {"noise": [{"rand": "10-20", "delay": "5"}]}}]}}},
    {"protocol": "wireguard", "tag": "fm-wg", "settings": {"secretKey": "` + wgKey + `", "address": ["172.16.0.2/32"], "peers": [{"endpoint": "162.159.192.1:2408", "publicKey": "` + wgPub + `"}]},
     "streamSettings": {"finalmask": {"udp": [{"type": "noise", "settings": {"noise": [{"rand": "10-20", "delay": "5"}]}}]}}}
  ]}`
	res, err := DecodeDetailed([]byte(config), DecodeOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Links) != 3 {
		t.Fatalf("links = %v", res.Links)
	}
	fm := func(link string) string {
		_, rawQuery, _ := strings.Cut(link, "?")
		rawQuery, _, _ = strings.Cut(rawQuery, "#")
		q, _ := url.ParseQuery(rawQuery)
		return q.Get("fm")
	}

	if got := fm(res.Links[0]); !strings.Contains(got, `"fragment"`) {
		t.Errorf("vless fm = %q", got)
	}
	v := &xray.Vless{OrigLink: res.Links[0]}
	if err := v.Parse(); err != nil {
		t.Fatal(err)
	}
	if ob, err := v.BuildOutboundDetourConfig(false); err != nil || ob.StreamSetting.FinalMask == nil || ob.StreamSetting.FinalMask.Tcp[0].Type != "fragment" {
		t.Errorf("vless finalmask not rebuilt: %v", err)
	}

	// Salamander is in obfs, and fm keeps the masks in their order.
	hy2 := res.Links[1]
	if got := fm(hy2); !strings.Contains(hy2, "obfs=salamander") || strings.Index(got, "salamander") < 0 || strings.Index(got, "salamander") > strings.Index(got, `"noise"`) {
		t.Errorf("hysteria2 link = %s", hy2)
	}

	if got := fm(res.Links[2]); !strings.Contains(got, `"noise"`) {
		t.Errorf("wireguard fm = %q", got)
	}
}
