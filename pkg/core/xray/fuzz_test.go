package xray

import (
	"encoding/base64"
	"testing"
)

// exercise runs every method a caller may use on a parsed link. None of
// them may panic, whatever the input.
func exercise(p Protocol) {
	if p.Parse() != nil {
		return
	}
	_ = p.DetailsStr()
	_ = p.GetLink()
	_ = p.ConvertToGeneralConfig()
	if ob, err := p.BuildOutboundDetourConfig(true); err == nil {
		_, _ = ob.Build()
	}
	if in, err := p.BuildInboundDetourConfig(); err == nil {
		_, _ = in.Build()
	}
}

func fuzzLinks(f *testing.F, newProto func(string) Protocol, seeds ...string) {
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, link string) {
		exercise(newProto(link))
		// CreateProtocol must reject or route any input without panicking.
		if p, err := (&Core{}).CreateProtocol(link); err == nil {
			exercise(p.(Protocol))
		}
	})
}

func FuzzVless(f *testing.F) {
	fuzzLinks(f, NewVless,
		"vless://00000000-0000-0000-0000-000000000000@1.2.3.4:443?security=reality&type=tcp&sni=a.com&pbk=k&sid=1#r",
		"vless://u@[2001:db8::1]:80?type=ws&host=a.com&path=%2F#100%",
		"vless://u@h:1?type=xhttp&extra=%7B%7D&mode=auto",
		"vless://",
	)
}

func FuzzTrojan(f *testing.F) {
	fuzzLinks(f, NewTrojan,
		"trojan://p%40ss@example.com:443?type=grpc&serviceName=s&security=tls#t",
		"trojan://pass@1.2.3.4:443?flow=xtls-rprx-vision",
		"trojan://@:",
	)
}

func FuzzVmess(f *testing.F) {
	j := `{"add":"1.2.3.4","port":443,"id":"u","net":"ws","tls":"tls","aid":"0"}`
	fuzzLinks(f, NewVmess,
		"vmess://"+base64.StdEncoding.EncodeToString([]byte(j)),
		"vmess://"+base64.RawURLEncoding.EncodeToString([]byte("auto:uuid@host:443"))+"?obfs=websocket&tls=1",
		"vmess://e30",
		"vmess://",
	)
}

func FuzzShadowsocks(f *testing.F) {
	fuzzLinks(f, NewShadowsocks,
		"ss://YWVzLTI1Ni1nY206cGFzcw@1.2.3.4:8388#x",
		"ss://"+base64.StdEncoding.EncodeToString([]byte("aes-256-gcm:p@ss@1.2.3.4:1")),
		"ss://2022-blake3-aes-128-gcm:k+ey@[::1]:1/?plugin=obfs-local%3Bobfs%3Dhttp",
		"ss:", "ss://@",
	)
}

func FuzzSocks(f *testing.F) {
	fuzzLinks(f, NewSocks,
		"socks://dXNlcjpwYXNz@1.2.3.4:1080#s",
		"socks5://u:p@[::1]:1",
		"socks://",
	)
}

func FuzzWireguard(f *testing.F) {
	fuzzLinks(f, NewWireguard,
		"wireguard://a+b/c=@1.2.3.4:51820?publickey=x+y=&address=10.0.0.2/32&reserved=1,2,3&mtu=1280#w",
		"wireguard://k@[::1]:1?address=fd00::2",
		"wireguard://@",
	)
}

func FuzzHysteria2(f *testing.F) {
	fuzzLinks(f, NewHysteria2,
		"hysteria2://pass@1.2.3.4:443?sni=a.com&obfs=salamander&obfs-password=x#h",
		"hy2://p@h:443,20000-30000/?insecure=1",
		"hy2://",
	)
}
