package convert

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/url"
	"strings"
	"testing"

	"github.com/lilendian0x00/xray-knife/v11/pkg/core"
	"github.com/lilendian0x00/xray-knife/v11/pkg/core/singbox"
	"github.com/lilendian0x00/xray-knife/v11/pkg/subscription"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/certificate"
	"github.com/sagernet/sing-box/adapter/endpoint"
	"github.com/sagernet/sing-box/adapter/inbound"
	boxOutbound "github.com/sagernet/sing-box/adapter/outbound"
	boxService "github.com/sagernet/sing-box/adapter/service"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/dns"
	dnsTransport "github.com/sagernet/sing-box/dns/transport"
	"github.com/sagernet/sing-box/dns/transport/local"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/direct"
	"github.com/sagernet/sing-box/protocol/group"
	boxHTTP "github.com/sagernet/sing-box/protocol/http"
	"github.com/sagernet/sing-box/protocol/hysteria"
	"github.com/sagernet/sing-box/protocol/hysteria2"
	"github.com/sagernet/sing-box/protocol/mixed"
	"github.com/sagernet/sing-box/protocol/shadowsocks"
	"github.com/sagernet/sing-box/protocol/socks"
	"github.com/sagernet/sing-box/protocol/ssh"
	"github.com/sagernet/sing-box/protocol/trojan"
	"github.com/sagernet/sing-box/protocol/tuic"
	"github.com/sagernet/sing-box/protocol/vless"
	"github.com/sagernet/sing-box/protocol/vmess"
	"github.com/sagernet/sing-box/protocol/wireguard"
	sjson "github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/service"
	"github.com/xtls/xray-core/infra/conf"
	"gopkg.in/yaml.v3"
)

const uuid = "11111111-1111-1111-1111-111111111111"

// Real-sized keys: xray validates REALITY and WireGuard keys. The
// WireGuard ones contain "+" and "/" on purpose.
var (
	realityKey = base64.RawURLEncoding.EncodeToString(bytes32(7))
	wgPrivate  = base64.StdEncoding.EncodeToString(append([]byte{0xfb, 0xef, 0xbe, 0xff, 0xff, 0xff}, bytes32(1)[6:]...))
	wgPublic   = base64.StdEncoding.EncodeToString(append([]byte{0xff, 0xef, 0xbe}, bytes32(2)[3:]...))
)

func bytes32(b byte) []byte {
	out := make([]byte, 32)
	for i := range out {
		out[i] = b
	}
	return out
}

func vmessJSON(fields string) string {
	return "vmess://" + base64.StdEncoding.EncodeToString([]byte(fields))
}

// links covers every protocol and transport each exporter maps. They use
// only options the formats can carry, so a Clash round trip is lossless.
var links = []string{
	"vless://" + uuid + "@1.2.3.4:443?security=reality&sni=www.microsoft.com&pbk=" + realityKey + "&sid=ab&flow=xtls-rprx-vision&fp=firefox#reality",
	"vless://" + uuid + "@v.example.com:443?security=tls&sni=v.example.com&type=ws&host=cdn.example.com&path=%2Fws%3Fed%3D2048&alpn=h2%2Chttp%2F1.1#vless-ws",
	"vless://" + uuid + "@v.example.com:443?security=tls&sni=v.example.com&type=grpc&serviceName=svc#vless-grpc",
	"vless://" + uuid + "@v.example.com:80?type=tcp&headerType=http&host=a.example.com&path=%2Fp#vless-http",
	"vless://" + uuid + "@v.example.com:443?security=tls&sni=v.example.com&type=httpupgrade&host=h.example.com&path=%2Fu#vless-upgrade",
	"vless://" + uuid + "@x.example.com:443?security=tls&sni=x.example.com&type=xhttp&path=%2Fx&mode=auto#vless-xhttp",
	vmessJSON(`{"add":"m.example.com","port":"443","id":"` + uuid + `","net":"ws","host":"cdn.example.com","path":"/m","tls":"tls","sni":"m.example.com","ps":"vmess-ws"}`),
	"trojan://p%40ss@t.example.com:443?sni=t.example.com&allowInsecure=1#trojan",
	"ss://" + base64.RawURLEncoding.EncodeToString([]byte("aes-256-gcm:secret")) + "@5.6.7.8:8388/?plugin=obfs-local%3Bobfs%3Dhttp%3Bobfs-host%3Dbing.com#ss-obfs",
	"ss://2022-blake3-aes-128-gcm:YWJj%2BZGVm%2FZw%3D%3D@[2001:db8::1]:443#ss2022",
	"socks://u:p@9.9.9.9:1080#socks",
	"wireguard://" + wgPrivate + "@162.159.192.1:2408?publickey=" + url.QueryEscape(wgPublic) + "&address=172.16.0.2&reserved=1%2C2%2C3&mtu=1280#wg",
	"hysteria2://pw@h.example.com:443?sni=h.example.com&obfs=salamander&obfs-password=op&mport=20000-30000&insecure=1#hy2",
	"tuic://" + uuid + ":pw@q.example.com:443?sni=q.example.com&alpn=h3&congestion_control=bbr&udp_relay_mode=quic#tuic",
	"anytls://pw@a.example.com:443?sni=a.example.com&insecure=1#anytls",
	"hysteria://h1.example.com:443?auth=pw&peer=h1.example.com&upmbps=30&downmbps=100&obfsParam=xo#hysteria",
	"ssh://u:p@s.example.com:2222?hk=ssh-ed25519%20AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl#ssh",
	"tg://proxy?server=1.2.3.4&port=443&secret=dd00112233445566778899aabbccddeeff#mtproto",
	"vless://" + uuid + "@k.example.com:443?type=kcp#kcp",
	"http://u:p@7.7.7.7:3128#http",
	"https://u:p@8.8.8.8:8443?sni=p.example.com#https",
	"vless://" + uuid + "@v.example.com:80?type=ws&host=cdn.example.com&path=%2Fplain#vless-ws-plain",
	"",
}

func fingerprints(t *testing.T, in []string) map[string]string {
	t.Helper()
	c := core.NewAutomaticCore(false, false)
	out := map[string]string{}
	for _, l := range in {
		f, err := core.ConnectionFingerprint(c, l)
		if err != nil {
			continue
		}
		p, _ := c.CreateProtocol(l)
		_ = p.Parse()
		out[p.ConvertToGeneralConfig().Remark] = f
	}
	return out
}

func TestPlainAndBase64(t *testing.T) {
	in := []string{" vless://a@h:1 ", "", "trojan://b@h:2"}
	if got := string(ToPlain(in)); got != "vless://a@h:1\ntrojan://b@h:2\n" {
		t.Fatalf("plain = %q", got)
	}
	decoded, err := subscription.Decode(ToBase64(in), subscription.DecodeOptions{})
	if err != nil || strings.Join(decoded, "|") != "vless://a@h:1|trojan://b@h:2" {
		t.Fatalf("base64 round trip = %v, %v", decoded, err)
	}
}

func TestToClashRoundTrip(t *testing.T) {
	out, report, err := ToClash(links, ClashOptions{})
	if err != nil {
		t.Fatal(err)
	}
	// MTProto and the mKCP link have no Clash form; the blank entry is ignored.
	if report.Converted != len(links)-3 || len(report.Skipped) != 2 {
		t.Fatalf("report = %+v", report)
	}

	var doc struct {
		Proxies     []map[string]interface{} `yaml:"proxies"`
		ProxyGroups []map[string]interface{} `yaml:"proxy-groups"`
		Rules       []string                 `yaml:"rules"`
	}
	if err := yaml.Unmarshal(out, &doc); err != nil {
		t.Fatalf("invalid YAML: %v\n%s", err, out)
	}
	if len(doc.ProxyGroups) != 2 || doc.ProxyGroups[0]["type"] != "select" || doc.ProxyGroups[1]["type"] != "url-test" || doc.Rules[0] != "MATCH,PROXY" {
		t.Fatalf("groups/rules = %+v %v", doc.ProxyGroups, doc.Rules)
	}
	if first := doc.Proxies[0]; first["name"] != "reality" || first["type"] != "vless" {
		t.Fatalf("first proxy = %v", first)
	}

	// Re-import through the subscription decoder: every proxy must come
	// back as the same connection.
	reimported, err := subscription.Decode(out, subscription.DecodeOptions{})
	if err != nil {
		t.Fatal(err)
	}
	want := fingerprints(t, links)
	got := fingerprints(t, reimported)
	for name, f := range got {
		if want[name] != f {
			t.Errorf("%s: fingerprint changed through Clash\n  in:  %s", name, linkNamed(links, name))
		}
	}
	for name := range want {
		if _, ok := got[name]; !ok && name != "mtproto" && name != "kcp" {
			t.Errorf("%s missing after re-import", name)
		}
	}
}

func linkNamed(in []string, name string) string {
	for _, l := range in {
		if strings.HasSuffix(l, "#"+name) {
			return l
		}
	}
	return "?"
}

func TestToSingboxBuilds(t *testing.T) {
	out, report, err := ToSingbox(links, SingboxOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if report.Converted == 0 {
		t.Fatalf("nothing converted: %+v", report)
	}
	for _, s := range report.Skipped {
		if s.Name == "reality" {
			t.Errorf("REALITY skipped: the export must not depend on build tags: %s", s.Reason)
		}
		t.Logf("skipped %d %s: %s", s.Index, s.Name, s.Reason)
	}
	ctx := testContext()
	opts, err := sjson.UnmarshalExtendedContext[option.Options](ctx, out)
	if err != nil {
		t.Fatalf("sing-box rejects the exported options: %v\n%s", err, out)
	}
	if opts.Route == nil || opts.Route.Final != "proxy" || len(opts.Inbounds) != 1 {
		t.Fatalf("route/inbounds = %+v %+v", opts.Route, opts.Inbounds)
	}

	// box.New wires every outbound; keep to the protocols a default build
	// (no QUIC or gVisor tags) can instantiate. The export assumes uTLS,
	// so TLS links only instantiate in builds that have it.
	want := []string{"socks", "ss-obfs", "http", "vless-ws-plain"}
	if singbox.UTLSAvailable() {
		want = append(want, "vless-ws", "vless-grpc", "trojan", "https", "reality")
	}
	var subset []string
	for _, name := range want {
		subset = append(subset, linkNamed(links, name))
	}
	out, report, err = ToSingbox(subset, SingboxOptions{})
	if err != nil || len(report.Skipped) != 0 {
		t.Fatalf("subset export: %v, %+v", err, report)
	}
	opts, err = sjson.UnmarshalExtendedContext[option.Options](ctx, out)
	if err != nil {
		t.Fatal(err)
	}
	instance, err := box.New(box.Options{Context: ctx, Options: opts})
	if err != nil {
		t.Fatalf("box.New: %v\n%s", err, out)
	}
	instance.Close()
}

func TestToXrayBuilds(t *testing.T) {
	out, report, err := ToXray(links)
	if err != nil {
		t.Fatal(err)
	}
	// sing-box-only protocols, MTProto and the SS plugin link are skipped.
	skipped := map[string]bool{}
	for _, s := range report.Skipped {
		skipped[scheme(links[s.Index])] = true
	}
	for _, want := range []string{"tuic", "anytls", "hysteria", "ssh", "tg", "ss"} {
		if !skipped[want] {
			t.Errorf("%s not skipped: %+v", want, report.Skipped)
		}
	}
	var cfg conf.Config
	if err := json.Unmarshal(out, &cfg); err != nil {
		t.Fatalf("xray rejects the JSON: %v\n%s", err, out)
	}
	if len(cfg.OutboundConfigs) != report.Converted {
		t.Fatalf("%d outbounds, report says %d", len(cfg.OutboundConfigs), report.Converted)
	}
	for _, ob := range cfg.OutboundConfigs {
		if _, err := ob.Build(); err != nil {
			t.Errorf("outbound %s does not build: %v", ob.Tag, err)
		}
	}
	if cfg.OutboundConfigs[0].Tag != "reality" {
		t.Errorf("first outbound = %s", cfg.OutboundConfigs[0].Tag)
	}
}

func TestNothingToExport(t *testing.T) {
	for name, export := range map[string]func([]string) (*Report, error){
		"clash":   func(l []string) (*Report, error) { _, r, err := ToClash(l, ClashOptions{}); return r, err },
		"singbox": func(l []string) (*Report, error) { _, r, err := ToSingbox(l, SingboxOptions{}); return r, err },
		"xray":    func(l []string) (*Report, error) { _, r, err := ToXray(l); return r, err },
	} {
		r, err := export([]string{"tg://proxy?server=1.2.3.4&port=443&secret=dd00112233445566778899aabbccddeeff", "not a link"})
		if !errors.Is(err, ErrNothingToExport) || len(r.Skipped) != 2 {
			t.Errorf("%s: err %v, report %+v", name, err, r)
		}
	}
}

func TestUniqueNames(t *testing.T) {
	out, _, err := ToClash([]string{"socks://1.1.1.1:1#same", "socks://2.2.2.2:1#same", "socks://3.3.3.3:1"}, ClashOptions{})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"name: same\n", "name: same 2\n", "name: socks-3\n"} {
		if !strings.Contains(string(out), want) {
			t.Errorf("missing %q in\n%s", want, out)
		}
	}
}

// testContext registers every type ToSingbox emits. sing-box's include
// package can't be used: its AnyTLS outbound needs a module this repo
// doesn't have yet, so AnyTLS gets an options-only registration.
func testContext() context.Context {
	ctx := service.ContextWithDefaultRegistry(context.Background())
	in := inbound.NewRegistry()
	mixed.RegisterInbound(in)
	out := boxOutbound.NewRegistry()
	direct.RegisterOutbound(out)
	group.RegisterSelector(out)
	group.RegisterURLTest(out)
	for _, register := range []func(*boxOutbound.Registry){
		vless.RegisterOutbound, vmess.RegisterOutbound, trojan.RegisterOutbound, shadowsocks.RegisterOutbound,
		socks.RegisterOutbound, boxHTTP.RegisterOutbound, hysteria2.RegisterOutbound, hysteria.RegisterOutbound, tuic.RegisterOutbound, ssh.RegisterOutbound,
	} {
		register(out)
	}
	boxOutbound.Register[option.AnyTLSOutboundOptions](out, C.TypeAnyTLS,
		func(context.Context, adapter.Router, log.ContextLogger, string, option.AnyTLSOutboundOptions) (adapter.Outbound, error) {
			return nil, errors.New("anytls is options-only in this test")
		})
	ep := endpoint.NewRegistry()
	wireguard.RegisterEndpoint(ep)
	dnsRegistry := dns.NewTransportRegistry()
	dnsTransport.RegisterUDP(dnsRegistry)
	local.RegisterTransport(dnsRegistry)
	return box.Context(ctx, in, out, ep, dnsRegistry, boxService.NewRegistry(), certificate.NewRegistry())
}
