package convert

import (
	"encoding/base64"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func clashProxies(t *testing.T, links []string, opts ClashOptions) []map[string]interface{} {
	t.Helper()
	out, _, err := ToClash(links, opts)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Proxies []map[string]interface{} `yaml:"proxies"`
	}
	if err := yaml.Unmarshal(out, &doc); err != nil {
		t.Fatalf("invalid YAML (duplicate key?): %v\n%s", err, out)
	}
	return doc.Proxies
}

// mihomo rejects a vmess proxy without alterId.
func TestClashVmessAlterIDZero(t *testing.T) {
	vm := `{"add":"v.example.com","port":"443","id":"11111111-2222-3333-4444-555555555555","aid":"0","net":"ws","path":"/ws","tls":"tls","ps":"vm"}`
	p := clashProxies(t, []string{"vmess://" + base64.StdEncoding.EncodeToString([]byte(vm))}, ClashOptions{})
	if v, ok := p[0]["alterId"]; !ok || v != 0 {
		t.Fatalf("alterId = %v (present %v)", v, ok)
	}
}

// Proxy names may not shadow the groups or mihomo's built-in policies.
func TestClashReservedNames(t *testing.T) {
	links := []string{
		"trojan://pw@t.example.com:443?sni=t.example.com#auto",
		"trojan://pw@t.example.com:443?sni=t.example.com#PROXY",
		"trojan://pw@t.example.com:443?sni=t.example.com#DIRECT",
		"trojan://pw@t.example.com:443?sni=t.example.com#mine",
	}
	var names []string
	for _, p := range clashProxies(t, links, ClashOptions{}) {
		names = append(names, p["name"].(string))
	}
	if strings.Join(names, "|") != "auto 2|PROXY 2|DIRECT 2|mine" {
		t.Fatalf("names = %v", names)
	}
	p := clashProxies(t, links[3:], ClashOptions{AutoGroup: "mine"})
	if p[0]["name"] != "mine 2" {
		t.Fatalf("custom group name not reserved: %v", p[0]["name"])
	}
}

// mihomo takes one ip and one ipv6; extra addresses must not repeat keys.
func TestClashWireguardOneAddressPerFamily(t *testing.T) {
	link := "wireguard://" + wgPrivate + "@1.2.3.4:51820?publickey=" + strings.ReplaceAll(wgPublic, "+", "%2B") +
		"&address=10.0.0.2%2F32,10.0.0.3%2F32,fd00::2%2F128,fd00::3%2F128#wg"
	p := clashProxies(t, []string{link}, ClashOptions{})
	if p[0]["ip"] != "10.0.0.2/32" || p[0]["ipv6"] != "fd00::2/128" {
		t.Fatalf("ip/ipv6 = %v / %v", p[0]["ip"], p[0]["ipv6"])
	}
}
