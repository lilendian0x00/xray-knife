package core

import (
	"strings"
	"testing"

	"github.com/lilendian0x00/xray-knife/v11/pkg/core/singbox"
)

func TestAutomaticCoreRoutesSingboxOnlyProtocols(t *testing.T) {
	c := NewAutomaticCore(false, false).(*AutomaticCore)
	for _, link := range []string{
		"tuic://00000000-0000-0000-0000-000000000000:pw@1.2.3.4:443?sni=a.com&alpn=h3",
		"anytls://pw@1.2.3.4:443?sni=a.com",
		"hysteria://1.2.3.4:443?auth=pw&peer=a.com&upmbps=10&downmbps=50",
		"ssh://root:pw@1.2.3.4:22",
		"TUIC://00000000-0000-0000-0000-000000000000:pw@1.2.3.4:443",
		"hysteria2://pw@1.2.3.4:443",
	} {
		selected, err := c.selectCoreForLink(link)
		if err != nil {
			t.Fatalf("%s: %v", link, err)
		}
		if selected != c.singboxCore {
			t.Errorf("%s routed to %s, want sing-box", link, selected.Name())
		}
		p, err := c.CreateProtocol(link)
		if err != nil {
			t.Fatalf("CreateProtocol(%s): %v", link, err)
		}
		if _, ok := p.(singbox.Protocol); !ok {
			t.Fatalf("%s: created %T", link, p)
		}
		if err := p.Parse(); err != nil {
			t.Fatalf("Parse(%s): %v", link, err)
		}
		if g := p.ConvertToGeneralConfig(); g.Address != "1.2.3.4" || g.Port == "" || g.OrigLink == "" {
			t.Errorf("%s: GeneralConfig = %+v", link, g)
		}
		if got, err := c.coreFor(p); err != nil || got != c.singboxCore {
			t.Errorf("%s: coreFor = %v, %v", link, got, err)
		}
	}
}

func TestAutomaticCoreRoutesHTTPProxyLinks(t *testing.T) {
	c := NewAutomaticCore(false, false).(*AutomaticCore)
	for _, link := range []string{"http://u:p@1.2.3.4:8080#h", "https://1.2.3.4:443?sni=a.com&insecure=1"} {
		selected, err := c.selectCoreForLink(link)
		if err != nil || selected != c.singboxCore {
			t.Fatalf("%s: %v, %v", link, selected, err)
		}
		p, err := c.CreateProtocol(link)
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := p.(*singbox.HTTPProxy); !ok {
			t.Fatalf("%s: created %T", link, p)
		}
	}
	// t.me proxy links are https too but belong to MTProto.
	if selected, err := c.selectCoreForLink("https://t.me/proxy?server=1.2.3.4&port=443&secret=00112233445566778899aabbccddeeff"); err != nil || selected != c.mtprotoCore {
		t.Fatalf("t.me link routed to %v, %v", selected, err)
	}
	for _, web := range []string{"https://sub.example.com/list.txt", "http://example.com", "https://u:secret@example.com/x"} {
		_, err := c.selectCoreForLink(web)
		if err == nil {
			t.Errorf("%s routed as a proxy", web)
		} else if strings.Contains(err.Error(), "secret") {
			t.Errorf("error leaks credentials: %v", err)
		}
	}
}
