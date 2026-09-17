package core

import (
	"context"
	"errors"
	"testing"

	"github.com/lilendian0x00/xray-knife/v11/pkg/core/mtproto"
)

// Asserted here rather than in mtproto: pkg/core imports it, not the reverse.
var _ Core = (*mtproto.Core)(nil)

func TestAutomaticCoreRoutesMTProtoLinks(t *testing.T) {
	c := NewAutomaticCore(false, false).(*AutomaticCore)
	const secret = "00112233445566778899aabbccddeeff"
	proxyLinks := []string{
		"tg://proxy?server=1.2.3.4&port=443&secret=" + secret,
		"https://t.me/proxy?server=1.2.3.4&port=443&secret=" + secret,
		"https://telegram.me/proxy?server=1.2.3.4&port=443&secret=" + secret,
		"http://telegram.dog/proxy?server=1.2.3.4&port=443&secret=" + secret,
	}
	for _, link := range proxyLinks {
		selected, err := c.selectCoreForLink(link)
		if err != nil {
			t.Fatalf("%s: %v", link, err)
		}
		if selected.Name() != "mtproto" {
			t.Errorf("%s routed to %s", link, selected.Name())
		}
		p, err := c.CreateProtocol(link)
		if err != nil {
			t.Fatalf("CreateProtocol(%s): %v", link, err)
		}
		if err := p.Parse(); err != nil {
			t.Fatalf("Parse(%s): %v", link, err)
		}
		if g := p.ConvertToGeneralConfig(); g.Protocol != "mtproto" || g.Address != "1.2.3.4" || g.Port != "443" {
			t.Errorf("%s: GeneralConfig = %+v", link, g)
		}
		if _, err := c.MakeInstance(context.Background(), p); !errors.Is(err, mtproto.ErrNotProxyable) {
			t.Errorf("%s: MakeInstance err = %v, want ErrNotProxyable", link, err)
		}
		if _, _, err := c.MakeHttpClient(context.Background(), p, 0); !errors.Is(err, mtproto.ErrNotProxyable) {
			t.Errorf("%s: MakeHttpClient err = %v, want ErrNotProxyable", link, err)
		}
	}

	for _, link := range []string{
		"https://t.me/joinchat/abc",
		"tg://evil/proxy?server=a&port=1&secret=b",
		"tg://proxy/extra?server=a&port=1&secret=b",
		"https://user@t.me/proxy?server=a&port=1&secret=b",
		"https://example.com/proxy?server=a&port=1&secret=b",
		"https://sub.example.com/list.txt",
		"vless://uuid@host:443?type=tcp",
	} {
		selected, err := c.selectCoreForLink(link)
		if err == nil && selected.Name() == "mtproto" {
			t.Errorf("%s wrongly routed to mtproto", link)
		}
	}
}

func TestExplicitCoresStillRejectMTProto(t *testing.T) {
	links := []string{
		"tg://proxy?server=1.2.3.4&port=443&secret=00112233445566778899aabbccddeeff",
		"https://t.me/proxy?server=1.2.3.4&port=443&secret=00112233445566778899aabbccddeeff",
	}
	for _, ct := range []CoreType{XrayCoreType, SingboxCoreType} {
		for _, link := range links {
			_, err := CoreFactory(ct, false, false).CreateProtocol(link)
			if err == nil {
				t.Errorf("core %d accepted an mtproto link %s", ct, link)
				continue
			}
			if !errors.Is(err, mtproto.ErrNotProxyable) {
				t.Errorf("core %d, %s: err = %v, want ErrNotProxyable", ct, link, err)
			}
		}
	}
}
