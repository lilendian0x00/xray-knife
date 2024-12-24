package singbox

import (
	"testing"
)

func TestNewHysteria2(t *testing.T) {
	link := "hysteria2://fKt0mUHH2UKx6kl3xdI43yiV@laser.kafsabtaheri.com:8443/?sni=laser.kafsabtaheri.com&alpn=h3%2Ch2%2Chttp%2F1.1&obfs=salamander&obfs-password=HGdgfYUJFGjgD&insecure=1#H"

	hys2 := NewHysteria2(link)
	err := hys2.Parse()
	if err != nil {
		t.Errorf("%s\n", hys2.DetailsStr())
		return
	}

	t.Logf("%s\n", hys2.DetailsStr())
}

//func TestHysteria2_MakeHttpClient(t *testing.T) {
//	var hys2 Hysteria2
//	err := hys2.Parse("hysteria2://fKt0mUHH2UKx6kl3xdI43yiV@laser.kafsabtaheri.com:8443/?sni=laser.kafsabtaheri.com&alpn=h3%2Ch2%2Chttp%2F1.1&obfs=salamander&obfs-password=HGdgfYUJFGjgD&insecure=1#H")
//	if err != nil {
//		t.Errorf("Error when parsing: %v", err)
//	}
//
//	l, _ := log.New(log.Options{
//		Options: option.LogOptions{},
//	})
//
//	outbound, err := hys2.CraftOutbound(context.Background(), l.Logger())
//	if err != nil {
//		return
//	}
//
//	t.Logf("%s\n", hys2.DetailsStr())
//}
