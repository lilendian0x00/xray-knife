package web

import (
	"fmt"
	"strings"
	"sync"

	"github.com/lilendian0x00/xray-knife/v11/pkg/core"
	"github.com/lilendian0x00/xray-knife/v11/pkg/core/mtproto"
	"github.com/lilendian0x00/xray-knife/v11/pkg/core/protocol"
	"github.com/lilendian0x00/xray-knife/v11/pkg/core/singbox"
	"github.com/lilendian0x00/xray-knife/v11/pkg/core/xray"
)

// protocolInfo is one share-link scheme the automatic core accepts.
type protocolInfo struct {
	Scheme string `json:"scheme"`
	Core   string `json:"core"`
}

// candidateSchemes are the schemes worth probing; aliases (hy2, socks5)
// route like their canonical names and are left out.
var candidateSchemes = []string{
	"vmess", "vless", "trojan", "ss", "socks", "wireguard",
	"hysteria2", "hysteria", "tuic", "anytls", "ssh", "shadowtls", "naive",
}

// supportedProtocols asks the automatic core which schemes it can build,
// so /info follows the cores as protocols are added without a list to
// keep in sync here.
var supportedProtocols = sync.OnceValue(func() []protocolInfo {
	c := core.NewAutomaticCore(false, false)
	out := []protocolInfo{}
	for _, scheme := range candidateSchemes {
		p, err := func() (p protocol.Protocol, err error) {
			// A parser bug must not take /info down with it.
			defer func() {
				if r := recover(); r != nil {
					p, err = nil, fmt.Errorf("probe panicked: %v", r)
				}
			}()
			return c.CreateProtocol(scheme + "://probe@127.0.0.1:1")
		}()
		if err != nil {
			if strings.Contains(err.Error(), "unsupported") {
				continue
			}
			// Another error (e.g. the probe link itself) still means the
			// scheme is routed; report it without a core.
			out = append(out, protocolInfo{Scheme: scheme})
			continue
		}
		name := ""
		switch p.(type) {
		case xray.Protocol:
			name = "xray"
		case singbox.Protocol:
			name = "sing-box"
		}
		out = append(out, protocolInfo{Scheme: scheme, Core: name})
	}
	// MTProto links (tg://proxy, t.me/proxy) are probed natively.
	if p, err := c.CreateProtocol("tg://proxy?server=127.0.0.1&port=1&secret=00112233445566778899aabbccddeeff"); err == nil {
		if _, ok := p.(*mtproto.MTProto); ok {
			out = append(out, protocolInfo{Scheme: "mtproto", Core: "mtproto"})
		}
	}
	return out
})
