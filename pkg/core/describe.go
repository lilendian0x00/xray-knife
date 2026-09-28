package core

import (
	"github.com/lilendian0x00/xray-knife/v11/pkg/core/mtproto"
	"github.com/lilendian0x00/xray-knife/v11/pkg/core/protocol"
)

// DescribeLink parses link with c for its protocol name and remark. ok is
// false when the link cannot be created or parsed (a parser panic
// included) or names no protocol.
func DescribeLink(c Core, link string) (proto, remark string, ok bool) {
	defer func() {
		if recover() != nil {
			proto, remark, ok = "", "", false
		}
	}()
	p, err := c.CreateProtocol(link)
	if err != nil || p.Parse() != nil {
		return "", "", false
	}
	g := p.ConvertToGeneralConfig()
	return g.Protocol, g.Remark, g.Protocol != ""
}

// CreateRelayProtocol is c.CreateProtocol for callers that need an
// outbound carrying general traffic (a chain hop, a scan target). A
// protocol that cannot relay (protocol.Relays) fails with
// mtproto.ErrNotProxyable whichever core created it: xray and sing-box
// refuse MTProto links themselves, the automatic core parses them for its
// native probe.
func CreateRelayProtocol(c Core, link string) (protocol.Protocol, error) {
	p, err := c.CreateProtocol(link)
	if err != nil {
		return nil, err
	}
	if !protocol.Relays(p) {
		return nil, mtproto.ErrNotProxyable
	}
	return p, nil
}
