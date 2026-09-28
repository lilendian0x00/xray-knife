package core

import (
	"errors"
	"testing"

	"github.com/lilendian0x00/xray-knife/v11/pkg/core/mtproto"
	"github.com/lilendian0x00/xray-knife/v11/pkg/core/protocol"
)

const (
	describeVless   = "vless://11111111-1111-1111-1111-111111111111@1.2.3.4:443?encryption=none&security=tls&type=tcp#home"
	describeMTProto = "tg://proxy?server=9.9.9.9&port=443&secret=dd00112233445566778899aabbccddeeff"
)

// panicCore's parser panics, as a malformed link once made one do.
type panicCore struct{ Core }

func (panicCore) CreateProtocol(string) (protocol.Protocol, error) { panic("boom") }

func TestDescribeLink(t *testing.T) {
	c := NewAutomaticCore(false, false)
	if proto, remark, ok := DescribeLink(c, describeVless); !ok || proto != "vless" || remark != "home" {
		t.Fatalf("vless = %q %q %v", proto, remark, ok)
	}
	if _, _, ok := DescribeLink(c, "vless://not a link"); ok {
		t.Fatal("garbage link described")
	}
	if _, _, ok := DescribeLink(panicCore{c}, describeVless); ok {
		t.Fatal("panicking parser described")
	}
}

// Every core refuses an MTProto link as an outbound the same way.
func TestCreateRelayProtocolRefusesMTProto(t *testing.T) {
	cores := map[string]Core{
		"automatic": NewAutomaticCore(false, false),
		"xray":      CoreFactory(XrayCoreType, false, false),
		"singbox":   CoreFactory(SingboxCoreType, false, false),
	}
	for name, c := range cores {
		if _, err := CreateRelayProtocol(c, describeMTProto); !errors.Is(err, mtproto.ErrNotProxyable) {
			t.Errorf("%s: err = %v, want ErrNotProxyable", name, err)
		}
		if p, err := CreateRelayProtocol(c, describeVless); err != nil || !protocol.Relays(p) {
			t.Errorf("%s: vless = %v, %v", name, p, err)
		}
	}
	// The automatic core still creates it for the native probe.
	if p, err := NewAutomaticCore(false, false).CreateProtocol(describeMTProto); err != nil || protocol.Relays(p) {
		t.Fatalf("automatic mtproto = %v, %v", p, err)
	}
}
