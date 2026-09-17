package mtproto

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestCoreCreateProtocol(t *testing.T) {
	c := NewCore()
	if c.Name() != "mtproto" {
		t.Errorf("Name() = %q", c.Name())
	}
	p, err := c.CreateProtocol("  tg://proxy?server=a.b&port=1&secret=" + testKeyHex + "  ")
	if err != nil {
		t.Fatal(err)
	}
	m, ok := p.(*MTProto)
	if !ok {
		t.Fatalf("CreateProtocol returned %T", p)
	}
	if m.OrigLink != "tg://proxy?server=a.b&port=1&secret="+testKeyHex {
		t.Errorf("OrigLink not trimmed: %q", m.OrigLink)
	}
	if _, err := c.CreateProtocol("vless://uuid@host:443"); err == nil {
		t.Error("non-proxy link accepted")
	}
}

func TestCoreRefusesOutboundUse(t *testing.T) {
	c := NewCore()
	p := NewMTProto("tg://proxy?server=a.b&port=1&secret=" + testKeyHex)
	if _, _, err := c.MakeHttpClient(context.Background(), p, time.Second); !errors.Is(err, ErrNotProxyable) {
		t.Errorf("MakeHttpClient err = %v", err)
	}
	if _, err := c.MakeInstance(context.Background(), p); !errors.Is(err, ErrNotProxyable) {
		t.Errorf("MakeInstance err = %v", err)
	}
	if err := c.SetInbound(p); !errors.Is(err, ErrNotProxyable) {
		t.Errorf("SetInbound err = %v", err)
	}
}
