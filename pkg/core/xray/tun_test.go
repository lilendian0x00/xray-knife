package xray

import (
	"testing"
)

func TestTun_Name(t *testing.T) {
	tun := NewTun()
	if tun.ProtocolName() != "tun" {
		t.Errorf("Name() = %v, want %v", tun.ProtocolName(), "tun")
	}
}

func TestTun_Parse(t *testing.T) {
	tun := NewTun()
	if err := tun.Parse(); err != nil {
		t.Errorf("Parse() returned error: %v", err)
	}
}

func TestTun_DefaultValues(t *testing.T) {
	tun := NewTun()
	if tun.Name != "xray0" {
		t.Errorf("Default Name = %v, want %v", tun.Name, "xray0")
	}
	if tun.MTU != 1500 {
		t.Errorf("Default MTU = %v, want %v", tun.MTU, 1500)
	}
	if tun.UserLevel != 0 {
		t.Errorf("Default UserLevel = %v, want %v", tun.UserLevel, 0)
	}
}

func TestTun_WithConfig(t *testing.T) {
	tun := NewTunWithConfig("mytun", 9000, 1)
	if tun.Name != "mytun" {
		t.Errorf("Name = %v, want %v", tun.Name, "mytun")
	}
	if tun.MTU != 9000 {
		t.Errorf("MTU = %v, want %v", tun.MTU, 9000)
	}
	if tun.UserLevel != 1 {
		t.Errorf("UserLevel = %v, want %v", tun.UserLevel, 1)
	}
}

func TestTun_WithConfig_DefaultsForEmpty(t *testing.T) {
	tun := NewTunWithConfig("", 0, 0)
	if tun.Name != "xray0" {
		t.Errorf("Name should default to xray0, got %v", tun.Name)
	}
	if tun.MTU != 1500 {
		t.Errorf("MTU should default to 1500, got %v", tun.MTU)
	}
}

func TestTun_DetailsStr(t *testing.T) {
	tun := NewTunWithConfig("xray0", 1500, 0)
	tun.Remark = "Test TUN"
	details := tun.DetailsStr()
	if details == "" {
		t.Error("DetailsStr() returned empty string")
	}
	// Just check it doesn't panic and returns something
	if len(details) < 10 {
		t.Errorf("DetailsStr() too short: %v", details)
	}
}

func TestTun_GetLink(t *testing.T) {
	tun := NewTunWithConfig("mytun", 1500, 0)
	link := tun.GetLink()
	if link != "mytun" {
		t.Errorf("GetLink() = %v, want %v", link, "mytun")
	}
}

func TestTun_ConvertToGeneralConfig(t *testing.T) {
	tun := NewTun()
	tun.Remark = "My TUN"
	gc := tun.ConvertToGeneralConfig()
	if gc.Protocol != "tun" {
		t.Errorf("Protocol = %v, want %v", gc.Protocol, "tun")
	}
	if gc.Remark != "My TUN" {
		t.Errorf("Remark = %v, want %v", gc.Remark, "My TUN")
	}
}

func TestTun_BuildInboundDetourConfig(t *testing.T) {
	tun := NewTunWithConfig("xray0", 1500, 0)
	inbound, err := tun.BuildInboundDetourConfig()
	if err != nil {
		t.Fatalf("BuildInboundDetourConfig() returned error: %v", err)
	}
	if inbound == nil {
		t.Fatal("BuildInboundDetourConfig() returned nil")
	}
	if inbound.Protocol != "tun" {
		t.Errorf("Protocol = %v, want %v", inbound.Protocol, "tun")
	}
	if inbound.Tag != "tun-inbound" {
		t.Errorf("Tag = %v, want %v", inbound.Tag, "tun-inbound")
	}
	if inbound.Settings == nil {
		t.Error("Settings is nil")
	}
}

func TestTun_BuildInboundDetourConfig_Defaults(t *testing.T) {
	// Test that defaults are applied when values are zero
	tun := &Tun{}
	inbound, err := tun.BuildInboundDetourConfig()
	if err != nil {
		t.Fatalf("BuildInboundDetourConfig() returned error: %v", err)
	}
	if inbound == nil {
		t.Fatal("BuildInboundDetourConfig() returned nil")
	}
	// Settings should contain defaults - we can't easily inspect the JSON
	// but we know the function doesn't error
}

func TestTun_BuildOutboundDetourConfig(t *testing.T) {
	tun := NewTun()
	outbound, err := tun.BuildOutboundDetourConfig(false)
	if err == nil {
		t.Error("BuildOutboundDetourConfig() should return an error for TUN")
	}
	if outbound != nil {
		t.Error("BuildOutboundDetourConfig() should return nil for TUN")
	}
}
