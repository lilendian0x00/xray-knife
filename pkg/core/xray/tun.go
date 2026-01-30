package xray

import (
	"encoding/json"
	"fmt"

	"github.com/lilendian0x00/xray-knife/v7/pkg/core/protocol"

	"github.com/fatih/color"
	"github.com/xtls/xray-core/infra/conf"
)

// Tun represents an xray-core TUN inbound configuration.
// TUN inbounds capture system traffic through a virtual network interface.
// NOTE: TUN is Linux-only and requires root/admin privileges.
type Tun struct {
	// Name of the TUN interface. Defaults to "xray0".
	Name string `json:"name"`
	// MTU (Maximum Transmission Unit) for the interface. Defaults to 1500.
	MTU uint32 `json:"MTU"`
	// UserLevel is the policy user level for this inbound.
	UserLevel uint32 `json:"userLevel"`
	// Remark is a human-readable name/description for this inbound.
	Remark string `json:"-"`
}

// NewTun creates a new Tun instance with default values.
func NewTun() *Tun {
	return &Tun{
		Name:      "xray0",
		MTU:       1500,
		UserLevel: 0,
	}
}

// NewTunWithConfig creates a new Tun instance with the specified configuration.
func NewTunWithConfig(name string, mtu uint32, userLevel uint32) *Tun {
	t := &Tun{
		Name:      name,
		MTU:       mtu,
		UserLevel: userLevel,
	}
	// Apply defaults for empty values
	if t.Name == "" {
		t.Name = "xray0"
	}
	if t.MTU == 0 {
		t.MTU = 1500
	}
	return t
}

// Protocol interface implementation

func (t *Tun) ProtocolName() string {
	return "tun"
}

// Parse is a no-op because Tun is constructed programmatically, not from a URL.
func (t *Tun) Parse() error {
	return nil
}

func (t *Tun) DetailsStr() string {
	info := fmt.Sprintf("%s: %s\n%s: %s\n%s: %d\n%s: %d\n",
		color.RedString("Protocol"), t.ProtocolName(),
		color.RedString("Interface"), t.Name,
		color.RedString("MTU"), t.MTU,
		color.RedString("UserLevel"), t.UserLevel,
	)
	if t.Remark != "" {
		info += fmt.Sprintf("%s: %s\n", color.RedString("Remark"), t.Remark)
	}
	return info
}

// GetLink returns the interface name as there is no standard URL format for TUN.
func (t *Tun) GetLink() string {
	return t.Name
}

func (t *Tun) ConvertToGeneralConfig() protocol.GeneralConfig {
	return protocol.GeneralConfig{
		Protocol: t.ProtocolName(),
		Remark:   t.Remark,
	}
}

// BuildInboundDetourConfig builds the xray-core InboundDetourConfig for TUN.
func (t *Tun) BuildInboundDetourConfig() (*conf.InboundDetourConfig, error) {
	in := &conf.InboundDetourConfig{
		Protocol: t.ProtocolName(),
		Tag:      "tun-inbound",
	}

	// Apply defaults
	name := t.Name
	if name == "" {
		name = "xray0"
	}
	mtu := t.MTU
	if mtu == 0 {
		mtu = 1500
	}

	// Build settings JSON
	settings := map[string]interface{}{
		"name":      name,
		"MTU":       mtu,
		"userLevel": t.UserLevel,
	}
	settingsJSON, err := json.Marshal(settings)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal TUN settings: %w", err)
	}
	rawSettings := json.RawMessage(settingsJSON)
	in.Settings = &rawSettings

	return in, nil
}

// BuildOutboundDetourConfig returns an error because TUN is inbound-only.
func (t *Tun) BuildOutboundDetourConfig(allowInsecure bool) (*conf.OutboundDetourConfig, error) {
	return nil, fmt.Errorf("TUN does not support outbound configuration")
}
