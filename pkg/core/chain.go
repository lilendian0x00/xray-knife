package core

import (
	"fmt"

	"github.com/lilendian0x00/xray-knife/v9/pkg/core/protocol"
)

// ChainConfig holds the parsed chain of proxy hops.
type ChainConfig struct {
	Hops []protocol.Protocol
}

// ValidateChainForCore checks whether the given chain of hops is valid
// for the specified core engine.
func ValidateChainForCore(coreName string, hops []protocol.Protocol) error {
	if len(hops) < 2 {
		return fmt.Errorf("chain requires at least 2 hops, got %d", len(hops))
	}

	if coreName == "singbox" || coreName == "sing-box" {
		for i, hop := range hops {
			g := hop.ConvertToGeneralConfig()
			if g.Protocol == protocol.VlessIdentifier && g.Type == "tcp" {
				return fmt.Errorf("sing-box does not support VLESS with TCP transport in chain hop %d (%s)", i, g.Remark)
			}
		}
	}

	return nil
}
