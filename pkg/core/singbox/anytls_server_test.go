package singbox

import (
	"github.com/sagernet/sing-box/adapter/inbound"
	sing_anytls "github.com/sagernet/sing-box/protocol/anytls"
)

func registerAnyTLSServer(r *inbound.Registry) { sing_anytls.RegisterInbound(r) }
