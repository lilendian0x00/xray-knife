package singbox

import (
	"context"
	"fmt"

	"github.com/sagernet/sing-box/adapter"
	boxOutbound "github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/option"
	sing_anytls "github.com/sagernet/sing-box/protocol/anytls"
	"github.com/sagernet/sing/common/logger"
	"github.com/sagernet/sing/service"
)

func registerAnyTLS(registry *boxOutbound.Registry) {
	sing_anytls.RegisterOutbound(registry)
}

func (a *AnyTLS) CraftOutbound(ctx context.Context, l logger.ContextLogger, allowInsecure bool) (adapter.Outbound, error) {
	options, err := a.CraftOutboundOptions(allowInsecure)
	if err != nil {
		return nil, err
	}
	anytlsOptions, ok := options.Options.(*option.AnyTLSOutboundOptions)
	if !ok {
		return nil, fmt.Errorf("anytls: unexpected options type %T", options.Options)
	}
	return sing_anytls.NewOutbound(ctx, service.FromContext[adapter.Router](ctx), l, "out_anytls", *anytlsOptions)
}
