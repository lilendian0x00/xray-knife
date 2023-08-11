package main

import (
	"xray-knife/cmd"
)

func init() {
	//common.Must(common.RegisterConfig((*proxyman.InboundConfig)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
	//	return inbound.New(ctx, config.(*proxyman.InboundConfig)), nil
	//}))
	//common.Must(common.RegisterConfig((*core.InboundHandlerConfig)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
	//	return inbound.NewHandler(ctx, config.(*core.InboundHandlerConfig)), nil
	//}))

	//common.Must(common.RegisterConfig((*proxyman.OutboundConfig)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
	//	return outbound.New(ctx, config.(*proxyman.OutboundConfig)), nil
	//}))
	//common.Must(common.RegisterConfig((*core.OutboundHandlerConfig)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
	//	return outbound.NewHandler(ctx, config.(*core.OutboundHandlerConfig)), nil
	//}))
}

func main() {
	cmd.Execute()
}
