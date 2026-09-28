package proxy

import (
	"github.com/spf13/cobra"
)

var inboundCmdRot inboundCfgPair

// InboundCmd is the `proxy inbound` subcommand.
var InboundCmd = newInboundCommand()

func newInboundCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "inbound",
		Short: "Run a local inbound proxy that tunnels traffic through a remote configuration. Supports automatic rotation.",
		Long: `Runs a local inbound proxy on --addr:--port. Configurations are read
from --config / --file / --stdin or, if none of those are provided, the
local subscription database (populated via 'xray-knife subs fetch').`,
		Example: `  xray-knife proxy inbound                                # use DB pool, default port 9999
  xray-knife proxy inbound -c "vless://..."               # one-shot single config
  xray-knife proxy inbound -f configs.txt -R 60           # rotate every 60s from file
  xray-knife proxy inbound --chain --chain-hops 3         # 3-hop chain from DB pool`,
		RunE: runInbound,
	}

	flags := cmd.Flags()
	flags.StringVar(&inboundCmdRot.in.inboundProtocol, "inbound", "socks", "Inbound protocol to use (vless, vmess, socks)")
	flags.StringVar(&inboundCmdRot.in.inboundTransport, "transport", "tcp", "Inbound transport to use (tcp, ws, grpc, xhttp)")
	flags.StringVar(&inboundCmdRot.in.inboundUUID, "uuid", "random", "Inbound custom UUID to use (default: random)")
	flags.StringVar(&inboundCmdRot.in.inboundConfigLink, "inbound-config", "", "Custom config link for the inbound proxy")
	cmd.MarkFlagsMutuallyExclusive("inbound-config", "inbound")

	addRotationFlags(cmd, &inboundCmdRot.rot)
	addChainFlags(cmd, &inboundCmdRot.ch)
	addOutboundNetFlags(cmd, &inboundCmdRot.on)

	return cmd
}

func runInbound(cmd *cobra.Command, args []string) error {
	if err := validateChainFlags(&inboundCmdRot.ch, pf.coreType); err != nil {
		return err
	}
	links, err := resolveLinks(&pf)
	if err != nil {
		return err
	}
	cfg, err := buildPkgConfig("inbound", &pf, &inboundCmdRot.in, &inboundCmdRot.rot, &inboundCmdRot.ch, &inboundCmdRot.on, nil, nil)
	if err != nil {
		return err
	}
	cfg.ConfigLinks = links
	return runService(cmd.Context(), cfg, false)
}
