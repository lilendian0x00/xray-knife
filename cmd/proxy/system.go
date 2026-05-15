package proxy

import (
	"github.com/spf13/cobra"
)

var systemCmdRot inboundCfgPair

// SystemCmd is the `proxy system` subcommand. Same flag set as
// InboundCmd but Mode="system" so pkg/proxy registers an OS-level
// proxy (sysproxy.Manager) for the lifetime of the command.
var SystemCmd = newSystemCommand()

func newSystemCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "system",
		Short: "Like 'inbound', plus register the running proxy as the OS system proxy.",
		Long: `Runs a local inbound proxy AND configures the host OS to route HTTP/HTTPS
traffic through it. On exit, the previous OS proxy settings are restored.

OS-specific behavior:
  Linux:   GNOME / KDE proxy settings via gsettings / kwriteconfig5
  macOS:   networksetup -setwebproxy / -setsecurewebproxy / -setsocksfirewallproxy
  Windows: per-protocol ProxyServer registry keys + WinINet refresh`,
		Example: `  xray-knife proxy system                  # DB pool, OS proxy on 127.0.0.1:9999
  xray-knife proxy system -c "vless://..." -p 8080`,
		RunE: runSystem,
	}

	flags := cmd.Flags()
	flags.StringVarP(&systemCmdRot.in.inboundProtocol, "inbound", "j", "socks", "Inbound protocol to use (vless, vmess, socks)")
	flags.StringVarP(&systemCmdRot.in.inboundTransport, "transport", "u", "tcp", "Inbound transport to use (tcp, ws, grpc, xhttp)")
	flags.StringVarP(&systemCmdRot.in.inboundUUID, "uuid", "g", "random", "Inbound custom UUID to use (default: random)")
	flags.StringVarP(&systemCmdRot.in.inboundConfigLink, "inbound-config", "I", "", "Custom config link for the inbound proxy")
	cmd.MarkFlagsMutuallyExclusive("inbound-config", "inbound")

	addRotationFlags(cmd, &systemCmdRot.rot)
	addChainFlags(cmd, &systemCmdRot.ch)
	addOutboundNetFlags(cmd, &systemCmdRot.on)

	return cmd
}

func runSystem(cmd *cobra.Command, args []string) error {
	if err := validateChainFlags(&systemCmdRot.ch, pf.coreType); err != nil {
		return err
	}
	links, err := resolveLinks(&pf)
	if err != nil {
		return err
	}
	cfg := buildPkgConfig("system", &pf, &systemCmdRot.in, &systemCmdRot.rot, &systemCmdRot.ch, &systemCmdRot.on, nil, nil)
	cfg.ConfigLinks = links
	return runService(cmd.Context(), cfg, false)
}
