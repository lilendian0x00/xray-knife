package proxy

import (
	"github.com/spf13/cobra"
)

var (
	appCmdMode appCfg
	appCmdRot  rotationFlags
	appCmdCh   chainFlags
	appCmdOn   outboundNetFlags
)

// AppCmd is the `proxy app` subcommand: per-process network namespace
// (Linux only, requires root). Either --shell drops the user into an
// interactive shell inside the namespace, or --namespace creates a
// named netns that other processes can join via `ip netns exec`.
var AppCmd = newAppCommand()

func newAppCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "app",
		Short: "Run the proxy inside a per-process Linux network namespace.",
		Long: `Creates a Linux network namespace whose only way out is a TUN device
that carries all in-namespace traffic (DNS included) through the proxy.
Nothing else is routable from inside, so traffic fails closed if the
tunnel stops. Requires root (sudo).

Use --shell to drop into an interactive shell in the namespace (as the
user who ran sudo, unless --shell-as-root), or --namespace <name> to
create a named netns other processes can join with
'sudo ip netns exec <name> <cmd>' or 'xray-knife exec <name> -- <cmd>'.`,
		Example: `  sudo xray-knife proxy app --shell -c "vless://..."
  sudo xray-knife proxy app --namespace work -f configs.txt`,
		RunE: runApp,
	}

	flags := cmd.Flags()
	flags.BoolVar(&appCmdMode.shell, "shell", false, "Launch an interactive shell inside the proxy namespace")
	flags.StringVar(&appCmdMode.namespaceName, "namespace", "", "Create a named namespace for the proxy")
	flags.BoolVar(&appCmdMode.shellAsRoot, "shell-as-root", false, "Keep the --shell as root under sudo (default: drop to the invoking user)")
	flags.BoolVar(&appCmdMode.killSwitch, "kill-switch", false, "Also firewall the namespace so only the tunnel carries traffic (it already has no other route out)")
	cmd.MarkFlagsMutuallyExclusive("shell", "namespace")

	addRotationFlags(cmd, &appCmdRot)
	addChainFlags(cmd, &appCmdCh)
	addOutboundNetFlags(cmd, &appCmdOn)

	return cmd
}

func runApp(cmd *cobra.Command, args []string) error {
	if err := validateChainFlags(&appCmdCh, pf.coreType); err != nil {
		return err
	}
	links, err := resolveLinks(&pf)
	if err != nil {
		return err
	}
	cfg, err := buildPkgConfig("app", &pf, nil, &appCmdRot, &appCmdCh, &appCmdOn, &appCmdMode, nil)
	if err != nil {
		return err
	}
	cfg.ConfigLinks = links
	// shell-interactive suppresses the manual rotation reader because the
	// spawned shell takes over stdin.
	return runService(cmd.Context(), cfg, appCmdMode.shell)
}
