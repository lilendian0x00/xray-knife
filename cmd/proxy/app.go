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
		Long: `Creates a Linux network namespace, sets up a veth pair, runs a SOCKS
listener inside the namespace, and routes all in-namespace traffic
through the proxy. Requires root (sudo).

Use --shell to drop into an interactive shell in the namespace, or
--namespace <name> to create a named netns other processes can join
with 'ip netns exec <name> <cmd>'.`,
		Example: `  sudo xray-knife proxy app --shell -c "vless://..."
  sudo xray-knife proxy app --namespace work -f configs.txt`,
		RunE: runApp,
	}

	flags := cmd.Flags()
	flags.BoolVar(&appCmdMode.shell, "shell", false, "Launch an interactive shell inside the proxy namespace")
	flags.StringVar(&appCmdMode.namespaceName, "namespace", "", "Create a named namespace for the proxy")
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
	cfg := buildPkgConfig("app", &pf, nil, &appCmdRot, &appCmdCh, &appCmdOn, &appCmdMode, nil)
	cfg.ConfigLinks = links
	// shell-interactive suppresses the manual rotation reader because the
	// spawned shell takes over stdin.
	return runService(cmd.Context(), cfg, appCmdMode.shell)
}
