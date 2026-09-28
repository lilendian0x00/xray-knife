package proxy

import (
	"errors"
	"fmt"

	pkgproxy "github.com/lilendian0x00/xray-knife/v11/pkg/proxy"

	"github.com/spf13/cobra"
)

var restoreForce bool

// RestoreCmd is `proxy restore`: undo what a crashed proxy run left behind.
var RestoreCmd = newRestoreCommand()

func newRestoreCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "restore",
		Short: "Remove leftovers of a crashed proxy run (kill switch, TUN rules, namespaces, system proxy settings).",
		Long: `Removes what a proxy run that did not exit cleanly left behind:

  - kill-switch firewall rules (tun --kill-switch keeps blocking traffic
    after a crash on purpose)
  - host-tun ip rules and routes
  - app-mode network namespaces and their resolv.conf
  - OS proxy settings changed by 'proxy system' (the previous settings
    are put back)

Only resources whose owning process is gone are touched; --force also
removes the kill switch and system proxy settings of a running instance.
Safe to run repeatedly. The Linux parts need root.`,
		Example: `  sudo xray-knife proxy restore
  xray-knife proxy restore            # macOS/Windows: system proxy settings`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			r := pkgproxy.Restore(restoreForce)
			out := cmd.OutOrStdout()
			if r.Empty() {
				fmt.Fprintln(out, "Nothing to restore.")
				return nil
			}
			for _, s := range r.Removed {
				fmt.Fprintln(out, "removed:", s)
			}
			for _, s := range r.Kept {
				fmt.Fprintln(out, "kept:   ", s)
			}
			for _, s := range r.Errors {
				fmt.Fprintln(cmd.ErrOrStderr(), "error:  ", s)
			}
			if len(r.Errors) > 0 {
				return errors.New("some leftovers could not be removed (are you root?)")
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&restoreForce, "force", false, "Also remove the kill switch and system proxy settings of a running instance")
	return cmd
}
