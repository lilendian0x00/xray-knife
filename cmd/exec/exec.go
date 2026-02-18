package exec

import (
	"fmt"
	"os"
	osexec "os/exec"
	"path/filepath"
	"runtime"

	"github.com/spf13/cobra"
)

// ExecCmd enters an existing proxy namespace and runs a command.
var ExecCmd = &cobra.Command{
	Use:   "exec <namespace> -- <command> [args...]",
	Short: "Run a command inside a proxy namespace",
	Long: `Enters an existing proxy namespace and runs the specified command.
The namespace must have been created by a prior 'proxy --mode app --namespace <name>' invocation.

Example:
  xray-knife exec myns -- curl https://ifconfig.me
  xray-knife exec myns -- firefox`,
	Args: cobra.MinimumNArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		if runtime.GOOS != "linux" {
			return fmt.Errorf("exec command is only supported on Linux")
		}

		nsName := args[0]
		nsPath := filepath.Join("/var/run/netns", nsName)

		if _, err := os.Stat(nsPath); os.IsNotExist(err) {
			return fmt.Errorf("namespace %q does not exist. Create it with: xray-knife proxy --mode app --namespace %s", nsName, nsName)
		}

		cmdArgs := args[1:]
		execCmd := osexec.Command("nsenter", append([]string{"--net=" + nsPath, "--"}, cmdArgs...)...)
		execCmd.Stdin = os.Stdin
		execCmd.Stdout = os.Stdout
		execCmd.Stderr = os.Stderr
		return execCmd.Run()
	},
}
