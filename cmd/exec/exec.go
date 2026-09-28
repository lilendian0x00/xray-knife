package exec

import (
	"errors"
	"fmt"
	"os"
	osexec "os/exec"
	"path/filepath"
	"regexp"
	"runtime"

	"github.com/lilendian0x00/xray-knife/v11/utils/exitcode"
	"github.com/spf13/cobra"
)

// validNamespace matches the names `ip netns` accepts and keeps the lookup
// inside /var/run/netns.
var validNamespace = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]*$`)

// ExecCmd enters an existing proxy namespace and runs a command.
var ExecCmd = &cobra.Command{
	Use:   "exec <namespace> -- <command> [args...]",
	Short: "Run a command inside a proxy namespace",
	Long: `Enters an existing proxy namespace and runs the specified command.
The namespace must have been created by a running
'xray-knife proxy app --namespace <name>' (Linux, root).

The command runs through 'ip netns exec' when available, which also applies
/etc/netns/<name>/resolv.conf so name resolution uses the namespace's DNS;
otherwise it falls back to 'nsenter --net'. The command's exit status becomes
xray-knife's exit status.

Example:
  sudo xray-knife exec myns -- curl https://ifconfig.me
  sudo xray-knife exec myns -- firefox`,
	Args: cobra.MinimumNArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		if runtime.GOOS != "linux" {
			return fmt.Errorf("exec command is only supported on Linux")
		}

		nsName := args[0]
		if !validNamespace.MatchString(nsName) {
			return exitcode.New(exitcode.Usage, fmt.Errorf("invalid namespace name %q", nsName))
		}
		nsPath := filepath.Join("/var/run/netns", nsName)

		if _, err := os.Stat(nsPath); errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("namespace %q does not exist. Create it with: sudo xray-knife proxy app --namespace %s", nsName, nsName)
		}

		cmdArgs := args[1:]
		var execCmd *osexec.Cmd
		if ip, err := osexec.LookPath("ip"); err == nil {
			execCmd = osexec.Command(ip, append([]string{"netns", "exec", nsName}, cmdArgs...)...)
		} else {
			execCmd = osexec.Command("nsenter", append([]string{"--net=" + nsPath, "--"}, cmdArgs...)...)
		}
		execCmd.Stdin = os.Stdin
		execCmd.Stdout = os.Stdout
		execCmd.Stderr = os.Stderr
		// The child's exit status becomes ours, silently (it printed its own
		// errors); a child killed by a signal exits 128+signal.
		return exitcode.Child(execCmd.Run())
	},
}
