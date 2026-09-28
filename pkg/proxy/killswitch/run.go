package killswitch

import (
	"os/exec"
	"strings"
)

// run executes a firewall tool with optional stdin. Tests replace it.
var run = func(stdin, name string, args ...string) ([]byte, error) {
	cmd := exec.Command(name, args...)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	return cmd.CombinedOutput()
}
