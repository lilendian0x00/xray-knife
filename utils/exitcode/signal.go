package exitcode

import (
	"errors"
	"os/exec"
	"syscall"
)

// signalCode maps a child killed by a signal to 128+signal, the shell
// convention (130 for SIGINT).
func signalCode(err error) int {
	var ee *exec.ExitError
	if errors.As(err, &ee) && ee.ProcessState != nil {
		if ws, ok := ee.ProcessState.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
			return 128 + int(ws.Signal())
		}
	}
	return Interrupted
}
