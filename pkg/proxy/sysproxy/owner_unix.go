//go:build !windows

package sysproxy

import (
	"errors"
	"os"
	"syscall"
)

// processAlive probes pid with signal 0.
func processAlive(pid int) bool {
	proc, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	err = proc.Signal(syscall.Signal(0))
	if err == nil {
		return true
	}
	// EPERM means the process exists but belongs to someone else.
	return !errors.Is(err, os.ErrProcessDone) && !errors.Is(err, syscall.ESRCH)
}

func sameBoot(a, b string) bool { return a == b }
