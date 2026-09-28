//go:build darwin || linux || freebsd || netbsd || openbsd || dragonfly

package database

import (
	"errors"
	"os"
	"syscall"
)

// tryLockFile takes a non-blocking exclusive advisory lock on f. It reports
// errLockBusy when another process holds the lock.
func tryLockFile(f *os.File) error {
	err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
	if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
		return errLockBusy
	}
	return err
}

func unlockFile(f *os.File) error {
	return syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
}
