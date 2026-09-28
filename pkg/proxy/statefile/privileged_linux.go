package statefile

import (
	"fmt"
	"os"
	"syscall"
)

const runDir = "/run/xray-knife"

func privilegedDir() (string, bool) {
	return runDir, os.Geteuid() == 0
}

// ensurePrivateDir creates dir as a root-owned 0700 directory, or checks
// that an existing one is exactly that (not a symlink, nobody else can
// write into it).
func ensurePrivateDir(dir string) error {
	if err := os.Mkdir(dir, 0o700); err != nil && !os.IsExist(err) {
		return err
	}
	fi, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !fi.IsDir() || fi.Mode()&os.ModeSymlink != 0 || !ok || st.Uid != 0 || fi.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("%s must be a root-owned directory with mode 0700", dir)
	}
	return nil
}
