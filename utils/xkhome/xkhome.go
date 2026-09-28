// Package xkhome resolves where xray-knife keeps its state: the database,
// system-proxy backups, and netns bookkeeping. Every caller goes through here
// so XRAY_KNIFE_HOME relocates all of it at once.
package xkhome

import (
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
)

// Path returns the xray-knife state directory without creating it.
//
// XRAY_KNIFE_HOME wins if set (made absolute, so a relative value does not
// move with the working directory). Otherwise it is ~/.xray-knife of the user
// who invoked the command: under sudo that is SUDO_USER's home, not root's,
// so `sudo xray-knife proxy ...` sees the same database as the user's
// unprivileged runs whether or not sudo resets HOME.
func Path() (string, error) {
	if dir := os.Getenv("XRAY_KNIFE_HOME"); dir != "" {
		abs, err := filepath.Abs(dir)
		if err != nil {
			return "", fmt.Errorf("XRAY_KNIFE_HOME: %w", err)
		}
		return abs, nil
	}
	home, err := invokerHome()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".xray-knife"), nil
}

// Dir returns the xray-knife state directory, creating it (mode 0700: it
// holds the web UI credentials and subscription URLs) if missing.
func Dir() (string, error) {
	dir, err := Path()
	if err != nil {
		return "", err
	}
	if _, statErr := os.Stat(dir); os.IsNotExist(statErr) {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return "", err
		}
		ChownToInvoker(dir)
	}
	return dir, nil
}

// DBPath returns the SQLite database path. A non-empty override (the --db
// flag) is used verbatim; otherwise the database lives under Dir().
func DBPath(override string) (string, error) {
	if override != "" {
		return override, nil
	}
	dir, err := Dir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "xray-knife.db"), nil
}

// DBPathNoCreate is DBPath without the side effect of creating the state
// directory, for read-only callers such as shell completion.
func DBPathNoCreate(override string) (string, error) {
	if override != "" {
		return override, nil
	}
	dir, err := Path()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "xray-knife.db"), nil
}

// sudoInvoker describes the user behind sudo when running as root.
type sudoInvoker struct {
	uid, gid int
	home     string
}

// lookupInvoker is swapped in tests.
var lookupInvoker = func() (*sudoInvoker, bool) {
	if os.Geteuid() != 0 {
		return nil, false
	}
	name := os.Getenv("SUDO_USER")
	if name == "" || name == "root" {
		return nil, false
	}
	uid, err1 := strconv.Atoi(os.Getenv("SUDO_UID"))
	gid, err2 := strconv.Atoi(os.Getenv("SUDO_GID"))
	if err1 != nil || err2 != nil {
		return nil, false
	}
	u, err := user.Lookup(name)
	if err != nil || u.HomeDir == "" {
		return nil, false
	}
	return &sudoInvoker{uid: uid, gid: gid, home: u.HomeDir}, true
}

func invokerHome() (string, error) {
	if inv, ok := lookupInvoker(); ok {
		return inv.home, nil
	}
	return os.UserHomeDir()
}

// ChownToInvoker hands files xray-knife created under sudo back to the user
// who ran sudo, so a later unprivileged run can still open them. It only
// touches paths inside that user's home directory and is a no-op when not
// running as root through sudo. Missing paths are skipped.
func ChownToInvoker(paths ...string) {
	inv, ok := lookupInvoker()
	if !ok {
		return
	}
	home := filepath.Clean(inv.home) + string(filepath.Separator)
	for _, p := range paths {
		abs, err := filepath.Abs(p)
		if err != nil || !strings.HasPrefix(abs, home) {
			continue
		}
		if _, err := os.Lstat(abs); err != nil {
			continue
		}
		_ = os.Lchown(abs, inv.uid, inv.gid)
	}
}
