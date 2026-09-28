// Package statefile stores the crash-recovery state of the proxy modes
// (namespaces, TUN rules, OS proxy settings) safely.
//
// Root acts on this state after a crash, so it must not live where an
// unprivileged user can write: under sudo the xray-knife home belongs to
// SUDO_USER, who could plant a symlink at the temp file root writes, or
// forge rule indices and names root then deletes. Root therefore keeps
// its state in /run/xray-knife (root-owned, 0700); other users keep it in
// the xray-knife home. Writes go through a freshly created temp file
// (O_EXCL|O_NOFOLLOW) and an atomic rename; reads refuse symlinks.
package statefile

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/lilendian0x00/xray-knife/v11/utils/xkhome"
)

// Dir returns (creating if needed) the state directory for this process.
func Dir() (string, error) {
	if dir, ok := privilegedDir(); ok {
		return dir, ensurePrivateDir(dir)
	}
	return xkhome.Dir()
}

// LegacyDir returns the directory older versions wrote root's state to
// (the xray-knife home) when it differs from Dir. Its contents may have
// been written by an unprivileged user: callers must validate them.
func LegacyDir() (string, bool) {
	cur, err := Dir()
	if err != nil {
		return "", false
	}
	old, err := xkhome.Path()
	if err != nil || filepath.Clean(old) == filepath.Clean(cur) {
		return "", false
	}
	return old, true
}

// Path returns name inside Dir.
func Path(name string) (string, error) {
	dir, err := Dir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, name), nil
}

// Write stores data as name in Dir atomically.
func Write(name string, data []byte) error {
	dir, err := Dir()
	if err != nil {
		return err
	}
	return WriteIn(dir, name, data)
}

// WriteIn stores data as name in dir atomically, via a new temp file that
// cannot be a pre-planted symlink.
func WriteIn(dir, name string, data []byte) error {
	var suffix [8]byte
	if _, err := rand.Read(suffix[:]); err != nil {
		return err
	}
	tmp := filepath.Join(dir, "."+name+"."+hex.EncodeToString(suffix[:])+".tmp")
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL|noFollow, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, filepath.Join(dir, name)); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}

// Read reads path, refusing to follow a symlink at the final component.
func Read(path string) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|noFollow, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	return io.ReadAll(io.LimitReader(f, 1<<20))
}

// Remove deletes name from Dir; a missing file is not an error.
func Remove(name string) error {
	p, err := Path(name)
	if err != nil {
		return err
	}
	if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}
