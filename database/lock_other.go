//go:build !(darwin || linux || freebsd || netbsd || openbsd || dragonfly || windows)

package database

import "os"

// Platforms without advisory file locks fall back to no cross-process
// locking; SQLite's own busy_timeout still serialises the writes.
func tryLockFile(*os.File) error { return nil }

func unlockFile(*os.File) error { return nil }
