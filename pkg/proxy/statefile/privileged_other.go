//go:build !linux

package statefile

// Only Linux runs the root-only modes; elsewhere state stays in the home.
func privilegedDir() (string, bool) { return "", false }

func ensurePrivateDir(string) error { return nil }
