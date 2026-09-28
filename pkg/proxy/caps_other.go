//go:build !linux

package proxy

// missingCaps is only meaningful on Linux; the modes that need
// capabilities are rejected earlier on other platforms.
func missingCaps(...int) []string { return nil }
