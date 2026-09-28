//go:build !linux

package hosttun

// IPv6Status is only meaningful on Linux.
func IPv6Status() (stack, enabled bool) { return true, true }
