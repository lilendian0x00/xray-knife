//go:build !linux

package hosttun

import "syscall"

func markControl(uint32) func(network, address string, c syscall.RawConn) error { return nil }
