//go:build !windows

package statefile

import "syscall"

const noFollow = syscall.O_NOFOLLOW
