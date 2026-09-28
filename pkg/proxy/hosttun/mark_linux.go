package hosttun

import (
	"syscall"

	"golang.org/x/sys/unix"
)

// markControl returns a dialer Control function setting SO_MARK.
func markControl(mark uint32) func(network, address string, c syscall.RawConn) error {
	return func(_, _ string, c syscall.RawConn) error {
		var serr error
		if err := c.Control(func(fd uintptr) {
			serr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK, int(mark))
		}); err != nil {
			return err
		}
		return serr
	}
}
