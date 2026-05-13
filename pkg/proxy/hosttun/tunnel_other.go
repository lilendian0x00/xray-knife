//go:build !linux

package hosttun

import (
	"context"
	"errors"

	"github.com/lilendian0x00/xray-knife/v9/pkg/core/protocol"
)

// ErrNotSupported is returned on non-Linux platforms.
var ErrNotSupported = errors.New("host-tun mode is only supported on Linux")

func Start(context.Context, Config) (protocol.Instance, error) {
	return nil, ErrNotSupported
}

func Preflight(context.Context, string, string) error {
	return ErrNotSupported
}
