//go:build !linux

package netns

import (
	"context"
	"errors"

	"github.com/lilendian0x00/xray-knife/v7/pkg/core/protocol"
)

// ErrNotSupported is returned on non-Linux platforms.
var ErrNotSupported = errors.New("network namespace proxy mode is only supported on Linux")

// Namespace is a stub on non-Linux platforms.
type Namespace struct{}

func Setup(Config) (*Namespace, error)                                         { return nil, ErrNotSupported }
func (n *Namespace) Close() error                                              { return ErrNotSupported }
func (n *Namespace) Shell(context.Context) error                               { return ErrNotSupported }
func (n *Namespace) Run(context.Context, []string) error                       { return ErrNotSupported }
func StartTunnel(context.Context, string, Config) (protocol.Instance, error)   { return nil, ErrNotSupported }
func CleanupNamespace(string)                                                  {}
func CleanupVeth(string)                                                       {}
func RecoverFromCrash()                                                        {}
