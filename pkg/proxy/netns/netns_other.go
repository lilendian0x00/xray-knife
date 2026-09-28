//go:build !linux

package netns

import (
	"context"
	"errors"
	"os/exec"
	"time"

	"github.com/lilendian0x00/xray-knife/v11/pkg/core/protocol"
)

// ErrNotSupported is returned on non-Linux platforms.
var ErrNotSupported = errors.New("network namespace proxy mode is only supported on Linux")

// Namespace is a stub on non-Linux platforms.
type Namespace struct{}

// Credential is the user a command inside the namespace runs as.
type Credential struct {
	Uid, Gid              uint32
	Username, Home, Shell string
}

func Setup(Config) (*Namespace, error)                                      { return nil, ErrNotSupported }
func (n *Namespace) Name() string                                           { return "" }
func (n *Namespace) ResolvDir() string                                      { return "" }
func (n *Namespace) Close() error                                           { return ErrNotSupported }
func (n *Namespace) Shell(context.Context, *Credential, func(string)) error { return ErrNotSupported }
func (n *Namespace) Run(context.Context, []string, *Credential, func(string)) error {
	return ErrNotSupported
}
func (n *Namespace) WaitForLinkGone(string, time.Duration) {}
func StartTunnel(context.Context, string, Config) (protocol.Instance, error) {
	return nil, ErrNotSupported
}
func CleanupNamespace(string) error { return nil }
func CleanupVeth(string)            {}
func RecoverFromCrash() []string    { return nil }
func SudoCredential() *Credential   { return nil }
func Command(context.Context, string, []string, *Credential) (*exec.Cmd, string, error) {
	return nil, "", ErrNotSupported
}
