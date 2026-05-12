// Package netbind binds outbound sockets to a specific OS interface
// (SO_BINDTOIFINDEX / SO_BINDTODEVICE on Linux, IP_BOUND_IF on Darwin,
// IP_UNICAST_IF on Windows). Useful when the host has multiple
// interfaces (eth0 + a VPN tunnel) and traffic must take a specific
// path regardless of the kernel's default route.
//
// On Linux, SO_BINDTODEVICE requires CAP_NET_RAW; callers without it
// will see EPERM at connect time.
package netbind

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"syscall"

	"github.com/sagernet/sing/common/control"
)

// Binder is a configured interface binder. The zero value is a no-op
// that disables binding.
type Binder struct {
	iface  string
	finder *control.DefaultInterfaceFinder
}

// New constructs a Binder for the given interface name. Returns a nil
// Binder (which is safe to use as a no-op) when iface is empty. Returns
// an error if the named interface does not exist on the host.
func New(iface string) (*Binder, error) {
	iface = strings.TrimSpace(iface)
	if iface == "" {
		return nil, nil
	}
	if _, err := net.InterfaceByName(iface); err != nil {
		return nil, fmt.Errorf("netbind: interface %q not found: %w", iface, err)
	}
	finder := control.NewDefaultInterfaceFinder()
	if err := finder.Update(); err != nil {
		return nil, fmt.Errorf("netbind: failed to enumerate interfaces: %w", err)
	}
	return &Binder{iface: iface, finder: finder}, nil
}

// Name returns the configured interface, or "" if disabled.
func (b *Binder) Name() string {
	if b == nil {
		return ""
	}
	return b.iface
}

// Enabled reports whether the binder will actually bind sockets.
func (b *Binder) Enabled() bool {
	return b != nil && b.iface != ""
}

// Control returns a control.Func suitable for net.Dialer.Control or for
// xray-core's transport/internet.RegisterDialerController. Returns nil
// when binding is disabled (callers must handle nil and skip wiring).
func (b *Binder) Control() control.Func {
	if !b.Enabled() {
		return nil
	}
	return control.BindToInterface(b.finder, b.iface, -1)
}

// ApplyDialer copies the binder's control function onto the given dialer.
// Existing Control hooks are wrapped so both run.
func (b *Binder) ApplyDialer(d *net.Dialer) {
	if !b.Enabled() || d == nil {
		return
	}
	bindCtl := b.Control()
	prev := d.Control
	d.Control = func(network, address string, c syscall.RawConn) error {
		if prev != nil {
			if err := prev(network, address, c); err != nil {
				return err
			}
		}
		return bindCtl(network, address, c)
	}
}

// ErrPermission is returned by upstream when CAP_NET_RAW is missing.
var ErrPermission = errors.New("netbind: missing CAP_NET_RAW (run as root or grant cap_net_raw+ep)")
