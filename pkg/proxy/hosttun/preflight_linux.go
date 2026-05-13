//go:build linux

package hosttun

import (
	"context"
	"fmt"
	"net"
	"os/exec"
	"strings"
)

// Preflight verifies the proposed exclusion list will keep the SSH
// session alive AFTER the TUN comes up. Runs BEFORE we touch routing.
//
// Specifically: `ip route get <sshClientIP>` must not currently resolve
// via the TUN interface (TUN doesn't exist yet at preflight time, but
// we sanity-check that the SSH client IP is currently reachable via
// the physical interface — if it's not, we have bigger problems).
//
// tunName is the planned TUN interface (used as a sanity check that
// nothing with that name already exists and is hijacking routes).
func Preflight(ctx context.Context, sshClientIP, tunName string) error {
	// 1. If a stale tun with our planned name exists, refuse — we'd
	//    blunder into someone else's setup.
	if tunName != "" {
		if _, err := net.InterfaceByName(tunName); err == nil {
			return fmt.Errorf("interface %q already exists; refusing to clobber it", tunName)
		}
	}

	// 2. If SSH client IP is empty (not over SSH), skip route check.
	if sshClientIP == "" {
		return nil
	}

	// 3. Run `ip route get` to find the egress iface for the SSH client.
	//    Must NOT be the planned TUN. (At this point the TUN doesn't
	//    exist yet, so the only failure mode is misconfiguration —
	//    e.g. user already has a stale tun matching the name.)
	out, err := exec.CommandContext(ctx, "ip", "-o", "route", "get", sshClientIP).Output()
	if err != nil {
		return fmt.Errorf("ip route get %s: %w", sshClientIP, err)
	}

	line := string(out)
	if tunName != "" && strings.Contains(line, " dev "+tunName+" ") {
		return fmt.Errorf("ip route get %s already prefers %q — refuse to start", sshClientIP, tunName)
	}
	return nil
}
