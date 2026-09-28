package hosttun

import (
	"os"
	"strings"
)

// IPv6Status reports whether the kernel has an IPv6 stack (stack) and
// whether it is enabled (not switched off with net.ipv6.conf.*.
// disable_ipv6). Giving the TUN an IPv6 address fails on such hosts.
func IPv6Status() (stack, enabled bool) {
	if _, err := os.Stat("/proc/net/if_inet6"); err != nil {
		return false, false
	}
	for _, f := range []string{"/proc/sys/net/ipv6/conf/all/disable_ipv6", "/proc/sys/net/ipv6/conf/default/disable_ipv6"} {
		if b, err := os.ReadFile(f); err == nil && strings.TrimSpace(string(b)) == "1" {
			return true, false
		}
	}
	return true, true
}
