package proxy

import "os"

// missingCaps reports which of the wanted capabilities the process lacks
// in its effective set. Checking capabilities rather than uid 0 lets a
// binary granted e.g. `setcap cap_net_admin,cap_net_raw+ep` run tun mode
// without sudo, and still catches a root shell inside a container that
// dropped CAP_NET_ADMIN.
func missingCaps(want ...int) []string {
	data, err := os.ReadFile("/proc/self/status")
	if err == nil {
		if mask, ok := parseCapEff(data); ok {
			return missingFromMask(mask, want)
		}
	}
	if os.Geteuid() == 0 {
		return nil
	}
	return missingFromMask(0, want)
}
