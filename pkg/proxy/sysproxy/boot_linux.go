package sysproxy

import (
	"os"
	"strings"
)

// bootMarker identifies the current boot by the kernel's boot_id.
func bootMarker() string {
	data, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}
