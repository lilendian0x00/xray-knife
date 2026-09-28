package sysproxy

import (
	"strconv"

	"golang.org/x/sys/unix"
)

// bootMarker identifies the current boot by its boot time.
func bootMarker() string {
	tv, err := unix.SysctlTimeval("kern.boottime")
	if err != nil {
		return ""
	}
	return "t" + strconv.FormatInt(tv.Sec, 10)
}
