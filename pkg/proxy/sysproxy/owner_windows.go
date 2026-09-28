//go:build windows

package sysproxy

import (
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/windows"
)

// processAlive reports whether pid names a running process.
func processAlive(pid int) bool {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		return false
	}
	defer windows.CloseHandle(h)
	var code uint32
	if err := windows.GetExitCodeProcess(h, &code); err != nil {
		return false
	}
	const stillActive = 259
	return code == stillActive
}

// bootMarker is the boot time (unix seconds), derived from the uptime.
func bootMarker() string {
	boot := time.Now().Add(-time.Duration(windows.DurationSinceBoot()))
	return "t" + strconv.FormatInt(boot.Unix(), 10)
}

// sameBoot compares boot times with slack: the value is computed from the
// uptime, so it jitters by a few seconds between calls.
func sameBoot(a, b string) bool {
	x, err1 := strconv.ParseInt(strings.TrimPrefix(a, "t"), 10, 64)
	y, err2 := strconv.ParseInt(strings.TrimPrefix(b, "t"), 10, 64)
	if err1 != nil || err2 != nil {
		return a == b
	}
	d := x - y
	if d < 0 {
		d = -d
	}
	return d <= 120
}
