package proxy

import (
	"bufio"
	"bytes"
	"strconv"
	"strings"
)

// Linux capability numbers (include/uapi/linux/capability.h).
const (
	capNetAdmin = 12
	capNetRaw   = 13
	capSysAdmin = 21
)

var capNames = map[int]string{
	capNetAdmin: "CAP_NET_ADMIN",
	capNetRaw:   "CAP_NET_RAW",
	capSysAdmin: "CAP_SYS_ADMIN",
}

// parseCapEff returns the effective capability mask from the contents of
// /proc/self/status, and whether the CapEff line was found.
func parseCapEff(status []byte) (uint64, bool) {
	sc := bufio.NewScanner(bytes.NewReader(status))
	for sc.Scan() {
		key, val, ok := strings.Cut(sc.Text(), ":")
		if !ok || key != "CapEff" {
			continue
		}
		mask, err := strconv.ParseUint(strings.TrimSpace(val), 16, 64)
		if err != nil {
			return 0, false
		}
		return mask, true
	}
	return 0, false
}

// missingFromMask lists the names of the capabilities in want that mask
// lacks.
func missingFromMask(mask uint64, want []int) []string {
	var missing []string
	for _, c := range want {
		if mask&(1<<uint(c)) == 0 {
			missing = append(missing, capNames[c])
		}
	}
	return missing
}
