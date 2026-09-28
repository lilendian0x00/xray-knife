package killswitch

import "strings"

// parseNftTables extracts kill-switch tables from `nft list tables`.
func parseNftTables(out string) []Leftover {
	var found []Leftover
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) == 3 && f[0] == "table" && f[1] == "inet" && strings.HasPrefix(f[2], nftPrefix) {
			if id := strings.TrimPrefix(f[2], nftPrefix); id != "" && id != "ns" {
				found = append(found, Leftover{Backend: "nftables", ID: id})
			}
		}
	}
	return found
}

// parseIptablesChains extracts kill-switch chains from `iptables -S`.
func parseIptablesChains(out string) []Leftover {
	var found []Leftover
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) == 2 && f[0] == "-N" && strings.HasPrefix(f[1], iptablesPrefix) {
			// The FORWARD chain belongs to the same kill switch.
			id := strings.TrimSuffix(strings.TrimPrefix(f[1], iptablesPrefix), forwardSuffix)
			found = append(found, Leftover{Backend: "iptables", ID: id})
		}
	}
	return found
}

func dedupLeftovers(in []Leftover) []Leftover {
	seen := map[Leftover]bool{}
	var out []Leftover
	for _, l := range in {
		if !seen[l] {
			seen[l] = true
			out = append(out, l)
		}
	}
	return out
}
