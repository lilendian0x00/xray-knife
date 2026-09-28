package hosttun

import (
	"net/netip"
	"sort"
)

// diffPrefixes returns what to add and what to delete to go from have to
// want.
func diffPrefixes(have map[netip.Prefix]bool, want []netip.Prefix) (add, del []netip.Prefix) {
	wantSet := map[netip.Prefix]bool{}
	for _, p := range want {
		wantSet[p.Masked()] = true
	}
	for p := range wantSet {
		if !have[p] {
			add = append(add, p)
		}
	}
	for p := range have {
		if !wantSet[p] {
			del = append(del, p)
		}
	}
	less := func(s []netip.Prefix) func(i, j int) bool {
		return func(i, j int) bool { return s[i].Addr().Less(s[j].Addr()) }
	}
	sort.Slice(add, less(add))
	sort.Slice(del, less(del))
	return add, del
}

// HostPrefixes turns addresses into single-host prefixes.
func HostPrefixes(addrs []netip.Addr) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(addrs))
	for _, a := range addrs {
		if a.IsValid() {
			a = a.Unmap()
			out = append(out, netip.PrefixFrom(a, a.BitLen()))
		}
	}
	return out
}
