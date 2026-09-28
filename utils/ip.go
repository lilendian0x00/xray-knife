package utils

import (
	"fmt"
	"math"
	"net"
	"strings"
)

func incrementIP(i *net.IP) {
	ip := *i
	for n := len(ip) - 1; n >= 0; n-- {
		if ip[n] == 255 {
			ip[n] = 0
			continue
		}
		ip[n]++
		break
	}
}

// CIDRtoListIP expands a CIDR into every address it contains.
//
// Deprecated: it allocates the whole range, which is unbounded for IPv6.
// Iterate with net/netip instead (see pkg/scanner).
func CIDRtoListIP(cidr string) ([]string, error) {
	ip, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("couldn't parse %s CIDR", cidr)
	}

	var IPs []string
	for ip := ip.Mask(ipNet.Mask); ipNet.Contains(ip); incrementIP(&ip) {
		IPs = append(IPs, ip.String())
	}
	return IPs, nil
}

// CIDRSize returns the number of IPs in a CIDR range using mask arithmetic,
// without allocating the full IP list into memory. Ranges larger than the
// platform int (any IPv6 prefix shorter than /65 on 64-bit) saturate at
// math.MaxInt instead of overflowing.
func CIDRSize(cidr string) (int, error) {
	n, err := CIDRSize64(cidr)
	if err != nil {
		return 0, err
	}
	if n > uint64(math.MaxInt) {
		return math.MaxInt, nil
	}
	return int(n), nil
}

// CIDRSize64 is CIDRSize with a uint64 result. A /0 IPv6 range (2^128
// addresses) saturates at math.MaxUint64.
func CIDRSize64(cidr string) (uint64, error) {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return 0, fmt.Errorf("couldn't parse %s CIDR: %w", cidr, err)
	}
	ones, bits := ipNet.Mask.Size()
	hostBits := bits - ones
	if hostBits >= 64 {
		return math.MaxUint64, nil
	}
	return 1 << hostBits, nil
}

// NormalizeCIDR appends /32 or /128 to bare IPs missing a subnet mask.
func NormalizeCIDR(s string) string {
	if strings.Contains(s, "/") {
		return s
	}
	ip := net.ParseIP(s)
	if ip == nil {
		return s
	}
	if ip.To4() != nil {
		return s + "/32"
	}
	return s + "/128"
}

func IsIPv6(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false // not a valid IP address
	}
	return ip.To4() == nil // if To4() returns nil, it's not an IPv4 address, hence it's IPv6
}
