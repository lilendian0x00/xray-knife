package scanner

import (
	"context"
	"encoding/binary"
	"fmt"
	"iter"
	"math"
	"math/bits"
	"math/rand/v2"
	"net/netip"
	"slices"
	"strings"
)

// DefaultMaxIPs caps how many addresses one scan visits when the caller sets
// no limit. It comfortably covers all of Cloudflare's IPv4 ranges (~1.5M
// addresses) while keeping an IPv6 prefix, which is effectively infinite,
// from queueing forever.
const DefaultMaxIPs = 2_000_000

// Sampling block sizes: --sample-per-subnet picks N addresses from every /24
// of an IPv4 range and every /48 of an IPv6 range.
const (
	sampleBlockBits4 = 24
	sampleBlockBits6 = 48
)

// ParsePrefixes validates and normalizes subnet strings ("1.1.1.0/24",
// "1.1.1.1", "2606:4700::/32"), then merges them: a prefix contained in
// another is dropped so no address is scanned twice.
func ParsePrefixes(subnets []string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, raw := range subnets {
		s := strings.TrimSpace(raw)
		if s == "" {
			continue
		}
		var p netip.Prefix
		if strings.Contains(s, "/") {
			var err error
			if p, err = netip.ParsePrefix(s); err != nil {
				return nil, fmt.Errorf("invalid subnet %q: %w", raw, err)
			}
		} else {
			addr, err := netip.ParseAddr(s)
			if err != nil {
				return nil, fmt.Errorf("invalid subnet %q: not a CIDR or IP address", raw)
			}
			p = netip.PrefixFrom(addr, addr.BitLen())
		}
		if p.Addr().Is4In6() && p.Bits() >= 96 {
			// ::ffff:1.2.3.0/120 is the IPv4 range 1.2.3.0/24.
			p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96)
		}
		out = append(out, p.Masked())
	}
	return mergePrefixes(out), nil
}

// mergePrefixes sorts prefixes and drops any contained in an earlier one.
// CIDR prefixes either nest or are disjoint, so this removes every overlap.
func mergePrefixes(in []netip.Prefix) []netip.Prefix {
	slices.SortFunc(in, func(a, b netip.Prefix) int {
		if c := a.Addr().Compare(b.Addr()); c != 0 {
			return c
		}
		return a.Bits() - b.Bits()
	})
	out := make([]netip.Prefix, 0, len(in))
	for _, p := range in {
		if n := len(out); n > 0 && out[n-1].Bits() <= p.Bits() && out[n-1].Contains(p.Addr()) {
			continue
		}
		out = append(out, p)
	}
	return out
}

// hostBits is the number of free address bits in p.
func hostBits(p netip.Prefix) int { return p.Addr().BitLen() - p.Bits() }

// pow2 returns 2^n saturated at math.MaxUint64.
func pow2(n int) uint64 {
	if n >= 64 {
		return math.MaxUint64
	}
	return 1 << n
}

// satAdd adds without wrapping past math.MaxUint64.
func satAdd(a, b uint64) uint64 {
	if s, carry := bits.Add64(a, b, 0); carry == 0 {
		return s
	}
	return math.MaxUint64
}

// satMul multiplies without wrapping past math.MaxUint64.
func satMul(a, b uint64) uint64 {
	if hi, lo := bits.Mul64(a, b); hi == 0 {
		return lo
	}
	return math.MaxUint64
}

// addOffset returns base + (hi<<64 | lo), treating the address as a
// big-endian integer. Callers keep the offset inside the prefix.
func addOffset(base netip.Addr, hi, lo uint64) netip.Addr {
	if base.Is4() {
		b := base.As4()
		v := binary.BigEndian.Uint32(b[:]) + uint32(lo)
		binary.BigEndian.PutUint32(b[:], v)
		return netip.AddrFrom4(b)
	}
	b := base.As16()
	l, carry := bits.Add64(binary.BigEndian.Uint64(b[8:]), lo, 0)
	h, _ := bits.Add64(binary.BigEndian.Uint64(b[:8]), hi, carry)
	binary.BigEndian.PutUint64(b[:8], h)
	binary.BigEndian.PutUint64(b[8:], l)
	return netip.AddrFrom16(b)
}

// randOffset returns a uniform random offset below 2^n as (hi, lo).
func randOffset(rng *rand.Rand, n int) (uint64, uint64) {
	switch {
	case n <= 0:
		return 0, 0
	case n < 64:
		return 0, rng.Uint64N(1 << n)
	case n == 64:
		return 0, rng.Uint64()
	default:
		return rng.Uint64() & (1<<(n-64) - 1), rng.Uint64()
	}
}

// ipPlan enumerates a scan's addresses lazily, so memory stays constant no
// matter how large the ranges are.
type ipPlan struct {
	prefixes []netip.Prefix
	// sample picks this many random addresses per /24 (IPv4) or /48 (IPv6)
	// block; 0 visits every address.
	sample  int
	shuffle bool   // visit addresses of each prefix in random order
	maxIPs  uint64 // 0 = unlimited
	rng     *rand.Rand
}

// blockBits is the host-bit size of one sampling block inside p.
func (pl *ipPlan) blockBits(p netip.Prefix) int {
	block := sampleBlockBits6
	if p.Addr().Is4() {
		block = sampleBlockBits4
	}
	return max(0, p.Addr().BitLen()-max(block, p.Bits()))
}

// prefixCount is how many addresses the plan visits inside p (saturated).
func (pl *ipPlan) prefixCount(p netip.Prefix) uint64 {
	if pl.sample <= 0 {
		return pow2(hostBits(p))
	}
	bb := pl.blockBits(p)
	blocks := pow2(hostBits(p) - bb)
	perBlock := min(uint64(pl.sample), pow2(bb))
	return satMul(blocks, perBlock)
}

// uncapped is the number of addresses the plan covers before the cap.
func (pl *ipPlan) uncapped() uint64 {
	var total uint64
	for _, p := range pl.prefixes {
		total = satAdd(total, pl.prefixCount(p))
	}
	return total
}

// Total is the number of addresses Each visits (after sampling and the cap).
func (pl *ipPlan) Total() uint64 {
	if pl.Capped() {
		return pl.maxIPs
	}
	return pl.uncapped()
}

// Capped reports whether the cap truncates the plan.
func (pl *ipPlan) Capped() bool {
	return pl.maxIPs > 0 && pl.uncapped() > pl.maxIPs
}

// Each calls visit for every planned address. With several prefixes it takes
// one address from each in turn (round robin), so a huge prefix cannot use up
// the cap before the others are visited at all. It stops when visit returns
// false, the cap is reached, or ctx is done (returning ctx.Err()).
func (pl *ipPlan) Each(ctx context.Context, visit func(netip.Addr) bool) error {
	var visited uint64
	emit := func(a netip.Addr) bool {
		if ctx.Err() != nil {
			return false
		}
		if pl.maxIPs > 0 && visited >= pl.maxIPs {
			return false
		}
		visited++
		return visit(a)
	}
	if len(pl.prefixes) == 1 {
		pl.walk(pl.prefixes[0], emit)
		return ctx.Err()
	}

	type source struct {
		next func() (netip.Addr, bool)
		stop func()
	}
	sources := make([]source, 0, len(pl.prefixes))
	for _, p := range pl.prefixes {
		next, stop := iter.Pull(func(yield func(netip.Addr) bool) { pl.walk(p, yield) })
		sources = append(sources, source{next, stop})
	}
	defer func() {
		for _, src := range sources {
			src.stop() // safe to call again on exhausted sources
		}
	}()
	for len(sources) > 0 {
		for i := 0; i < len(sources); {
			a, ok := sources[i].next()
			if !ok {
				sources[i].stop()
				sources = append(sources[:i], sources[i+1:]...)
				continue
			}
			if !emit(a) {
				return ctx.Err()
			}
			i++
		}
	}
	return ctx.Err()
}

// walk visits p's addresses in the plan's order until yield returns false.
func (pl *ipPlan) walk(p netip.Prefix, yield func(netip.Addr) bool) {
	if pl.sample > 0 {
		pl.eachSampled(p, yield)
	} else {
		pl.eachAddress(p, yield)
	}
}

// unboundedIPv6 returns the first IPv6 prefix the plan could never finish:
// larger than /112 without sampling and without a cap.
func (pl *ipPlan) unboundedIPv6() (netip.Prefix, bool) {
	if pl.sample > 0 || pl.maxIPs > 0 {
		return netip.Prefix{}, false
	}
	for _, p := range pl.prefixes {
		if p.Addr().Is6() && p.Bits() < 112 {
			return p, true
		}
	}
	return netip.Prefix{}, false
}

// eachAddress visits every address of p, sequentially or in a random order.
func (pl *ipPlan) eachAddress(p netip.Prefix, emit func(netip.Addr) bool) bool {
	base := p.Masked().Addr()
	hb := hostBits(p)
	if hb > 64 {
		// 2^65+ addresses: a permutation is out of reach and a sequential
		// walk never leaves the first /64. Random picks cover the range and
		// collisions are negligible at this size; the cap ends the walk.
		for {
			hi, lo := randOffset(pl.rng, hb)
			if !emit(addOffset(base, hi, lo)) {
				return false
			}
		}
	}
	size := pow2(hb) // exact: hb <= 64 (2^64 saturates to MaxUint64, one short)
	if !pl.shuffle {
		for i := uint64(0); ; i++ {
			if !emit(addOffset(base, 0, i)) {
				return false
			}
			if i == size-1 {
				return true
			}
		}
	}
	return permute(pl.rng, hb, func(i uint64) bool { return emit(addOffset(base, 0, i)) })
}

// eachSampled visits up to pl.sample random addresses from every block of p.
func (pl *ipPlan) eachSampled(p netip.Prefix, emit func(netip.Addr) bool) bool {
	base := p.Masked().Addr()
	bb := pl.blockBits(p)
	blockCountBits := hostBits(p) - bb

	visitBlock := func(blockHi, blockLo uint64) bool {
		// Block start = base + blockIndex << bb.
		hi, lo := shl128(blockHi, blockLo, bb)
		start := addOffset(base, hi, lo)
		if uint64(pl.sample) >= pow2(bb) && bb < 64 {
			// Small block: take all of it.
			for i := uint64(0); i < pow2(bb); i++ {
				if !emit(addOffset(start, 0, i)) {
					return false
				}
			}
			return true
		}
		// Size hint only: a huge sample must not allocate its map up front
		// (the cap usually ends the walk long before).
		seen := make(map[[2]uint64]struct{}, min(pl.sample, 1024))
		for len(seen) < pl.sample {
			ohi, olo := randOffset(pl.rng, bb)
			if _, dup := seen[[2]uint64{ohi, olo}]; dup {
				continue
			}
			seen[[2]uint64{ohi, olo}] = struct{}{}
			if !emit(addOffset(start, ohi, olo)) {
				return false
			}
		}
		return true
	}

	if blockCountBits > 64 {
		for {
			hi, lo := randOffset(pl.rng, blockCountBits)
			if !visitBlock(hi, lo) {
				return false
			}
		}
	}
	if !pl.shuffle {
		blocks := pow2(blockCountBits)
		for i := uint64(0); ; i++ {
			if !visitBlock(0, i) {
				return false
			}
			if i == blocks-1 {
				return true
			}
		}
	}
	return permute(pl.rng, blockCountBits, func(i uint64) bool { return visitBlock(0, i) })
}

// shl128 shifts (hi, lo) left by n bits.
func shl128(hi, lo uint64, n int) (uint64, uint64) {
	switch {
	case n == 0:
		return hi, lo
	case n >= 128:
		return 0, 0
	case n >= 64:
		return lo << (n - 64), 0
	default:
		return hi<<n | lo>>(64-n), lo << n
	}
}

// permute calls visit for every i in [0, 2^n) exactly once, in a random
// order, in O(1) memory: a full-period linear congruential generator modulo
// 2^n (multiplier ≡ 1 mod 4, odd increment, Hull–Dobell) walks the whole
// space. The result is not cryptographically random, only well spread.
func permute(rng *rand.Rand, n int, visit func(uint64) bool) bool {
	if n <= 0 {
		return visit(0)
	}
	mask := uint64(math.MaxUint64)
	if n < 64 {
		mask = 1<<n - 1
	}
	a := (rng.Uint64() &^ 3) | 1 // ≡ 1 mod 4
	if n < 2 {
		a = 1
	}
	c := rng.Uint64() | 1
	x := rng.Uint64() & mask
	for i := uint64(0); ; i++ {
		if !visit(x) {
			return false
		}
		if i == mask {
			return true
		}
		x = (a*x + c) & mask
	}
}
