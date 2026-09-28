package scanner

import (
	"context"
	"math/rand/v2"
	"net/netip"
	"runtime"
	"testing"
	"time"
)

func testPlan(t *testing.T, subnets []string, sample int, shuffle bool, maxIPs uint64) *ipPlan {
	t.Helper()
	p, err := ParsePrefixes(subnets)
	if err != nil {
		t.Fatal(err)
	}
	return &ipPlan{prefixes: p, sample: sample, shuffle: shuffle, maxIPs: maxIPs, rng: rand.New(rand.NewPCG(1, 2))}
}

func visitAll(t *testing.T, pl *ipPlan) []netip.Addr {
	t.Helper()
	var out []netip.Addr
	if err := pl.Each(context.Background(), func(a netip.Addr) bool { out = append(out, a); return true }); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestParsePrefixesMergesAndValidates(t *testing.T) {
	got, err := ParsePrefixes([]string{"1.1.1.0/24", "1.1.1.128/25", " 1.1.1.7 ", "10.0.0.5/8", "::ffff:8.8.8.0/120", ""})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"1.1.1.0/24", "8.8.8.0/24", "10.0.0.0/8"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i].String() != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
	for _, bad := range []string{"1.1.1.0/33", "nonsense", "1.1.1/24"} {
		if _, err := ParsePrefixes([]string{bad}); err == nil {
			t.Errorf("ParsePrefixes(%q) accepted", bad)
		}
	}
}

func TestPlanSequentialCoversRangeOnce(t *testing.T) {
	pl := testPlan(t, []string{"192.0.2.0/30", "198.51.100.8/31"}, 0, false, 0)
	got := visitAll(t, pl)
	// Prefixes are visited round robin, each in its own order.
	want := []string{"192.0.2.0", "198.51.100.8", "192.0.2.1", "198.51.100.9", "192.0.2.2", "192.0.2.3"}
	if len(got) != len(want) || pl.Total() != uint64(len(want)) {
		t.Fatalf("got %v (total %d)", got, pl.Total())
	}
	for i := range want {
		if got[i].String() != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
}

func TestPlanShuffleIsAPermutation(t *testing.T) {
	pl := testPlan(t, []string{"10.0.0.0/22"}, 0, true, 0)
	got := visitAll(t, pl)
	seen := map[netip.Addr]bool{}
	for _, a := range got {
		if seen[a] {
			t.Fatalf("%s visited twice", a)
		}
		seen[a] = true
		if !netip.MustParsePrefix("10.0.0.0/22").Contains(a) {
			t.Fatalf("%s outside the range", a)
		}
	}
	if len(seen) != 1024 {
		t.Fatalf("visited %d addresses, want 1024", len(seen))
	}
	if got[0].String() == "10.0.0.0" && got[1].String() == "10.0.0.1" {
		t.Error("shuffle kept sequential order")
	}
}

func TestPlanSamplingPerBlock(t *testing.T) {
	pl := testPlan(t, []string{"10.0.0.0/22"}, 3, false, 0)
	got := visitAll(t, pl)
	if len(got) != 12 || pl.Total() != 12 {
		t.Fatalf("visited %d (total %d), want 3 per /24 x 4", len(got), pl.Total())
	}
	perBlock := map[byte]int{}
	for _, a := range got {
		perBlock[a.As4()[2]]++
	}
	for b := byte(0); b < 4; b++ {
		if perBlock[b] != 3 {
			t.Fatalf("block %d got %d samples: %v", b, perBlock[b], perBlock)
		}
	}
	// A block smaller than the sample is taken whole.
	small := testPlan(t, []string{"10.0.0.0/30"}, 10, false, 0)
	if n := len(visitAll(t, small)); n != 4 {
		t.Fatalf("small block visited %d, want 4", n)
	}
}

// An IPv6 /32 is effectively infinite: the cap must end the walk, quickly
// and in constant memory, and the planned total must not overflow.
func TestPlanIPv6IsBoundedByCap(t *testing.T) {
	for _, sample := range []int{0, 2} {
		pl := testPlan(t, []string{"2606:4700::/32"}, sample, false, 5000)
		if pl.Total() != 5000 || !pl.Capped() {
			t.Fatalf("sample %d: total %d capped %v", sample, pl.Total(), pl.Capped())
		}
		start := time.Now()
		got := visitAll(t, pl)
		if len(got) != 5000 || time.Since(start) > 5*time.Second {
			t.Fatalf("sample %d: visited %d in %v", sample, len(got), time.Since(start))
		}
		for _, a := range got {
			if !netip.MustParsePrefix("2606:4700::/32").Contains(a) {
				t.Fatalf("%s outside the range", a)
			}
		}
	}
	whole := testPlan(t, []string{"::/0"}, 0, false, 0)
	if whole.Total() == 0 {
		t.Fatal("::/0 total overflowed to 0")
	}
}

func TestPlanStopsOnCancel(t *testing.T) {
	pl := testPlan(t, []string{"10.0.0.0/8"}, 0, false, 0)
	ctx, cancel := context.WithCancel(context.Background())
	n := 0
	err := pl.Each(ctx, func(netip.Addr) bool {
		n++
		if n == 100 {
			cancel()
		}
		return true
	})
	if err == nil || n != 100 {
		t.Fatalf("err %v after %d visits, want cancellation at 100", err, n)
	}
}

func TestPermuteSmallSpaces(t *testing.T) {
	rng := rand.New(rand.NewPCG(3, 4))
	for n := 0; n <= 10; n++ {
		seen := map[uint64]bool{}
		permute(rng, n, func(i uint64) bool { seen[i] = true; return true })
		if len(seen) != 1<<n {
			t.Fatalf("n=%d: %d distinct values, want %d", n, len(seen), 1<<n)
		}
	}
}

// Several big IPv6 prefixes under a cap: each gets its share instead of the
// first one absorbing the whole cap.
func TestPlanRoundRobinSharesTheCap(t *testing.T) {
	pl := testPlan(t, []string{"2400:cb00::/32", "2606:4700::/32", "2a06:98c0::/29"}, 0, false, 999)
	counts := map[string]int{}
	pl.Each(context.Background(), func(a netip.Addr) bool {
		for _, p := range pl.prefixes {
			if p.Contains(a) {
				counts[p.String()]++
			}
		}
		return true
	})
	for _, p := range pl.prefixes {
		if counts[p.String()] != 333 {
			t.Fatalf("per-prefix visits = %v, want 333 each", counts)
		}
	}
}

// A huge per-block sample with a small cap must not allocate its map up front.
func TestPlanHugeSampleAllocatesLazily(t *testing.T) {
	pl := testPlan(t, []string{"2606:4700::/48"}, MaxSamplePerSubnet, false, 10)
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	n := 0
	pl.Each(context.Background(), func(netip.Addr) bool { n++; return true })
	runtime.ReadMemStats(&after)
	if n != 10 {
		t.Fatalf("visited %d, want 10", n)
	}
	if alloc := after.TotalAlloc - before.TotalAlloc; alloc > 8<<20 {
		t.Fatalf("allocated %d MB for 10 addresses", alloc>>20)
	}
}
