package utils

import (
	"math"
	"testing"
)

func TestCIDRSizeSaturates(t *testing.T) {
	cases := []struct {
		cidr string
		want uint64
	}{
		{"1.1.1.1/32", 1},
		{"1.1.1.0/24", 256},
		{"0.0.0.0/0", 1 << 32},
		{"2001:db8::/120", 256},
		{"2001:db8::/65", 1 << 63},
		{"2001:db8::/64", math.MaxUint64},
		{"2001:db8::/32", math.MaxUint64},
		{"::/0", math.MaxUint64},
	}
	for _, tc := range cases {
		got, err := CIDRSize64(tc.cidr)
		if err != nil || got != tc.want {
			t.Errorf("CIDRSize64(%s) = %d, %v; want %d", tc.cidr, got, err, tc.want)
		}
		n, err := CIDRSize(tc.cidr)
		if err != nil || n <= 0 {
			t.Errorf("CIDRSize(%s) = %d, %v; want a positive count", tc.cidr, n, err)
		}
	}
	if _, err := CIDRSize("not-a-cidr"); err == nil {
		t.Error("invalid CIDR accepted")
	}
}
