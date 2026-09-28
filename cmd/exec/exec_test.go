package exec

import "testing"

func TestValidNamespace(t *testing.T) {
	for _, ok := range []string{"xkn-123", "myns", "a.b_c"} {
		if !validNamespace.MatchString(ok) {
			t.Errorf("%q rejected", ok)
		}
	}
	for _, bad := range []string{"", "../etc", "a/b", ".hidden", "x y"} {
		if validNamespace.MatchString(bad) {
			t.Errorf("%q accepted", bad)
		}
	}
}
