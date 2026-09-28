package proxy

import (
	"strings"
	"testing"

	"github.com/lilendian0x00/xray-knife/v11/pkg/proxy/hosttun"
)

// Restore removes the state a crashed run left and is idempotent.
func TestRestoreIsIdempotent(t *testing.T) {
	t.Setenv("XRAY_KNIFE_HOME", t.TempDir())
	if r := Restore(false); !r.Empty() {
		t.Fatalf("clean system reported %+v", r)
	}
	// A host-tun state file whose owner is long gone.
	if err := hosttun.SaveState(&hosttun.State{Pid: 999999, BootID: "another-boot", TunName: "xkt0", TableIndex: 31000, RuleIndex: 9101, BypassPriority: 9100}); err != nil {
		t.Fatal(err)
	}
	r := Restore(false)
	if len(r.Removed) != 1 || !strings.Contains(r.Removed[0], "pid 999999") {
		t.Fatalf("report = %+v", r)
	}
	if r := Restore(false); !r.Empty() {
		t.Fatalf("second run found more: %+v", r)
	}
}
