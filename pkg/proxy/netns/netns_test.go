package netns

import (
	"os"
	"path/filepath"
	"testing"
)

func TestValidateName(t *testing.T) {
	for _, ok := range []string{"xk-1234", "work", "a.b_c-d", "ns1"} {
		if err := ValidateName(ok); err != nil {
			t.Errorf("ValidateName(%q): %v", ok, err)
		}
	}
	for _, bad := range []string{"", ".", "..", "../etc", "a/b", "-x", "x y", string(make([]byte, 70))} {
		if err := ValidateName(bad); err == nil {
			t.Errorf("ValidateName(%q) accepted", bad)
		}
	}
}

func TestResolverAddr(t *testing.T) {
	c := DefaultConfig(1080)
	if got, err := c.resolverAddr(); err != nil || got != "10.10.0.2" {
		t.Fatalf("resolverAddr = %q, %v", got, err)
	}
	c.TunAddr = "10.10.0.1/32"
	if _, err := c.resolverAddr(); err == nil {
		t.Fatal("/32 TUN has no room for a resolver")
	}
}

// Parallel instances keep separate state files; clearing one must not
// touch another's.
func TestStatePerInstance(t *testing.T) {
	home := t.TempDir()
	t.Setenv("XRAY_KNIFE_HOME", home)

	if err := SaveState(&State{Name: "mine"}); err != nil {
		t.Fatal(err)
	}
	if err := SaveState(&State{Name: "other", Pid: 999999, BootID: "gone"}); err != nil {
		t.Fatal(err)
	}
	legacy := `{"name":"old","vethHost":"xkh-1","pid":1,"bootId":"x"}`
	if err := os.WriteFile(filepath.Join(home, legacyStateFile), []byte(legacy), 0o600); err != nil {
		t.Fatal(err)
	}
	states, files, _, err := LoadStates()
	if err != nil || len(states) != 3 || len(files) != 3 {
		t.Fatalf("LoadStates = %d states, %v", len(states), err)
	}
	if err := ClearState(); err != nil {
		t.Fatal(err)
	}
	states, _, _, _ = LoadStates()
	names := map[string]bool{}
	for _, s := range states {
		names[s.Name] = true
	}
	if names["mine"] || !names["other"] || !names["old"] {
		t.Fatalf("after ClearState: %v", names)
	}
}

func TestStateOwnerAlive(t *testing.T) {
	if !stateOwnerAlive(&State{Pid: os.Getpid()}) {
		t.Fatal("own PID reported dead")
	}
	if stateOwnerAlive(&State{Pid: 0}) || stateOwnerAlive(nil) {
		t.Fatal("empty state reported alive")
	}
}

// Recovery runs as root on these values; a forged state file must not be
// able to name arbitrary namespaces, links or directories.
func TestStateValidation(t *testing.T) {
	good := State{Name: "xk-42", Pid: 42, ResolvDir: "/etc/netns/xk-42"}
	if err := good.Validate(); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*State){
		"path name":  func(s *State) { s.Name = "../../etc" },
		"other dir":  func(s *State) { s.ResolvDir = "/etc" },
		"host iface": func(s *State) { s.VethHost = "eth0" },
		"no pid":     func(s *State) { s.Pid = 0 },
	} {
		s := good
		mutate(&s)
		if s.Validate() == nil {
			t.Errorf("%s: forged state accepted", name)
		}
	}
	t.Setenv("XRAY_KNIFE_HOME", t.TempDir())
	forged := good
	forged.ResolvDir = "/etc"
	forged.Pid = 999998
	if err := SaveState(&forged); err != nil {
		t.Fatal(err)
	}
	if states, _, bad, _ := LoadStates(); len(states) != 0 || len(bad) != 1 {
		t.Fatalf("states=%v bad=%v", states, bad)
	}
}
