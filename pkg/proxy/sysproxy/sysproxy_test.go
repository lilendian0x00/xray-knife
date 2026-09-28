package sysproxy

import (
	"os"
	"testing"
)

func TestSaveStateStampsOwnerAtomically(t *testing.T) {
	t.Setenv("XRAY_KNIFE_HOME", t.TempDir())
	if err := SaveState(&Settings{Platform: "test", Data: map[string]string{"k": "v"}}); err != nil {
		t.Fatal(err)
	}
	s, err := LoadState()
	if err != nil || s == nil {
		t.Fatalf("LoadState: %v", err)
	}
	if s.Owner == nil || s.Owner.Pid != os.Getpid() {
		t.Fatalf("owner = %+v", s.Owner)
	}
	if !OwnerAlive(s) {
		t.Fatal("own state reported orphaned")
	}
	path, _ := stateFilePath()
	if fi, err := os.Stat(path); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("state file mode: %v %v", fi.Mode(), err)
	}
	if _, err := os.Stat(path + ".tmp"); !os.IsNotExist(err) {
		t.Fatal("temp file left behind")
	}
	if err := ClearState(); err != nil {
		t.Fatal(err)
	}
}

func TestOwnerAliveOrphans(t *testing.T) {
	if OwnerAlive(&Settings{}) {
		t.Fatal("state without owner (older version) must count as orphaned")
	}
	if OwnerAlive(&Settings{Owner: &Owner{Pid: os.Getpid() + 1_000_000}}) {
		t.Fatal("nonexistent PID reported alive")
	}
	if OwnerAlive(&Settings{Owner: &Owner{Pid: 1, Boot: "some-other-boot"}}) {
		t.Fatal("owner from another boot reported alive")
	}
}
