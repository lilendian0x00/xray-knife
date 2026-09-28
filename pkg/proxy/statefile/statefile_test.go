package statefile

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestWriteReadAtomic(t *testing.T) {
	t.Setenv("XRAY_KNIFE_HOME", t.TempDir())
	if err := Write("s.json", []byte("one")); err != nil {
		t.Fatal(err)
	}
	if err := Write("s.json", []byte("two")); err != nil {
		t.Fatal(err)
	}
	p, _ := Path("s.json")
	got, err := Read(p)
	if err != nil || string(got) != "two" {
		t.Fatalf("Read = %q, %v", got, err)
	}
	entries, _ := os.ReadDir(filepath.Dir(p))
	if len(entries) != 1 {
		t.Fatalf("temp files left: %v", entries)
	}
	if fi, _ := os.Stat(p); fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", fi.Mode())
	}
}

// A symlink planted at the state path must not be followed on read, and a
// write replaces it instead of writing through it.
func TestSymlinksAreNotFollowed(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no symlink attack surface tested on windows")
	}
	home := t.TempDir()
	t.Setenv("XRAY_KNIFE_HOME", home)
	victim := filepath.Join(t.TempDir(), "victim")
	if err := os.WriteFile(victim, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(home, "s.json")
	if err := os.Symlink(victim, link); err != nil {
		t.Fatal(err)
	}
	if _, err := Read(link); err == nil {
		t.Fatal("Read followed a symlink")
	}
	if err := Write("s.json", []byte("state")); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(victim); string(b) != "secret" {
		t.Fatalf("write went through the symlink: victim = %q", b)
	}
}
