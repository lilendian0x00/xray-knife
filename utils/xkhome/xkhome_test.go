package xkhome

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDirPrefersEnvVar(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("XRAY_KNIFE_HOME", tmp)

	got, err := Dir()
	if err != nil {
		t.Fatalf("Dir() error = %v", err)
	}
	if got != tmp {
		t.Fatalf("Dir() = %q, want %q", got, tmp)
	}
}

func TestDBPathOverrideWins(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("XRAY_KNIFE_HOME", tmp)

	want := filepath.Join(tmp, "custom.db")
	got, err := DBPath(want)
	if err != nil {
		t.Fatalf("DBPath() error = %v", err)
	}
	if got != want {
		t.Fatalf("DBPath(%q) = %q, want %q", want, got, want)
	}
}

func TestDBPathDefaultsUnderHome(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("XRAY_KNIFE_HOME", tmp)

	want := filepath.Join(tmp, "xray-knife.db")
	got, err := DBPath("")
	if err != nil {
		t.Fatalf("DBPath() error = %v", err)
	}
	if got != want {
		t.Fatalf("DBPath(\"\") = %q, want %q", got, want)
	}
}

func TestRelativeHomeIsMadeAbsolute(t *testing.T) {
	tmp := t.TempDir()
	t.Chdir(tmp)
	t.Setenv("XRAY_KNIFE_HOME", "state")

	got, err := Path()
	if err != nil {
		t.Fatal(err)
	}
	if !filepath.IsAbs(got) {
		t.Fatalf("Path() = %q, want an absolute path", got)
	}
	resolved, _ := filepath.EvalSymlinks(tmp)
	if got != filepath.Join(tmp, "state") && got != filepath.Join(resolved, "state") {
		t.Fatalf("Path() = %q, want %q", got, filepath.Join(tmp, "state"))
	}
}

func TestDirIsCreatedPrivate(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "home")
	t.Setenv("XRAY_KNIFE_HOME", dir)
	if _, err := Dir(); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		t.Fatalf("state dir mode = %o, want no group/other access", perm)
	}
}

func TestPathNoCreateHasNoSideEffect(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "absent")
	t.Setenv("XRAY_KNIFE_HOME", dir)
	if _, err := DBPathNoCreate(""); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("DBPathNoCreate created %s", dir)
	}
}

func TestSudoUsesInvokerHome(t *testing.T) {
	invHome := t.TempDir()
	saved := lookupInvoker
	t.Cleanup(func() { lookupInvoker = saved })
	lookupInvoker = func() (*sudoInvoker, bool) {
		return &sudoInvoker{uid: os.Getuid(), gid: os.Getgid(), home: invHome}, true
	}
	t.Setenv("XRAY_KNIFE_HOME", "")

	got, err := Path()
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(invHome, ".xray-knife"); got != want {
		t.Fatalf("Path() under sudo = %q, want %q", got, want)
	}
	// Chowning to our own uid is always permitted, so this exercises the
	// path filter without needing root.
	inside := filepath.Join(invHome, "f")
	if err := os.WriteFile(inside, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	ChownToInvoker(inside, filepath.Join(t.TempDir(), "outside"), filepath.Join(invHome, "missing"))
}
