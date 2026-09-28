package proxy

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestListenPortReachesServiceAsString pins the boundary conversion: the CLI
// takes --port as a uint16 (so a bad value fails at parse time with a clear
// message), while pkg/proxy.Config keeps ListenPort as a string.
func TestListenPortReachesServiceAsString(t *testing.T) {
	p := &parentFlags{listenAddr: "127.0.0.1", listenPort: 1080}

	cfg, err := buildPkgConfig("inbound", p, nil, nil, nil, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	if cfg.ListenPort != "1080" {
		t.Fatalf("ListenPort = %q, want %q", cfg.ListenPort, "1080")
	}
}

func TestListenPortDefaultConverts(t *testing.T) {
	p := &parentFlags{listenAddr: "127.0.0.1", listenPort: 9999}

	cfg, err := buildPkgConfig("inbound", p, nil, nil, nil, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	if cfg.ListenPort != "9999" {
		t.Fatalf("ListenPort = %q, want %q", cfg.ListenPort, "9999")
	}
}

func TestFragmentFlagsReachConfig(t *testing.T) {
	p := &parentFlags{listenAddr: "127.0.0.1", listenPort: 9999}
	on := &outboundNetFlags{fragment: "tlshello,100-200,10-20", noise: []string{"rand:10-20:10-16"}}

	cfg, err := buildPkgConfig("inbound", p, nil, nil, nil, on, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Fragment == nil || cfg.Fragment.String() != "tlshello,100-200,10-20" || len(cfg.Fragment.Noises) != 1 {
		t.Fatalf("Fragment = %+v", cfg.Fragment)
	}

	on.fragment = "tlshello,0-5"
	if _, err := buildPkgConfig("inbound", p, nil, nil, nil, on, nil, nil); err == nil {
		t.Fatal("invalid --fragment accepted")
	}

	on.fragment, on.noise = "off", nil
	cfg, err = buildPkgConfig("inbound", p, nil, nil, nil, on, nil, nil)
	if err != nil || cfg.Fragment != nil {
		t.Fatalf("--fragment off: cfg.Fragment = %+v, err = %v", cfg.Fragment, err)
	}
}

// A typo in --file used to fall through to the whole DB pool.
func TestResolveLinksRejectsMissingAndEmptyFiles(t *testing.T) {
	dir := t.TempDir()
	if _, err := resolveLinks(&parentFlags{configFile: filepath.Join(dir, "nope.txt")}); err == nil {
		t.Fatal("missing --file accepted")
	}
	empty := filepath.Join(dir, "empty.txt")
	if err := os.WriteFile(empty, []byte("\n# nothing\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := resolveLinks(&parentFlags{configFile: empty}); err == nil {
		t.Fatal("empty --file accepted")
	}
	good := filepath.Join(dir, "good.txt")
	if err := os.WriteFile(good, []byte("vless://a\n\ntrojan://b\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	links, err := resolveLinks(&parentFlags{configFile: good})
	if err != nil || strings.Join(links, "|") != "vless://a|trojan://b" {
		t.Fatalf("links = %q, err = %v", links, err)
	}
}

type fakeDeadman struct{ pending int }

func (f *fakeDeadman) ConfirmDeadman() bool {
	if f.pending > 0 {
		f.pending--
		return true
	}
	return false
}

// The deadman ENTER must reach the deadman, not trigger a rotation; later
// lines rotate, and a burst never blocks the single reader.
func TestDispatchStdinRoutesDeadmanFirst(t *testing.T) {
	r, w := io.Pipe()
	svc := &fakeDeadman{pending: 1}
	rotate := make(chan struct{}, 1)
	done := make(chan struct{})
	go func() {
		dispatchStdin(context.Background(), r, svc, rotate, true)
		close(done)
	}()

	io.WriteString(w, "\n")
	io.WriteString(w, "\n\n\n") // one rotation pending, the rest coalesced
	w.Close()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("dispatchStdin blocked")
	}
	if svc.pending != 0 {
		t.Fatal("deadman confirmation not delivered")
	}
	if len(rotate) != 1 {
		t.Fatalf("pending rotations = %d, want 1", len(rotate))
	}
}
