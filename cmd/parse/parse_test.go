package parse

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCollectLinksFromArgsFlagAndFile(t *testing.T) {
	saved := stdinIsTerminal
	t.Cleanup(func() { stdinIsTerminal = saved })
	stdinIsTerminal = func() bool { return true }

	file := filepath.Join(t.TempDir(), "links.txt")
	if err := os.WriteFile(file, []byte("\ufeffvless://f1\n# note\nvless://f2\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := &parseCmdConfig{configLink: " vless://c ", configLinksFile: file}
	links, err := collectLinks(context.Background(), cfg, []string{"vless://arg"})
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(links, ","); got != "vless://arg,vless://c,vless://f1,vless://f2" {
		t.Fatalf("links = %s", got)
	}

	cfg = &parseCmdConfig{configLinksFile: filepath.Join(t.TempDir(), "missing")}
	if _, err := collectLinks(context.Background(), cfg, nil); err == nil {
		t.Fatal("missing -f file accepted")
	}
}

func TestReadStdinLinksWithoutTrailingNewline(t *testing.T) {
	links, err := readStdinLinks(context.Background(), strings.NewReader("vless://a\nvless://b"), false)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(links, ",") != "vless://a,vless://b" {
		t.Fatalf("links = %v", links)
	}
}

func TestReadStdinLinksStopsOnCancel(t *testing.T) {
	r, w := io.Pipe()
	defer w.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := readStdinLinks(ctx, r, false); err == nil {
		t.Fatal("blocked stdin read ignored cancellation")
	}
}
