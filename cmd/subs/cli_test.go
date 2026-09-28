package subs

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lilendian0x00/xray-knife/v11/database"
	"github.com/lilendian0x00/xray-knife/v11/utils/exitcode"
)

func TestValidateSubscriptionURL(t *testing.T) {
	for _, ok := range []string{"https://example.com/sub", "http://1.2.3.4:8080/s?token=x"} {
		if err := validateSubscriptionURL(ok); err != nil {
			t.Errorf("%q rejected: %v", ok, err)
		}
	}
	for _, bad := range []string{"/etc/passwd", "ftp://example.com/x", "not a url at all", "https://", "example.com/sub"} {
		if err := validateSubscriptionURL(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestDedupeConfigs(t *testing.T) {
	in := []database.SubscriptionConfig{{ConfigLink: "a"}, {ConfigLink: "b"}, {ConfigLink: "a"}}
	out := dedupeConfigs(in)
	if len(out) != 2 || out[0].ConfigLink != "a" || out[1].ConfigLink != "b" {
		t.Fatalf("dedupe = %+v", out)
	}
	if len(in) != 3 || in[2].ConfigLink != "a" {
		t.Fatal("dedupe modified its input")
	}
}

func TestRmRefusesWithoutTerminal(t *testing.T) {
	saved := stdinIsTerminal
	t.Cleanup(func() { stdinIsTerminal = saved; rmYes = false })
	stdinIsTerminal = func() bool { return false }
	rmYes = false
	err := RmCmd.RunE(RmCmd, []string{"1"})
	if code, _ := exitcode.Of(err); err == nil || code != exitcode.Usage || !strings.Contains(err.Error(), "--yes") {
		t.Fatalf("rm without a terminal: err=%v code=%d", err, code)
	}
}

func TestFetchFromMissingFileFails(t *testing.T) {
	fc := newTestFetchCommand()
	fc.config.FileInput = filepath.Join(t.TempDir(), "missing.txt")
	if err := fc.fetchFromFile(context.Background()); err == nil {
		t.Fatal("missing --file accepted")
	}
	onlyBad := filepath.Join(t.TempDir(), "bad.txt")
	if err := os.WriteFile(onlyBad, []byte("# comment\nftp://x\n/etc/passwd\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	fc.config.FileInput = onlyBad
	if err := fc.fetchFromFile(context.Background()); err == nil || !strings.Contains(err.Error(), "no valid") {
		t.Fatalf("file without http(s) URLs: %v", err)
	}
}

func TestWriteOutputKeepsFileWhenNothingFetched(t *testing.T) {
	out := filepath.Join(t.TempDir(), "configs.txt")
	if err := os.WriteFile(out, []byte("vless://old\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	fc := newTestFetchCommand()
	fc.config.OutputFile = out
	if err := fc.writeOutput(nil); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(out); string(b) != "vless://old\n" {
		t.Fatalf("file changed: %q", b)
	}
	if err := fc.writeOutput([]database.SubscriptionConfig{{ConfigLink: "vless://new"}}); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(out); string(b) != "vless://new\n" {
		t.Fatalf("file not rewritten: %q", b)
	}
}

func TestSubIDFlagAndDeprecatedAlias(t *testing.T) {
	for _, flag := range []string{"--sub-id", "--id"} {
		fc := newTestFetchCommand()
		cmd := fc.createCommand()
		if err := cmd.ParseFlags([]string{flag, "7"}); err != nil {
			t.Fatalf("%s: %v", flag, err)
		}
		if fc.config.SubscriptionID != 7 {
			t.Fatalf("%s did not set the subscription id", flag)
		}
	}
	fc := newTestFetchCommand()
	cmd := fc.createCommand()
	_ = cmd.ParseFlags(nil)
	err := fc.validateFlags(cmd, nil)
	if code, _ := exitcode.Of(err); code != exitcode.Usage {
		t.Fatalf("no source: err=%v code=%d", err, code)
	}
	fc.config.SubscriptionURL = "file:///etc/passwd"
	if err := fc.validateFlags(cmd, nil); err == nil {
		t.Fatal("non-http --url accepted")
	}
}

// Configs two subscriptions share survive removing one of them, end to end
// through the fetch path's parse + upsert.
func TestSharedConfigSurvivesRm(t *testing.T) {
	if err := database.InitDB(filepath.Join(t.TempDir(), "rm.db")); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	for _, u := range []string{"https://a.example/s", "https://b.example/s"} {
		if err := database.AddSubscription(u, "", ""); err != nil {
			t.Fatal(err)
		}
	}
	shared := "vless://11111111-1111-1111-1111-111111111111@example.com:443?security=tls&type=tcp#shared"
	fc := newTestFetchCommand()
	for id := int64(1); id <= 2; id++ {
		cfgs, _ := fc.parseLinks([]string{shared}, sql.NullInt64{Int64: id, Valid: true})
		if err := database.UpsertSubscriptionConfigs(cfgs); err != nil {
			t.Fatal(err)
		}
	}
	saved := stdinIsTerminal
	t.Cleanup(func() { stdinIsTerminal = saved; rmYes = false })
	rmYes = true
	if err := RmCmd.RunE(RmCmd, []string{"2"}); err != nil {
		t.Fatal(err)
	}
	links, err := database.GetConfigsFromDB(1, "", 0)
	if err != nil || len(links) != 1 || links[0] != shared {
		t.Fatalf("shared config lost: %v %v", links, err)
	}
	if err := RmCmd.RunE(RmCmd, []string{"2"}); err == nil || errors.Is(err, context.Canceled) {
		t.Fatalf("removing a missing subscription: %v", err)
	}
}
