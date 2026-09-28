package subs

import (
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/lilendian0x00/xray-knife/v11/database"
	"github.com/lilendian0x00/xray-knife/v11/pkg/subscription"
	"github.com/lilendian0x00/xray-knife/v11/utils/exitcode"
)

const (
	exportVless  = "vless://11111111-1111-1111-1111-111111111111@example.com:443?security=tls&type=ws&path=%2Fws&sni=example.com#fast"
	exportTrojan = "trojan://secret@example.org:443?security=tls&sni=example.org#slow"
)

// exportDB builds a temp database: subscription 1 provides the vless, trojan
// and MTProto links; the latest run passed vless (fast) and trojan (slow).
func exportDB(t *testing.T) {
	t.Helper()
	if err := database.InitDB(filepath.Join(t.TempDir(), "export.db")); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	if err := database.AddSubscription("https://example.test/sub", "", ""); err != nil {
		t.Fatal(err)
	}
	fc := newTestFetchCommand()
	cfgs, _ := fc.parseLinks([]string{exportVless, exportTrojan, mtprotoTg}, sql.NullInt64{Int64: 1, Valid: true})
	if err := database.UpsertSubscriptionConfigs(cfgs); err != nil {
		t.Fatal(err)
	}
	run, err := database.CreateHttpTestRun("{}", 3)
	if err != nil {
		t.Fatal(err)
	}
	if err := database.InsertHttpTestResultsBatch(run, []database.HttpTestResult{
		{ConfigLink: exportTrojan, Status: "passed", DelayMs: 400},
		{ConfigLink: exportVless, Status: "passed", DelayMs: 100},
		{ConfigLink: mtprotoTg, Status: "failed"},
	}); err != nil {
		t.Fatal(err)
	}
}

func runExportCmd(t *testing.T, args ...string) error {
	t.Helper()
	cmd := newExportCommand()
	cmd.SetArgs(args)
	cmd.SilenceUsage, cmd.SilenceErrors = true, true
	return cmd.Execute()
}

func readOut(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestExportPlainAndBase64(t *testing.T) {
	exportDB(t)
	dir := t.TempDir()

	plain := filepath.Join(dir, "plain.txt")
	if err := runExportCmd(t, "--sub-id", "1", "--status", "passed", "--format", "plain", "-o", plain); err != nil {
		t.Fatal(err)
	}
	if got := readOut(t, plain); got != exportVless+"\n"+exportTrojan+"\n" {
		t.Fatalf("plain export (fastest first) = %q", got)
	}

	b64 := filepath.Join(dir, "sub.txt")
	if err := runExportCmd(t, "--all", "--limit", "2", "-o", b64); err != nil {
		t.Fatal(err)
	}
	decoded, err := base64.StdEncoding.DecodeString(readOut(t, b64))
	if err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(string(decoded), "\n"); n != 2 {
		t.Fatalf("base64 export with --limit 2 has %d links: %q", n, decoded)
	}
	// The export must round-trip through the importer.
	links, err := subscription.Decode([]byte(readOut(t, b64)), subscription.DecodeOptions{})
	if err != nil || len(links) != 2 {
		t.Fatalf("re-import: %v %v", links, err)
	}
}

func TestExportStructuredSkipsWhatItCannotExpress(t *testing.T) {
	exportDB(t)
	dir := t.TempDir()

	clash := filepath.Join(dir, "best.yaml")
	if err := runExportCmd(t, "--sub-id", "1", "--format", "clash", "--select-group", "MINE", "-o", clash); err != nil {
		t.Fatal(err)
	}
	got := readOut(t, clash)
	for _, want := range []string{"proxies:", "fast", "slow", "MINE"} {
		if !strings.Contains(got, want) {
			t.Errorf("clash export lacks %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "tg://") {
		t.Error("MTProto link leaked into a clash export")
	}

	sb := filepath.Join(dir, "config.json")
	if err := runExportCmd(t, "--sub-id", "1", "--status", "passed", "--format", "singbox", "--mixed-port", "3080", "-o", sb); err != nil {
		t.Fatal(err)
	}
	var cfg map[string]any
	if err := json.Unmarshal([]byte(readOut(t, sb)), &cfg); err != nil {
		t.Fatalf("singbox export is not JSON: %v", err)
	}
	if !strings.Contains(readOut(t, sb), "3080") {
		t.Error("--mixed-port not applied")
	}

	xr := filepath.Join(dir, "xray.json")
	if err := runExportCmd(t, "--sub-id", "1", "--format", "xray", "-o", xr); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(readOut(t, xr)), &cfg); err != nil {
		t.Fatalf("xray export is not JSON: %v", err)
	}
}

func TestExportNothingExits3(t *testing.T) {
	exportDB(t)
	dir := t.TempDir()
	onlyMTProto := filepath.Join(dir, "tg.txt")
	if err := os.WriteFile(onlyMTProto, []byte(mtprotoTg+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "out.yaml")
	err := runExportCmd(t, "-f", onlyMTProto, "--format", "clash", "-o", out)
	if code, _ := exitcode.Of(err); code != exitcode.NothingPassed {
		t.Fatalf("MTProto-only clash export: err=%v code=%d", err, code)
	}
	if _, statErr := os.Stat(out); !os.IsNotExist(statErr) {
		t.Fatal("an empty export wrote the output file")
	}

	// No config passed its test.
	err = runExportCmd(t, "-f", onlyMTProto, "--status", "passed", "-o", out)
	if code, _ := exitcode.Of(err); code != exitcode.NothingPassed {
		t.Fatalf("status filter with no passes: err=%v code=%d", err, code)
	}
}

func TestExportUsageErrors(t *testing.T) {
	exportDB(t)
	for name, args := range map[string][]string{
		"no source":      {},
		"bad format":     {"--all", "--format", "surge"},
		"bad status":     {"--all", "--status", "failed"},
		"negative limit": {"--all", "--limit", "-1"},
	} {
		err := runExportCmd(t, args...)
		if code, _ := exitcode.Of(err); code != exitcode.Usage {
			t.Errorf("%s: err=%v code=%d, want usage", name, err, code)
		}
	}
	if err := runExportCmd(t, "--all", "--sub-id", "1"); err == nil {
		t.Error("--all with --sub-id accepted")
	}
}

func TestFormatSummary(t *testing.T) {
	if s := formatSummary(subscription.FormatPlain, 10, nil); s != "" {
		t.Errorf("plain list summary = %q, want none", s)
	}
	if s := formatSummary(subscription.FormatClash, 120, nil); s != "clash: 120 links" {
		t.Errorf("clash summary = %q", s)
	}
	got := formatSummary(subscription.FormatClash, 120, map[string]int{"missing server": 2, "unsupported clash proxy type snell": 3})
	want := "clash: 120 links, skipped 5 (3 unsupported clash proxy type snell, 2 missing server)"
	if got != want {
		t.Errorf("summary = %q, want %q", got, want)
	}
}

func TestExportFileModes(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX modes")
	}
	dir := t.TempDir()
	fresh := filepath.Join(dir, "new.txt")
	if err := writeExport(fresh, []byte("x\n")); err != nil {
		t.Fatal(err)
	}
	if info, _ := os.Stat(fresh); info.Mode().Perm() != 0o600 {
		t.Fatalf("new export mode = %o, want 600", info.Mode().Perm())
	}
	served := filepath.Join(dir, "served.txt")
	if err := os.WriteFile(served, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(served, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := writeExport(served, []byte("new\n")); err != nil {
		t.Fatal(err)
	}
	if info, _ := os.Stat(served); info.Mode().Perm() != 0o644 {
		t.Fatalf("replaced export mode = %o, want the existing 644", info.Mode().Perm())
	}
	if readOut(t, served) != "new\n" {
		t.Fatal("existing file not replaced")
	}
}
