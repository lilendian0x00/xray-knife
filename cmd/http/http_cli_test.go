package http

import (
	"context"
	"database/sql"
	"errors"
	nethttp "net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/lilendian0x00/xray-knife/v11/database"
	"github.com/lilendian0x00/xray-knife/v11/pkg/core/protocol"
	pkghttp "github.com/lilendian0x00/xray-knife/v11/pkg/http"
	"github.com/lilendian0x00/xray-knife/v11/utils/exitcode"
)

func validConfig() *Config {
	return &Config{CoreType: "auto", ThreadCount: 50, SuccessThreshold: 1, OutputFile: "valid.txt", OutputType: "txt", PingInterval: 1000}
}

func TestValidateConfigRejectsBadValues(t *testing.T) {
	cases := map[string]func(*Config){
		"zero threads":    func(c *Config) { c.ThreadCount = 0 },
		"zero interval":   func(c *Config) { c.Ping = true; c.PingInterval = 0 },
		"ping with stdin": func(c *Config) { c.Ping = true; c.Stdin = true },
		"bad type":        func(c *Config) { c.OutputType = "xml" },
		"bad fragment":    func(c *Config) { c.FragmentSpec = "tlshello" },
		"bad noise":       func(c *Config) { c.NoiseSpecs = []string{"nope:1"} },
		"threshold > 1":   func(c *Config) { c.SuccessThreshold = 1.5 },
		"unknown preset":  func(c *Config) { c.CheckPreset = "nope" },
		"unknown core":    func(c *Config) { c.CoreType = "v2ray" },
	}
	for name, mutate := range cases {
		c := validConfig()
		mutate(c)
		if err := validateConfig(c); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if err := validateConfig(validConfig()); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
}

func TestValidateConfigOutputExtensionAndFragment(t *testing.T) {
	for typ, want := range map[string]string{"csv": "valid.csv", "json": "valid.json", "jsonl": "valid.jsonl", "txt": "valid.txt"} {
		c := validConfig()
		c.OutputType = typ
		if err := validateConfig(c); err != nil || c.OutputFile != want {
			t.Errorf("%s: out = %q, err %v", typ, c.OutputFile, err)
		}
	}
	c := validConfig()
	c.OutputFile, c.OutputType = "-", "json"
	if err := validateConfig(c); err != nil || c.OutputFile != "-" {
		t.Errorf("stdout output renamed to %q (%v)", c.OutputFile, err)
	}

	c = validConfig()
	c.FragmentSpec = "tlshello,100-200,10-20"
	c.NoiseSpecs = []string{"rand:10-20:10-16"}
	if err := validateConfig(c); err != nil {
		t.Fatal(err)
	}
	opts := examinerOptions(c, nil)
	if opts.Fragment.String() != "tlshello,100-200,10-20" || len(opts.Fragment.Noises) != 1 {
		t.Fatalf("fragment not carried to the examiner: %+v", opts.Fragment)
	}
}

func TestSingleConfigErrorNamesStatus(t *testing.T) {
	if err := singleConfigError(pkghttp.Result{Status: "failed"}); err == nil || !strings.Contains(err.Error(), "failed") {
		t.Fatalf("err = %v", err)
	}
}

// The previous output survives until this run has a replacement.
func TestOutputStreamKeepsOldFileUntilFinished(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "valid.txt")
	if err := os.WriteFile(path, []byte("vless://previous"), 0644); err != nil {
		t.Fatal(err)
	}
	o := newOutputStream(path, "txt")
	if err := o.reset(); err != nil {
		t.Fatal(err)
	}
	passed := &pkghttp.Result{ConfigLink: "vless://new", Status: "passed", Delay: 10}
	if err := o.append([]*pkghttp.Result{passed}); err != nil {
		t.Fatal(err)
	}
	if raw, _ := os.ReadFile(path); string(raw) != "vless://previous" {
		t.Fatalf("output replaced mid-run: %q", raw)
	}
	if err := o.finish(pkghttp.ConfigResults{passed}, false); err != nil {
		t.Fatal(err)
	}
	if raw, _ := os.ReadFile(path); string(raw) != "vless://new" {
		t.Fatalf("output = %q", raw)
	}
	if _, err := os.Stat(path + ".partial"); !os.IsNotExist(err) {
		t.Fatal("side file left behind")
	}

	// A run that produced nothing keeps the old output.
	o = newOutputStream(path, "txt")
	_ = o.reset()
	if err := o.finish(nil, true); err != nil {
		t.Fatal(err)
	}
	if raw, _ := os.ReadFile(path); string(raw) != "vless://new" {
		t.Fatalf("empty run clobbered the output: %q", raw)
	}
}

func TestOutputStreamSortedJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "valid.json")
	o := newOutputStream(path, "json")
	_ = o.reset()
	results := pkghttp.ConfigResults{
		{ConfigLink: "vless://slow", Status: "passed", Delay: 900},
		{ConfigLink: "vless://fast", Status: "passed", Delay: 100},
	}
	if err := o.finish(results, true); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Index(string(raw), "vless://fast") > strings.Index(string(raw), "vless://slow") {
		t.Fatalf("json not sorted by delay:\n%s", raw)
	}
}

// brokenCore refuses every link, so a batch runs but nothing can pass.
type brokenCore struct{}

func (brokenCore) Name() string { return "broken" }
func (brokenCore) CreateProtocol(string) (protocol.Protocol, error) {
	return nil, errors.New("unsupported link")
}
func (brokenCore) MakeHttpClient(context.Context, protocol.Protocol, time.Duration) (*nethttp.Client, protocol.Instance, error) {
	return nil, nil, errors.New("unreachable")
}
func (brokenCore) MakeInstance(context.Context, protocol.Protocol) (protocol.Instance, error) {
	return nil, errors.New("unreachable")
}
func (brokenCore) SetInbound(protocol.Protocol) error { return nil }

func TestBatchWithNothingPassedExitsThree(t *testing.T) {
	c := validConfig()
	c.OutputFile = ""
	c.ThreadCount = 2
	e, err := pkghttp.NewExaminer(examinerOptions(c, nil))
	if err != nil {
		t.Fatal(err)
	}
	e.Core = brokenCore{}
	err = handleMultipleConfigs(context.Background(), e, c, []string{"x://a", "x://b"})
	if code, ok := exitcode.Of(err); !ok || code != exitcode.NothingPassed {
		t.Fatalf("err = %v (code %d), want exit code %d", err, code, exitcode.NothingPassed)
	}
}

func TestSingleConfigErrorCodes(t *testing.T) {
	if code, _ := exitcode.Of(singleConfigError(pkghttp.Result{Status: "failed", FailureKind: "tls-reset"})); code != exitcode.NothingPassed {
		t.Errorf("failed config: code %d", code)
	}
	if code, _ := exitcode.Of(singleConfigError(pkghttp.Result{Status: "broken"})); code != exitcode.Error {
		t.Errorf("broken config: code %d", code)
	}
	if err := singleConfigError(pkghttp.Result{Status: "failed", FailureKind: "tls-reset"}); !strings.Contains(err.Error(), "tls-reset") {
		t.Errorf("message %q lacks the kind", err)
	}
}

func TestCompletionsRegistered(t *testing.T) {
	cmd := newHttpCommand()
	for flag, want := range map[string]string{"core": "xray", "check-preset": "google", "protocol": "vless", "type": "jsonl"} {
		fn, ok := cmd.GetFlagCompletionFunc(flag)
		if !ok {
			t.Errorf("--%s has no completion", flag)
			continue
		}
		got, _ := fn(cmd, nil, "")
		if !slices.Contains(got, want) {
			t.Errorf("--%s completes %v, want %q among them", flag, got, want)
		}
	}
}

func TestStoredResultCarriesKind(t *testing.T) {
	row := database.HttpTestResult{Status: "failed", ConfigLink: "vless://x",
		Reason: sql.NullString{String: "https://x: EOF; diagnosis: tls-reset: 1.2.3.4:443 ...", Valid: true}, DelayMs: -1}
	got := toStoredResult(row)
	if got.FailureKind != "tls-reset" || got.Link != "vless://x" {
		t.Fatalf("stored result = %+v", got)
	}
}
