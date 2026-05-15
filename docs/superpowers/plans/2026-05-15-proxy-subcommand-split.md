# Proxy CLI Subcommand Split — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the single `xray-knife proxy --mode X` command with four mode-specific subcommands (`inbound`, `system`, `app`, `tun`); bundle error-message hint, `Example:` blocks, automatic flag scoping, and `host-tun → tun` rename in same release (v10.0.0 breaking).

**Architecture:** `cmd/proxy/` is restructured into a parent command with persistent flags + four sibling subcommand files + a `shared.go` helper. Cross-mode validation that today lives in `cmd/proxy/proxy.go:97-145` is replaced by cobra's `MarkFlagRequired` / `MarkFlagsMutuallyExclusive` plus a tiny `validateChainFlags` helper. `pkg/proxy` API is unchanged — internal `Config.Mode` string stays as `"inbound"`, `"system"`, `"app"`, `"host-tun"` (only the CLI rename — internals untouched).

**Tech Stack:** Go 1.26.x, `github.com/spf13/cobra`, existing `pkg/proxy` service. New tests use Go's standard `testing` package — no third-party assertion lib (matches `cmd/subs/subscription_test.go` style).

**Spec:** [`docs/superpowers/specs/2026-05-15-proxy-subcommand-split-design.md`](../specs/2026-05-15-proxy-subcommand-split-design.md)

---

## File Structure

| Path | Status | Responsibility |
|---|---|---|
| `cmd/proxy/proxy.go` | Rewrite | Parent `ProxyCmd`, persistent flags (`--core/--config/--file/--stdin/--addr/--port/--verbose/--insecure`), `addSubcommandPalettes()`, `init()`. No `RunE` — bare `proxy` invokes cobra default help. |
| `cmd/proxy/shared.go` | Create | `parentFlags`, `rotationFlags`, `chainFlags`, `outboundNetFlags` structs; `addRotationFlags`, `addChainFlags`, `addOutboundNetFlags`, `validateChainFlags`; `runService` (signal setup + manual rotation reader + `service.Run`); `resolveLinks` (read from `--config/--file/--stdin` or empty for DB pool). |
| `cmd/proxy/inbound.go` | Create | `InboundCmd` + inbound-specific flags (`--inbound/-j`, `--inbound-config/-I`, `--transport/-u`, `--uuid/-g`) + `RunE` setting `Mode="inbound"`. |
| `cmd/proxy/system.go` | Create | `SystemCmd` + same flags as `InboundCmd` + `RunE` setting `Mode="system"`. |
| `cmd/proxy/app.go` | Create | `AppCmd` + `--shell` + `--namespace` (mutually exclusive) + `RunE` setting `Mode="app"`. |
| `cmd/proxy/tun.go` | Create | `TunCmd` + `--i-might-lose-ssh` (required) + `--bind` (required override) + `--tun-deadman/--tun-exclude/--tun-name/--tun-addr/--tun-mtu/--tun-include-private` + `RunE` setting `Mode="host-tun"`. |
| `cmd/proxy/proxy_test.go` | Create | Subcommand-registration, flag-scoping, mutual-exclusion, required-flag, persistent-flag-inheritance, chain-validation tests. |
| `pkg/proxy/service.go:271` | Modify | Error message text update. |
| `pkg/proxy/service_test.go` | Create-or-extend | Test for new error message text. (No existing test file — create.) |
| `cmd/root.go:25` | Modify | Bump `Version` from `9.12.1` → `10.0.0`. |
| `README.md` | Modify | Replace all `xray-knife proxy --mode X` examples with subcommand form; document `host-tun → tun` rename and `--host-tun-* → --tun-*` flag rename. |
| `RELEASE_NOTES_v10.0.0.md` | Create | Breaking changes list. |

**Files removed:** None. (Old `cmd/proxy/proxy.go` is rewritten in place; no separate deletion.)

---

## Task 0: Create the worktree and run baseline tests

**Files:**
- N/A (environment prep)

- [ ] **Step 1: Confirm clean working tree on master**

```bash
git -C /var/sys/xray-knife status --short
```

Expected: only the untracked `.claude/`, `RELEASE_NOTES_v9.11.0.md`, `RELEASE_NOTES_v9.12.0.md`, `results.csv`. No tracked modifications.

- [ ] **Step 2: Run baseline `go build` and `go test ./...`**

```bash
cd /var/sys/xray-knife && rtk go build ./... && rtk go test ./...
```

Expected: build succeeds; tests in `cmd/subs/` and `pkg/...` pass (or are absent — current test count is small).

- [ ] **Step 3: Capture baseline `xray-knife proxy --help` output for diff reference**

```bash
cd /var/sys/xray-knife && rtk go run . proxy --help > /tmp/proxy-help-before.txt 2>&1; head -40 /tmp/proxy-help-before.txt
```

Expected: ~33 flags listed under one `Flags:` section.

- [ ] **Step 4: No commit yet**

Baseline only — implementation starts in Task 1.

---

## Task 1: Add `pkg/proxy/service_test.go` with the new error-message expectation

**Rationale:** TDD — write the failing assertion for the new `"no configs in database. Run 'xray-knife subs fetch --all'..."` message before changing the production string.

**Files:**
- Create: `pkg/proxy/service_test.go`

- [ ] **Step 1: Write the failing test**

```go
package proxy

import (
	"strings"
	"testing"
)

// TestNew_NoConfigsErrorMessage verifies the error returned when no config
// links are passed and the database is empty mentions both `subs fetch`
// AND the --config/--file/--stdin alternatives.
func TestNew_NoConfigsErrorMessage(t *testing.T) {
	// Force the empty-pool path: no ConfigLinks and a fresh in-memory DB.
	// We can't easily wire a fake DB here without refactoring, so this test
	// stays a string-shape assertion against the literal error text in
	// service.go. If the New() path is later refactored, promote this to a
	// real integration test.
	const want1 = "no configs in database"
	const want2 = "xray-knife subs fetch --all"
	const want3 = "--config / --file / --stdin"

	got := emptyDBErrorText()

	for _, sub := range []string{want1, want2, want3} {
		if !strings.Contains(got, sub) {
			t.Errorf("error message %q missing substring %q", got, sub)
		}
	}
}

// emptyDBErrorText returns the static error string used in service.go
// for the empty-DB path. Kept as a separate function so the test can
// import the message without spinning up a database.
func emptyDBErrorText() string { return emptyDBError }
```

- [ ] **Step 2: Add the named string constant referenced by the test**

In `pkg/proxy/service.go`, add a package-level constant near the top of the file (after the imports / before `type Config`):

```go
// emptyDBError is the error returned when no config links are passed via
// flags and the database pool is empty. Exported as a constant so tests
// can assert its shape without spinning up a real database.
const emptyDBError = "no configs in database. Run 'xray-knife subs fetch --all' to populate, or pass --config / --file / --stdin"
```

- [ ] **Step 3: Run the test — expect PASS (constant carries the new text already)**

```bash
cd /var/sys/xray-knife && rtk go test ./pkg/proxy/ -run TestNew_NoConfigsErrorMessage -v
```

Expected: PASS. The test asserts on the named constant's shape, not on the line 271 call site. Step 4 below swaps the literal at the call site so production behavior matches the constant. The test is a regression guard against accidentally weakening the message in a future edit.

- [ ] **Step 4: Replace the literal at `pkg/proxy/service.go:271` with the constant**

Find:

```go
return nil, errors.New("no configs found in the database. Use 'subs fetch' to populate it")
```

Replace with:

```go
return nil, errors.New(emptyDBError)
```

- [ ] **Step 5: Re-run the test**

```bash
cd /var/sys/xray-knife && rtk go test ./pkg/proxy/ -run TestNew_NoConfigsErrorMessage -v
```

Expected: PASS.

- [ ] **Step 6: Verify no other test broke**

```bash
cd /var/sys/xray-knife && rtk go test ./...
```

Expected: PASS for every package.

- [ ] **Step 7: Commit**

```bash
git -C /var/sys/xray-knife add pkg/proxy/service.go pkg/proxy/service_test.go
git -C /var/sys/xray-knife commit -m "proxy: hint --config/--file/--stdin in empty-DB error"
```

---

## Task 2: Create `cmd/proxy/shared.go` with parentFlags + helper structs (no behavior yet)

**Rationale:** Stand up the shared scaffolding that every subcommand will reuse. No subcommand wiring yet — that comes in Task 4 onward. Keeping this isolated keeps the diffs reviewable.

**Files:**
- Create: `cmd/proxy/shared.go`

- [ ] **Step 1: Write `cmd/proxy/shared.go` with the four flag structs and the four flag-binding helpers**

```go
package proxy

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	pkgproxy "github.com/lilendian0x00/xray-knife/v9/pkg/proxy"
	"github.com/lilendian0x00/xray-knife/v9/utils"
	"github.com/lilendian0x00/xray-knife/v9/utils/customlog"

	"github.com/spf13/cobra"
)

// parentFlags carries every persistent flag declared on ProxyCmd.
// Subcommand RunE funcs read these directly — cobra has populated the
// fields by parse time.
type parentFlags struct {
	coreType        string
	configLink      string
	configFile      string
	readFromSTDIN   bool
	listenAddr      string
	listenPort      string
	verbose         bool
	insecureTLS     bool
}

// rotationFlags carries the rotation/health/blacklist tuning knobs that
// every subcommand carries (every mode rotates).
type rotationFlags struct {
	rotationInterval    uint32
	maximumAllowedDelay uint16
	batchSize           uint16
	concurrency         uint16
	healthCheckInterval uint32
	healthFailThreshold uint16
	drainTimeout        uint16
	blacklistStrikes    uint16
	blacklistDuration   uint32
}

// chainFlags carries the multi-hop chaining knobs.
type chainFlags struct {
	chain         bool
	chainLinks    string
	chainFile     string
	chainHops     uint8
	chainRotation string
	chainAttempts uint16
}

// outboundNetFlags carries flags that shape outbound dials (interface
// pinning + DNS resolver inside the tunnel).
type outboundNetFlags struct {
	bindInterface string
	dns           string
	dnsType       string
}

// pf is the package-level instance bound to ProxyCmd's persistent flags
// in proxy.go. Subcommands read it directly from RunE.
var pf parentFlags

func addRotationFlags(cmd *cobra.Command, r *rotationFlags) {
	flags := cmd.Flags()
	flags.Uint32VarP(&r.rotationInterval, "rotate", "t", 300, "How often to rotate outbounds (seconds)")
	flags.Uint16VarP(&r.maximumAllowedDelay, "mdelay", "d", 3000, "Maximum allowed delay (ms) for testing configs during rotation")
	flags.Uint16VarP(&r.batchSize, "batch", "b", 0, "Number of configs to test per rotation (0=auto)")
	flags.Uint16VarP(&r.concurrency, "concurrency", "n", 0, "Number of concurrent test threads (0=auto)")
	flags.Uint32Var(&r.healthCheckInterval, "health-check", 30, "Health check interval in seconds (0=disabled)")
	flags.Uint16Var(&r.healthFailThreshold, "health-fail-threshold", 0, "Consecutive health-check failures before striking the active config (0=default)")
	flags.Uint16Var(&r.drainTimeout, "drain", 0, "Seconds to keep the current outbound serving before switching during rotation (0=switch immediately)")
	flags.Uint16Var(&r.blacklistStrikes, "blacklist-strikes", 3, "Failures before blacklisting a config (0=disabled)")
	flags.Uint32Var(&r.blacklistDuration, "blacklist-duration", 600, "Seconds to blacklist a failed config")
}

func addChainFlags(cmd *cobra.Command, c *chainFlags) {
	flags := cmd.Flags()
	flags.BoolVar(&c.chain, "chain", false, "Enable outbound chaining (multi-hop proxy)")
	flags.StringVar(&c.chainLinks, "chain-links", "", "Fixed chain hops as pipe-separated config links")
	flags.StringVar(&c.chainFile, "chain-file", "", "Fixed chain hops from file (one link per line)")
	flags.Uint8Var(&c.chainHops, "chain-hops", 2, "Number of hops when selecting from pool")
	flags.StringVar(&c.chainRotation, "chain-rotation", "none", "Chain rotation mode: none, exit, full")
	flags.Uint16Var(&c.chainAttempts, "chain-attempts", 0, "Random chain combinations to try per rotation cycle (0=default)")
	cmd.RegisterFlagCompletionFunc("chain-rotation", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return []string{"none", "exit", "full"}, cobra.ShellCompDirectiveNoFileComp
	})
	cmd.MarkFlagsMutuallyExclusive("chain-links", "chain-file")
}

func addOutboundNetFlags(cmd *cobra.Command, o *outboundNetFlags) {
	flags := cmd.Flags()
	flags.StringVar(&o.bindInterface, "bind", "", "Bind outbound dials to a specific OS interface (e.g. eth0). Linux: needs CAP_NET_RAW.")
	flags.StringVar(&o.dns, "dns", "1.1.1.1", "DNS resolver used inside the app/tun-mode tunnel (ip, ip:port, or https://host/path for --dns-type=https)")
	flags.StringVar(&o.dnsType, "dns-type", "udp", "DNS transport for the app/tun-mode tunnel: udp, tcp, tls, https")
	cmd.RegisterFlagCompletionFunc("dns-type", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return []string{"udp", "tcp", "tls", "https"}, cobra.ShellCompDirectiveNoFileComp
	})
}

// validateChainFlags runs the three chain-related cross-flag checks that
// today live in cmd/proxy/proxy.go:122-145. coreType is the resolved
// parent --core value (already defaulted to "xray").
func validateChainFlags(c *chainFlags, coreType string) error {
	// Treat "fixed chain provided" as implicitly enabling --chain so users
	// don't have to pass --chain alongside --chain-links / --chain-file.
	if c.chainLinks != "" || c.chainFile != "" {
		c.chain = true
	}
	// Default the rotation mode to "none" if left blank.
	if c.chainRotation == "" {
		c.chainRotation = "none"
	}
	if c.chainRotation != "none" && !c.chain {
		return fmt.Errorf("--chain-rotation requires --chain")
	}
	if c.chain {
		if coreType == "auto" {
			return fmt.Errorf("--chain requires an explicit core type (xray or sing-box), not auto")
		}
		if c.chainHops < 2 {
			c.chainHops = 2
		}
		// Fixed chains are incompatible with rotation.
		if (c.chainLinks != "" || c.chainFile != "") && c.chainRotation != "none" {
			return fmt.Errorf("--chain-rotation is incompatible with --chain-links / --chain-file (fixed chains don't rotate)")
		}
	}
	return nil
}

// resolveLinks reads config links from the persistent --config / --file /
// --stdin flags (mutual exclusion is enforced by cobra on the parent).
// If none are set, returns nil — pkg/proxy then falls back to the DB pool.
func resolveLinks(p *parentFlags) ([]string, error) {
	switch {
	case p.configFile != "":
		return utils.ParseFileByNewline(p.configFile), nil
	case p.configLink != "":
		return []string{p.configLink}, nil
	case p.readFromSTDIN:
		scanner := bufio.NewScanner(os.Stdin)
		fmt.Println("Reading config links from STDIN (press CTRL+D when done):")
		var links []string
		for scanner.Scan() {
			if trimmed := strings.TrimSpace(scanner.Text()); trimmed != "" {
				links = append(links, trimmed)
			}
		}
		if err := scanner.Err(); err != nil {
			return nil, fmt.Errorf("error reading from stdin: %w", err)
		}
		return links, nil
	}
	return nil, nil
}

// runService is the common runtime path for all four subcommands: build
// the pkgproxy.Service, set up signal handling (incl. SIGHUP for tun),
// start the manual-rotation stdin reader (skipped when app+shell), and
// block on service.Run until the context is cancelled.
//
// shellInteractive is true only for AppCmd when --shell is set — it
// suppresses the stdin reader because the spawned shell takes stdin.
func runService(ctx context.Context, cfg pkgproxy.Config, shellInteractive bool) error {
	service, err := pkgproxy.New(cfg, nil)
	if err != nil {
		return err
	}
	defer service.Close()

	runCtx, cancel := context.WithCancel(ctx)
	signalChan := make(chan os.Signal, 1)
	// SIGHUP is caught for tun mode running over SSH: when the SSH
	// session drops, the kernel sends SIGHUP to the controlling
	// process group. Without catching it, the process dies before
	// service.Close() can tear down the TUN and routing rules,
	// leaving the host unreachable.
	signal.Notify(signalChan, os.Interrupt, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	defer func() {
		signal.Stop(signalChan)
		cancel()
	}()
	go func() {
		select {
		case sig := <-signalChan:
			customlog.Printf(customlog.Processing, "Received signal: %v. Shutting down...\n", sig)
			cancel()
		case <-runCtx.Done():
		}
	}()

	forceRotateChan := make(chan struct{})
	if service.ConfigCount() > 1 && !shellInteractive {
		go func() {
			reader := bufio.NewReader(os.Stdin)
			for {
				// ReadString returns an error on EOF (e.g. when stdin
				// is /dev/null or a closed pipe). Without this guard
				// the loop spins, sending forceRotate signals as fast
				// as the rotation worker can accept them.
				if _, err := reader.ReadString('\n'); err != nil {
					return
				}
				select {
				case forceRotateChan <- struct{}{}:
				case <-runCtx.Done():
					return
				}
			}
		}()
	}

	return service.Run(runCtx, forceRotateChan)
}
```

- [ ] **Step 2: Compile to confirm zero unused-import / unused-symbol errors**

```bash
cd /var/sys/xray-knife && rtk go build ./cmd/proxy/...
```

Expected: success. (No subcommand uses these helpers yet, but the package itself still compiles because the existing `proxy.go` is unchanged. The `_ = pkgproxy.Config{}` style isn't needed — every symbol is referenced inside the helpers.)

- [ ] **Step 3: Commit**

```bash
git -C /var/sys/xray-knife add cmd/proxy/shared.go
git -C /var/sys/xray-knife commit -m "proxy: add shared.go scaffolding for subcommand split"
```

---

## Task 3: Write `cmd/proxy/proxy_test.go` with the failing structural tests

**Rationale:** Lock the new CLI shape before writing it. These tests will all fail at first, then go green as Tasks 4-7 land.

**Files:**
- Create: `cmd/proxy/proxy_test.go`

- [ ] **Step 1: Write the test file**

```go
package proxy

import (
	"sort"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

func findSubcommand(name string) *cobra.Command {
	for _, c := range ProxyCmd.Commands() {
		if c.Name() == name {
			return c
		}
	}
	return nil
}

func allFlagNames(cmd *cobra.Command) []string {
	var out []string
	cmd.Flags().VisitAll(func(f *pflag.Flag) { out = append(out, f.Name) })
	sort.Strings(out)
	return out
}

func localFlagNames(cmd *cobra.Command) []string {
	var out []string
	cmd.LocalFlags().VisitAll(func(f *pflag.Flag) { out = append(out, f.Name) })
	sort.Strings(out)
	return out
}

func contains(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}

// resetProxyState zeroes the package-level flag bags so cobra's
// SetArgs+Execute pattern doesn't leak values between tests. Call as
// t.Cleanup(resetProxyState) at the start of any test that runs Execute.
func resetProxyState() {
	pf = parentFlags{}
	inboundCmdRot = inboundCfgPair{}
	systemCmdRot = inboundCfgPair{}
	appCmdMode = appCfg{}
	appCmdRot = rotationFlags{}
	appCmdCh = chainFlags{}
	appCmdOn = outboundNetFlags{}
	tunCmdMode = tunCfg{}
	tunCmdRot = rotationFlags{}
	tunCmdCh = chainFlags{}
	tunCmdOn = outboundNetFlags{}
}

// --- subcommand registration ---

func TestProxyCmd_HasFourSubcommands(t *testing.T) {
	want := []string{"inbound", "system", "app", "tun"}
	for _, name := range want {
		if findSubcommand(name) == nil {
			t.Errorf("ProxyCmd missing subcommand %q", name)
		}
	}
}

func TestProxyCmd_NoModeFlag(t *testing.T) {
	if ProxyCmd.Flags().Lookup("mode") != nil {
		t.Errorf("ProxyCmd still exposes the deprecated --mode flag")
	}
}

func TestProxyCmd_BareInvocationPrintsHelp(t *testing.T) {
	if ProxyCmd.RunE != nil || ProxyCmd.Run != nil {
		t.Errorf("ProxyCmd should have no RunE/Run so cobra prints help on bare invocation")
	}
}

// --- persistent flags on parent ---

func TestProxyCmd_PersistentFlags(t *testing.T) {
	want := []string{"core", "config", "file", "stdin", "addr", "port", "verbose", "insecure"}
	persistentNames := []string{}
	ProxyCmd.PersistentFlags().VisitAll(func(f *pflag.Flag) { persistentNames = append(persistentNames, f.Name) })
	sort.Strings(persistentNames)
	for _, name := range want {
		if !contains(persistentNames, name) {
			t.Errorf("persistent flag %q missing from ProxyCmd; got: %v", name, persistentNames)
		}
	}
}

// --- flag scoping: app-only ---

func TestAppCmd_LocalFlags(t *testing.T) {
	app := findSubcommand("app")
	if app == nil {
		t.Fatal("AppCmd not found")
	}
	local := localFlagNames(app)
	for _, want := range []string{"shell", "namespace"} {
		if !contains(local, want) {
			t.Errorf("AppCmd missing local flag %q; got: %v", want, local)
		}
	}
	// Inbound protocol flags must NOT be on app.
	for _, forbidden := range []string{"inbound", "transport", "uuid", "inbound-config"} {
		if contains(local, forbidden) {
			t.Errorf("AppCmd should not have local flag %q", forbidden)
		}
	}
}

// --- flag scoping: tun-only ---

func TestTunCmd_LocalFlags(t *testing.T) {
	tun := findSubcommand("tun")
	if tun == nil {
		t.Fatal("TunCmd not found")
	}
	local := localFlagNames(tun)
	for _, want := range []string{
		"i-might-lose-ssh", "tun-deadman", "tun-exclude",
		"tun-name", "tun-addr", "tun-mtu", "tun-include-private",
	} {
		if !contains(local, want) {
			t.Errorf("TunCmd missing local flag %q; got: %v", want, local)
		}
	}
	// Renamed flags must NOT exist with old names.
	for _, oldName := range []string{
		"host-tun-deadman", "host-tun-exclude", "host-tun-name",
		"host-tun-addr", "host-tun-mtu", "host-tun-include-private",
	} {
		if contains(local, oldName) {
			t.Errorf("TunCmd still exposes old flag name %q (should be tun-* without host- prefix)", oldName)
		}
	}
	// shell/namespace must not appear on tun.
	for _, forbidden := range []string{"shell", "namespace"} {
		if contains(local, forbidden) {
			t.Errorf("TunCmd should not have local flag %q", forbidden)
		}
	}
}

// --- flag scoping: --i-might-lose-ssh appears nowhere except tun ---

func TestIMightLoseSSH_OnlyOnTun(t *testing.T) {
	for _, name := range []string{"inbound", "system", "app"} {
		sub := findSubcommand(name)
		if sub == nil {
			continue
		}
		if sub.Flags().Lookup("i-might-lose-ssh") != nil {
			t.Errorf("subcommand %q should not have flag --i-might-lose-ssh", name)
		}
	}
}

// --- flag scoping: inbound + system have inbound protocol flags ---

func TestInboundAndSystem_HaveInboundProtocolFlags(t *testing.T) {
	for _, name := range []string{"inbound", "system"} {
		sub := findSubcommand(name)
		if sub == nil {
			t.Fatalf("subcommand %q not found", name)
		}
		for _, want := range []string{"inbound", "transport", "uuid", "inbound-config"} {
			if sub.Flags().Lookup(want) == nil {
				t.Errorf("subcommand %q missing flag %q", name, want)
			}
		}
	}
}

// --- mutual exclusion: --shell / --namespace on app ---

func TestAppCmd_ShellNamespaceMutuallyExclusive(t *testing.T) {
	app := findSubcommand("app")
	if app == nil {
		t.Fatal("AppCmd not found")
	}
	t.Cleanup(resetProxyState)
	ProxyCmd.SetArgs([]string{"app", "--shell", "--namespace", "ns1"})
	ProxyCmd.SilenceUsage = true
	ProxyCmd.SilenceErrors = true
	err := ProxyCmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "mutually exclusive") {
		t.Errorf("expected mutually-exclusive error, got: %v", err)
	}
}

// --- mutual exclusion: --config / --file / --stdin on parent ---

func TestProxyCmd_ConfigSourcesMutuallyExclusive(t *testing.T) {
	t.Cleanup(resetProxyState)
	ProxyCmd.SetArgs([]string{"inbound", "--config", "x", "--file", "y"})
	ProxyCmd.SilenceUsage = true
	ProxyCmd.SilenceErrors = true
	err := ProxyCmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "mutually exclusive") {
		t.Errorf("expected mutually-exclusive error for --config + --file, got: %v", err)
	}
}

// --- required: --i-might-lose-ssh + --bind on tun ---

func TestTunCmd_RequiredFlags(t *testing.T) {
	t.Cleanup(resetProxyState)
	ProxyCmd.SetArgs([]string{"tun"})
	ProxyCmd.SilenceUsage = true
	ProxyCmd.SilenceErrors = true
	err := ProxyCmd.Execute()
	if err == nil {
		t.Fatal("expected required-flag error for `proxy tun` with no flags")
	}
	if !strings.Contains(err.Error(), "i-might-lose-ssh") && !strings.Contains(err.Error(), "bind") {
		t.Errorf("expected required-flag error to mention i-might-lose-ssh or bind, got: %v", err)
	}
}

// --- chain validation helper ---

func TestValidateChainFlags(t *testing.T) {
	cases := []struct {
		name    string
		c       chainFlags
		core    string
		wantErr string
	}{
		{name: "no chain, no error", c: chainFlags{}, core: "xray", wantErr: ""},
		{name: "chain-rotation without --chain", c: chainFlags{chainRotation: "full"}, core: "xray", wantErr: "--chain-rotation requires --chain"},
		{name: "fixed chain + rotation", c: chainFlags{chainLinks: "vless://x|vmess://y", chainRotation: "full"}, core: "xray", wantErr: "--chain-rotation is incompatible"},
		{name: "chain with auto core", c: chainFlags{chain: true}, core: "auto", wantErr: "explicit core type"},
		{name: "chain with default hops bumps to 2", c: chainFlags{chain: true, chainHops: 1}, core: "xray", wantErr: ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateChainFlags(&tc.c, tc.core)
			if tc.wantErr == "" {
				if err != nil {
					t.Errorf("expected nil err, got %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("expected err containing %q, got %v", tc.wantErr, err)
			}
		})
	}
}
```

- [ ] **Step 2: Run tests — expect compile errors or failures**

```bash
cd /var/sys/xray-knife && rtk go test ./cmd/proxy/ -v
```

Expected: tests fail because:
- `findSubcommand("inbound")` etc. return nil — subcommands don't exist yet.
- `--mode` flag still present on `ProxyCmd`.
- `validateChainFlags` exists (added in Task 2) so the helper test compiles and may pass for the simple case.

(The compile may fail if `chainFlags` is unexported — adjust the test imports / use a thin exported wrapper inside `shared.go` if needed. Since the test file is in the same `package proxy`, unexported types are reachable.)

- [ ] **Step 3: Commit (red tests)**

```bash
git -C /var/sys/xray-knife add cmd/proxy/proxy_test.go
git -C /var/sys/xray-knife commit -m "proxy: add failing structural tests for subcommand split"
```

---

## Task 4: Implement `cmd/proxy/inbound.go`

**Files:**
- Create: `cmd/proxy/inbound.go`

- [ ] **Step 1: Write the file**

```go
package proxy

import (
	"github.com/spf13/cobra"
)

// inboundCfg holds inbound-specific flag values.
type inboundCfg struct {
	inboundProtocol   string
	inboundTransport  string
	inboundUUID       string
	inboundConfigLink string
}

// inboundCfgPair groups inbound-specific + the shared rotation/chain/net
// flag structs so SystemCmd can reuse the layout without name clashes.
type inboundCfgPair struct {
	in  inboundCfg
	rot rotationFlags
	ch  chainFlags
	on  outboundNetFlags
}

var inboundCmdRot inboundCfgPair

// InboundCmd is the `proxy inbound` subcommand.
var InboundCmd = newInboundCommand()

func newInboundCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "inbound",
		Short: "Run a local inbound proxy that tunnels traffic through a remote configuration. Supports automatic rotation.",
		Long: `Runs a local inbound proxy on --addr:--port. Configurations are read
from --config / --file / --stdin or, if none of those are provided, the
local subscription database (populated via 'xray-knife subs fetch').`,
		Example: `  xray-knife proxy inbound                                # use DB pool, default port 9999
  xray-knife proxy inbound -c "vless://..."               # one-shot single config
  xray-knife proxy inbound -f configs.txt -t 60           # rotate every 60s from file
  xray-knife proxy inbound --chain --chain-hops 3         # 3-hop chain from DB pool`,
		RunE: runInbound,
	}

	flags := cmd.Flags()
	flags.StringVarP(&inboundCmdRot.in.inboundProtocol, "inbound", "j", "socks", "Inbound protocol to use (vless, vmess, socks)")
	flags.StringVarP(&inboundCmdRot.in.inboundTransport, "transport", "u", "tcp", "Inbound transport to use (tcp, ws, grpc, xhttp)")
	flags.StringVarP(&inboundCmdRot.in.inboundUUID, "uuid", "g", "random", "Inbound custom UUID to use (default: random)")
	flags.StringVarP(&inboundCmdRot.in.inboundConfigLink, "inbound-config", "I", "", "Custom config link for the inbound proxy")
	cmd.MarkFlagsMutuallyExclusive("inbound-config", "inbound")

	addRotationFlags(cmd, &inboundCmdRot.rot)
	addChainFlags(cmd, &inboundCmdRot.ch)
	addOutboundNetFlags(cmd, &inboundCmdRot.on)

	return cmd
}

func runInbound(cmd *cobra.Command, args []string) error {
	if err := validateChainFlags(&inboundCmdRot.ch, pf.coreType); err != nil {
		return err
	}
	links, err := resolveLinks(&pf)
	if err != nil {
		return err
	}
	cfg := buildPkgConfig("inbound", &pf, &inboundCmdRot.in, &inboundCmdRot.rot, &inboundCmdRot.ch, &inboundCmdRot.on, nil, nil)
	cfg.ConfigLinks = links
	return runService(cmd.Context(), cfg, false)
}
```

- [ ] **Step 2: Add `buildPkgConfig` helper to `shared.go`**

The helper centralises Config construction so all four subcommands stay in sync. Append to `cmd/proxy/shared.go`:

```go
// appCfg / tunCfg are the per-mode flag groups. Defined in app.go and
// tun.go respectively; declared here as forward types to keep the
// buildPkgConfig signature in one place.
type appCfg struct {
	shell         bool
	namespaceName string
}

type tunCfg struct {
	hostTunAck            bool
	hostTunDeadman        uint16
	hostTunExclude        string
	hostTunName           string
	hostTunAddr           string
	hostTunMTU            uint32
	hostTunIncludePrivate bool // CLI flag --tun-include-private; service expects ExcludePrivate so we negate.
}

// buildPkgConfig assembles a pkgproxy.Config from the parent flags + the
// per-subcommand flag groups. mode must be one of "inbound", "system",
// "app", "host-tun" (note "host-tun" — internal pkg/proxy still uses the
// pre-rename mode string). Pass nil for any group not relevant to mode.
func buildPkgConfig(
	mode string,
	p *parentFlags,
	in *inboundCfg,
	rot *rotationFlags,
	ch *chainFlags,
	on *outboundNetFlags,
	app *appCfg,
	tun *tunCfg,
) pkgproxy.Config {
	cfg := pkgproxy.Config{
		Mode:        mode,
		CoreType:    p.coreType,
		ListenAddr:  p.listenAddr,
		ListenPort:  p.listenPort,
		Verbose:     p.verbose,
		InsecureTLS: p.insecureTLS,
	}
	if in != nil {
		cfg.InboundProtocol = in.inboundProtocol
		cfg.InboundTransport = in.inboundTransport
		cfg.InboundUUID = in.inboundUUID
		cfg.InboundConfigLink = in.inboundConfigLink
	}
	if rot != nil {
		cfg.RotationInterval = rot.rotationInterval
		cfg.MaximumAllowedDelay = rot.maximumAllowedDelay
		cfg.BatchSize = rot.batchSize
		cfg.Concurrency = rot.concurrency
		cfg.HealthCheckInterval = rot.healthCheckInterval
		cfg.HealthFailThreshold = rot.healthFailThreshold
		cfg.DrainTimeout = rot.drainTimeout
		cfg.BlacklistStrikes = rot.blacklistStrikes
		cfg.BlacklistDuration = rot.blacklistDuration
	}
	if ch != nil {
		cfg.Chain = ch.chain
		cfg.ChainLinks = ch.chainLinks
		cfg.ChainFile = ch.chainFile
		cfg.ChainHops = ch.chainHops
		cfg.ChainRotation = ch.chainRotation
		cfg.ChainAttempts = ch.chainAttempts
	}
	if on != nil {
		cfg.BindInterface = on.bindInterface
		cfg.DNS = on.dns
		cfg.DNSType = on.dnsType
	}
	if app != nil {
		cfg.Shell = app.shell
		cfg.NamespaceName = app.namespaceName
	}
	if tun != nil {
		cfg.HostTunAck = tun.hostTunAck
		cfg.HostTunDeadman = tun.hostTunDeadman
		cfg.HostTunExclude = tun.hostTunExclude
		cfg.HostTunName = tun.hostTunName
		cfg.HostTunAddr = tun.hostTunAddr
		cfg.HostTunMTU = tun.hostTunMTU
		// CLI flag is --tun-include-private (default false = exclude).
		// pkg/proxy field is HostTunExcludePrivate (default true).
		cfg.HostTunExcludePrivate = !tun.hostTunIncludePrivate
	}
	return cfg
}
```

- [ ] **Step 3: Compile to confirm `inbound.go` + updated `shared.go` build**

```bash
cd /var/sys/xray-knife && rtk go build ./cmd/proxy/...
```

Expected: success. (Wiring into `ProxyCmd` happens in Task 7.)

- [ ] **Step 4: Commit**

```bash
git -C /var/sys/xray-knife add cmd/proxy/inbound.go cmd/proxy/shared.go
git -C /var/sys/xray-knife commit -m "proxy: add inbound subcommand + buildPkgConfig helper"
```

---

## Task 5: Implement `cmd/proxy/system.go`

**Files:**
- Create: `cmd/proxy/system.go`

- [ ] **Step 1: Write the file**

```go
package proxy

import (
	"github.com/spf13/cobra"
)

// SystemCmd is the `proxy system` subcommand. Same flag set as
// InboundCmd but Mode="system" so pkg/proxy registers an OS-level
// proxy (sysproxy.Manager) for the lifetime of the command.
var SystemCmd = newSystemCommand()

var systemCmdRot inboundCfgPair

func newSystemCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "system",
		Short: "Like 'inbound', plus register the running proxy as the OS system proxy.",
		Long: `Runs a local inbound proxy AND configures the host OS to route HTTP/HTTPS
traffic through it. On exit, the previous OS proxy settings are restored.

OS-specific behavior:
  Linux:   GNOME / KDE proxy settings via gsettings / kwriteconfig5
  macOS:   networksetup -setwebproxy / -setsecurewebproxy / -setsocksfirewallproxy
  Windows: per-protocol ProxyServer registry keys + WinINet refresh`,
		Example: `  xray-knife proxy system                # DB pool, OS proxy on 127.0.0.1:9999
  xray-knife proxy system -c "vless://..." -p 8080`,
		RunE: runSystem,
	}

	flags := cmd.Flags()
	flags.StringVarP(&systemCmdRot.in.inboundProtocol, "inbound", "j", "socks", "Inbound protocol to use (vless, vmess, socks)")
	flags.StringVarP(&systemCmdRot.in.inboundTransport, "transport", "u", "tcp", "Inbound transport to use (tcp, ws, grpc, xhttp)")
	flags.StringVarP(&systemCmdRot.in.inboundUUID, "uuid", "g", "random", "Inbound custom UUID to use (default: random)")
	flags.StringVarP(&systemCmdRot.in.inboundConfigLink, "inbound-config", "I", "", "Custom config link for the inbound proxy")
	cmd.MarkFlagsMutuallyExclusive("inbound-config", "inbound")

	addRotationFlags(cmd, &systemCmdRot.rot)
	addChainFlags(cmd, &systemCmdRot.ch)
	addOutboundNetFlags(cmd, &systemCmdRot.on)

	return cmd
}

func runSystem(cmd *cobra.Command, args []string) error {
	if err := validateChainFlags(&systemCmdRot.ch, pf.coreType); err != nil {
		return err
	}
	links, err := resolveLinks(&pf)
	if err != nil {
		return err
	}
	cfg := buildPkgConfig("system", &pf, &systemCmdRot.in, &systemCmdRot.rot, &systemCmdRot.ch, &systemCmdRot.on, nil, nil)
	cfg.ConfigLinks = links
	return runService(cmd.Context(), cfg, false)
}
```

- [ ] **Step 2: Compile**

```bash
cd /var/sys/xray-knife && rtk go build ./cmd/proxy/...
```

Expected: success.

- [ ] **Step 3: Commit**

```bash
git -C /var/sys/xray-knife add cmd/proxy/system.go
git -C /var/sys/xray-knife commit -m "proxy: add system subcommand"
```

---

## Task 6: Implement `cmd/proxy/app.go`

**Files:**
- Create: `cmd/proxy/app.go`

- [ ] **Step 1: Write the file**

```go
package proxy

import (
	"github.com/spf13/cobra"
)

// AppCmd is the `proxy app` subcommand: per-process network namespace
// (Linux only, requires root). Either --shell drops the user into an
// interactive shell inside the namespace, or --namespace creates a
// named netns that other processes can join via `ip netns exec`.
var AppCmd = newAppCommand()

var (
	appCmdMode appCfg
	appCmdRot  rotationFlags
	appCmdCh   chainFlags
	appCmdOn   outboundNetFlags
)

func newAppCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "app",
		Short: "Run the proxy inside a per-process Linux network namespace.",
		Long: `Creates a Linux network namespace, sets up a veth pair, runs a SOCKS
listener inside the namespace, and routes all in-namespace traffic
through the proxy. Requires root (sudo).

Use --shell to drop into an interactive shell in the namespace, or
--namespace <name> to create a named netns other processes can join
with 'ip netns exec <name> <cmd>'.`,
		Example: `  sudo xray-knife proxy app --shell -c "vless://..."
  sudo xray-knife proxy app --namespace work -f configs.txt`,
		RunE: runApp,
	}

	flags := cmd.Flags()
	flags.BoolVar(&appCmdMode.shell, "shell", false, "Launch an interactive shell inside the proxy namespace")
	flags.StringVar(&appCmdMode.namespaceName, "namespace", "", "Create a named namespace for the proxy")
	cmd.MarkFlagsMutuallyExclusive("shell", "namespace")

	addRotationFlags(cmd, &appCmdRot)
	addChainFlags(cmd, &appCmdCh)
	addOutboundNetFlags(cmd, &appCmdOn)

	return cmd
}

func runApp(cmd *cobra.Command, args []string) error {
	if err := validateChainFlags(&appCmdCh, pf.coreType); err != nil {
		return err
	}
	links, err := resolveLinks(&pf)
	if err != nil {
		return err
	}
	cfg := buildPkgConfig("app", &pf, nil, &appCmdRot, &appCmdCh, &appCmdOn, &appCmdMode, nil)
	cfg.ConfigLinks = links
	// shell-interactive suppresses the manual rotation reader because the
	// spawned shell takes over stdin.
	return runService(cmd.Context(), cfg, appCmdMode.shell)
}
```

- [ ] **Step 2: Compile**

```bash
cd /var/sys/xray-knife && rtk go build ./cmd/proxy/...
```

Expected: success.

- [ ] **Step 3: Commit**

```bash
git -C /var/sys/xray-knife add cmd/proxy/app.go
git -C /var/sys/xray-knife commit -m "proxy: add app subcommand"
```

---

## Task 7: Implement `cmd/proxy/tun.go`

**Files:**
- Create: `cmd/proxy/tun.go`

- [ ] **Step 1: Write the file**

```go
package proxy

import (
	"github.com/spf13/cobra"
)

// TunCmd is the `proxy tun` subcommand: host-wide TUN capture (Linux
// only). Replaces the host's default route, captures all egress
// traffic, and forwards it through the proxy. Dangerous over SSH —
// requires --i-might-lose-ssh acknowledgement.
var TunCmd = newTunCommand()

var (
	tunCmdMode tunCfg
	tunCmdRot  rotationFlags
	tunCmdCh   chainFlags
	tunCmdOn   outboundNetFlags
)

func newTunCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "tun",
		Short: "Capture all host egress through a TUN device (Linux only, DANGEROUS over SSH).",
		Long: `Creates a TUN interface, replaces the host's default route, and forwards
all egress through the rotating proxy. Linux only. Requires root.

WARNING: this mode replaces the default route. If you run it over an
SSH session, the route swap can drop your SSH connection. Pass
--i-might-lose-ssh to acknowledge. The default --tun-deadman of 60s
gives you a grace period to confirm the tunnel is working before the
process self-terminates.`,
		Example: `  sudo xray-knife proxy tun --bind eth0 --i-might-lose-ssh
  sudo xray-knife proxy tun --bind eth0 --i-might-lose-ssh --tun-include-private`,
		RunE: runTun,
	}

	flags := cmd.Flags()
	flags.BoolVar(&tunCmdMode.hostTunAck, "i-might-lose-ssh", false, "Required ack: confirms you understand this can kill your active SSH session.")
	flags.Uint16Var(&tunCmdMode.hostTunDeadman, "tun-deadman", 60, "Seconds to wait for ENTER after tun comes up before auto-teardown (0 = disable)")
	flags.StringVar(&tunCmdMode.hostTunExclude, "tun-exclude", "", "Comma-separated extra CIDRs to exclude from tun capture")
	flags.StringVar(&tunCmdMode.hostTunName, "tun-name", "xkt0", "TUN interface name")
	flags.StringVar(&tunCmdMode.hostTunAddr, "tun-addr", "198.18.0.1/30", "TUN address/CIDR (RFC 2544 by default to avoid LAN collision)")
	flags.Uint32Var(&tunCmdMode.hostTunMTU, "tun-mtu", 1500, "TUN MTU")
	flags.BoolVar(&tunCmdMode.hostTunIncludePrivate, "tun-include-private", false, "Capture RFC1918 / private LAN traffic too (default: excluded). Risky over LAN.")

	if err := cmd.MarkFlagRequired("i-might-lose-ssh"); err != nil {
		panic(err) // programmer error: flag was just registered above
	}

	addRotationFlags(cmd, &tunCmdRot)
	addChainFlags(cmd, &tunCmdCh)
	addOutboundNetFlags(cmd, &tunCmdOn)

	// --bind is registered by addOutboundNetFlags; mark it required for
	// tun mode (sing-box must pin its outbound dials to the physical NIC).
	if err := cmd.MarkFlagRequired("bind"); err != nil {
		panic(err)
	}

	return cmd
}

func runTun(cmd *cobra.Command, args []string) error {
	if err := validateChainFlags(&tunCmdCh, pf.coreType); err != nil {
		return err
	}
	links, err := resolveLinks(&pf)
	if err != nil {
		return err
	}
	// Internal pkg/proxy mode string remains "host-tun" — the rename is
	// CLI-only.
	cfg := buildPkgConfig("host-tun", &pf, nil, &tunCmdRot, &tunCmdCh, &tunCmdOn, nil, &tunCmdMode)
	cfg.ConfigLinks = links
	return runService(cmd.Context(), cfg, false)
}
```

- [ ] **Step 2: Compile**

```bash
cd /var/sys/xray-knife && rtk go build ./cmd/proxy/...
```

Expected: success.

- [ ] **Step 3: Commit**

```bash
git -C /var/sys/xray-knife add cmd/proxy/tun.go
git -C /var/sys/xray-knife commit -m "proxy: add tun subcommand (renamed from host-tun)"
```

---

## Task 8: Rewrite `cmd/proxy/proxy.go` to be parent-only + wire subcommands

**Files:**
- Modify: `cmd/proxy/proxy.go` (full rewrite — replace 322 lines with ~60)

- [ ] **Step 1: Replace the file contents**

```go
package proxy

import (
	"github.com/spf13/cobra"
)

// ProxyCmd is the parent for the proxy subcommand family.
//
// Bare `xray-knife proxy` prints help (no RunE — cobra's default).
// All real work lives in the four subcommands: inbound, system,
// app, tun.
var ProxyCmd = newProxyCommand()

func newProxyCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "proxy",
		Short: "Run a local proxy that tunnels traffic through a remote configuration. Supports rotation and multiple operating modes.",
		Long: `Run a proxy in one of four modes:

  inbound  — local listener (default for most use cases)
  system   — local listener + register as the OS system proxy
  app      — per-process Linux network namespace (--shell / --namespace)
  tun      — host-wide TUN capture (Linux only, DANGEROUS over SSH)

Configurations are read from --config / --file / --stdin or, if none of
those are provided, from the local subscription database (populate with
'xray-knife subs fetch').`,
	}

	flags := cmd.PersistentFlags()
	flags.StringVarP(&pf.coreType, "core", "z", "xray", "Core type: (xray, sing-box)")
	cmd.RegisterFlagCompletionFunc("core", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return []string{"xray", "sing-box"}, cobra.ShellCompDirectiveNoFileComp
	})
	flags.StringVarP(&pf.configLink, "config", "c", "", "The single xray/sing-box config link to use")
	flags.StringVarP(&pf.configFile, "file", "f", "", "Read config links from a file")
	flags.BoolVarP(&pf.readFromSTDIN, "stdin", "i", false, "Read config link(s) from STDIN")
	flags.StringVarP(&pf.listenAddr, "addr", "a", "127.0.0.1", "Listen ip address for the proxy server")
	flags.StringVarP(&pf.listenPort, "port", "p", "9999", "Listen port number for the proxy server")
	flags.BoolVarP(&pf.verbose, "verbose", "v", false, "Enable verbose logging for the selected core")
	flags.BoolVarP(&pf.insecureTLS, "insecure", "e", false, "Allow insecure TLS connections (e.g., self-signed certs)")

	cmd.MarkFlagsMutuallyExclusive("config", "file", "stdin")

	addSubcommandPalettes(cmd)
	return cmd
}

func addSubcommandPalettes(cmd *cobra.Command) {
	cmd.AddCommand(InboundCmd)
	cmd.AddCommand(SystemCmd)
	cmd.AddCommand(AppCmd)
	cmd.AddCommand(TunCmd)
}
```

- [ ] **Step 2: Build and run all tests**

```bash
cd /var/sys/xray-knife && rtk go build ./... && rtk go test ./...
```

Expected:
- Build succeeds.
- `cmd/proxy/proxy_test.go` tests now PASS:
  - `TestProxyCmd_HasFourSubcommands`
  - `TestProxyCmd_NoModeFlag`
  - `TestProxyCmd_BareInvocationPrintsHelp`
  - `TestProxyCmd_PersistentFlags`
  - `TestAppCmd_LocalFlags`
  - `TestTunCmd_LocalFlags`
  - `TestIMightLoseSSH_OnlyOnTun`
  - `TestInboundAndSystem_HaveInboundProtocolFlags`
  - `TestAppCmd_ShellNamespaceMutuallyExclusive`
  - `TestProxyCmd_ConfigSourcesMutuallyExclusive`
  - `TestTunCmd_RequiredFlags`
  - `TestValidateChainFlags`
- `pkg/proxy/service_test.go::TestNew_NoConfigsErrorMessage` still passes.

- [ ] **Step 3: Run `xray-knife proxy --help` to eyeball the new output**

```bash
cd /var/sys/xray-knife && rtk go run . proxy --help > /tmp/proxy-help-after.txt 2>&1; cat /tmp/proxy-help-after.txt
```

Expected: shows the 4 subcommands under `Available Commands:` and only the persistent flags (8 of them) under `Flags:`. No `--mode`, no `--shell`, no `--tun-*`, no `--rotate`, etc.

- [ ] **Step 4: Inspect each subcommand help**

```bash
cd /var/sys/xray-knife && rtk go run . proxy inbound --help
cd /var/sys/xray-knife && rtk go run . proxy app --help
cd /var/sys/xray-knife && rtk go run . proxy tun --help
```

Expected:
- `inbound --help` shows inbound + rotation + chain + outbound-net flags + `Global Flags:` (the persistent ones from parent).
- `app --help` shows `--shell`, `--namespace`, rotation, chain, outbound-net, no inbound protocol flags.
- `tun --help` shows `--i-might-lose-ssh` (marked required), `--tun-*`, rotation, chain, outbound-net, `--bind` (marked required).

- [ ] **Step 5: Commit**

```bash
git -C /var/sys/xray-knife add cmd/proxy/proxy.go
git -C /var/sys/xray-knife commit -m "proxy: rewrite parent as subcommand-only, wire 4 subcommands"
```

---

## Task 9: Bump version + write release notes

**Files:**
- Modify: `cmd/root.go` line 25
- Create: `RELEASE_NOTES_v10.0.0.md`

- [ ] **Step 1: Bump the version string**

In `cmd/root.go`, change:

```go
Version: "9.12.1",
```

to:

```go
Version: "10.0.0",
```

- [ ] **Step 2: Write release notes**

Create `RELEASE_NOTES_v10.0.0.md`:

```markdown
# v10.0.0 — Proxy CLI restructure (BREAKING)

The `proxy` command has been split into four mode-specific subcommands.
The `--mode` flag is gone; `host-tun` is renamed to `tun`; the
`--host-tun-*` flags are renamed to `--tun-*`.

## Breaking changes

### `--mode` removed; use subcommands

| Old | New |
|---|---|
| `xray-knife proxy` (defaulted to inbound) | `xray-knife proxy inbound` |
| `xray-knife proxy --mode inbound` | `xray-knife proxy inbound` |
| `xray-knife proxy --mode system` | `xray-knife proxy system` |
| `xray-knife proxy --mode app --shell` | `xray-knife proxy app --shell` |
| `xray-knife proxy --mode host-tun ...` | `xray-knife proxy tun ...` |

### `host-tun` renamed to `tun`; flag prefix renamed

| Old flag | New flag |
|---|---|
| `--host-tun-deadman` | `--tun-deadman` |
| `--host-tun-exclude` | `--tun-exclude` |
| `--host-tun-name` | `--tun-name` |
| `--host-tun-addr` | `--tun-addr` |
| `--host-tun-mtu` | `--tun-mtu` |
| `--host-tun-include-private` | `--tun-include-private` |

### Persistent flags

`--core`, `--config`, `--file`, `--stdin`, `--addr`, `--port`,
`--verbose`, `--insecure` are now persistent on the `proxy` parent.
They may appear before OR after the subcommand name. All other flags
must appear after the subcommand name.

## UX improvements

- `xray-knife proxy --help` and per-subcommand `--help` now show only
  the relevant flag set (no more cross-mode flag pollution).
- `--shell` / `--namespace` are visible only on `proxy app`.
- `--i-might-lose-ssh` and `--tun-*` are visible only on `proxy tun`.
- `--i-might-lose-ssh` and `--bind` are now marked required for `tun`,
  so cobra rejects bad invocations at parse time instead of failing
  inside the service.
- The "no configs in database" error now hints at both `subs fetch`
  AND `--config / --file / --stdin`.
- Each subcommand has an `Examples:` block.

## Migration

Update any scripts or systemd units that invoke `xray-knife proxy
--mode X` to use the subcommand form. The `--mode` flag will produce
a clear `unknown flag: --mode` error.
```

- [ ] **Step 3: Verify version**

```bash
cd /var/sys/xray-knife && rtk go run . --version
```

Expected: `xray-knife version 10.0.0`.

- [ ] **Step 4: Commit**

```bash
git -C /var/sys/xray-knife add cmd/root.go RELEASE_NOTES_v10.0.0.md
git -C /var/sys/xray-knife commit -m "release: bump to v10.0.0 with proxy subcommand split"
```

---

## Task 10: Update `README.md`

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Identify all proxy-related sections to update**

```bash
cd /var/sys/xray-knife && rtk grep -n 'proxy --mode\|host-tun\|--host-tun' README.md
```

Expected: list of line numbers needing updates.

- [ ] **Step 2: Replace `xray-knife proxy --mode X` with `xray-knife proxy X` and `host-tun` → `tun` throughout**

For each match found in Step 1:
- `xray-knife proxy --mode inbound` → `xray-knife proxy inbound`
- `xray-knife proxy --mode system` → `xray-knife proxy system`
- `xray-knife proxy --mode app` → `xray-knife proxy app`
- `xray-knife proxy --mode host-tun` → `xray-knife proxy tun`
- `--host-tun-deadman` → `--tun-deadman` (and similar for the other 5 flags)

- [ ] **Step 3: Add a "Migrating from v9" callout near the top of the proxy section**

Add (or update) a brief block:

```markdown
> **v10 breaking change:** the `--mode` flag is gone — use the subcommand form (`xray-knife proxy inbound`, etc.). `host-tun` is renamed to `tun`, and `--host-tun-*` flags become `--tun-*`. See [RELEASE_NOTES_v10.0.0.md](RELEASE_NOTES_v10.0.0.md) for the full migration table.
```

- [ ] **Step 4: Verify README still renders sensibly**

```bash
cd /var/sys/xray-knife && rtk grep -n 'proxy --mode\|--host-tun-' README.md
```

Expected: zero matches.

- [ ] **Step 5: Commit**

```bash
git -C /var/sys/xray-knife add README.md
git -C /var/sys/xray-knife commit -m "docs: update README for proxy subcommand split"
```

---

## Task 11: End-to-end manual smoke test

**Files:**
- N/A (runtime verification)

> **Note:** these checks must be performed by a human or by an agent with appropriate root privileges + network access. Document the outcome of each step in the PR description.

- [ ] **Step 1: Bare `proxy` prints help and exits 1**

```bash
cd /var/sys/xray-knife && rtk go run . proxy; echo "exit=$?"
```

Expected: cobra help text printed; `exit=1`.

- [ ] **Step 2: `proxy --mode inbound` produces a clear error**

```bash
cd /var/sys/xray-knife && rtk go run . proxy --mode inbound 2>&1 | head -3
```

Expected: `Error: unknown flag: --mode` (cobra default).

- [ ] **Step 3: `proxy inbound` runs with a single config**

```bash
cd /var/sys/xray-knife && rtk go run . proxy inbound -c "vless://<test-config>" -p 19999 &
sleep 2
curl --socks5 127.0.0.1:19999 -s -o /dev/null -w "%{http_code}\n" https://www.cloudflare.com/cdn-cgi/trace
kill %1
```

Expected: HTTP 200; process terminates cleanly.

- [ ] **Step 4: `proxy tun` rejects missing required flags clearly**

```bash
cd /var/sys/xray-knife && rtk go run . proxy tun 2>&1 | head -5
```

Expected: error mentioning `i-might-lose-ssh` and/or `bind` as required.

- [ ] **Step 5: `proxy app --shell --namespace x` rejects mutual-exclusion at parse time**

```bash
cd /var/sys/xray-knife && rtk go run . proxy app --shell --namespace x 2>&1 | head -3
```

Expected: error mentioning `mutually exclusive`.

- [ ] **Step 6: `proxy inbound --chain --core auto` rejects clearly**

```bash
cd /var/sys/xray-knife && rtk go run . proxy inbound --chain --core auto 2>&1 | head -3
```

Expected: error containing `--chain requires an explicit core type`.

- [ ] **Step 7: With empty DB and no flags, `proxy inbound` emits the new error message**

```bash
# Move any existing DB out of the way temporarily.
mv ~/.xray-knife/xray-knife.db ~/.xray-knife/xray-knife.db.bak 2>/dev/null
cd /var/sys/xray-knife && rtk go run . proxy inbound 2>&1 | head -3
# Restore.
mv ~/.xray-knife/xray-knife.db.bak ~/.xray-knife/xray-knife.db 2>/dev/null
```

Expected: error containing `no configs in database` AND `xray-knife subs fetch --all` AND `--config / --file / --stdin`.

- [ ] **Step 8: No commit needed for smoke tests**

Document outcomes in the PR description. Smoke results are evidence, not artifacts.

---

## Self-Review Checklist (run before opening PR)

- [ ] All tasks above committed; `git status` clean.
- [ ] `rtk go build ./...` succeeds.
- [ ] `rtk go test ./...` passes.
- [ ] `xray-knife proxy --help` shows 4 subcommands and 8 persistent flags only.
- [ ] `xray-knife proxy inbound --help` shows no `--shell`, `--namespace`, `--tun-*`, or `--i-might-lose-ssh`.
- [ ] `xray-knife proxy app --help` shows no inbound protocol flags (`--inbound`, `--transport`, `--uuid`, `--inbound-config`).
- [ ] `xray-knife proxy tun --help` shows `--i-might-lose-ssh` and `--bind` marked required.
- [ ] `grep -rn 'proxy --mode\|--host-tun-' README.md` returns zero matches.
- [ ] `cmd/root.go` shows `Version: "10.0.0"`.
- [ ] `RELEASE_NOTES_v10.0.0.md` exists and lists all breaking changes.
- [ ] Web UI service consumer (`web/services.go:181`) still receives a valid `pkgproxy.Config` — no changes needed there since `pkg/proxy.Config` shape is unchanged.

## Notes for the Implementer

- **Internal mode string vs CLI subcommand name.** `pkg/proxy.Service` switches on `Config.Mode == "host-tun"` at `pkg/proxy/service.go:812`. The CLI subcommand is `tun`, but `runTun` must set `cfg.Mode = "host-tun"` (already done in Task 7). Do not change `pkg/proxy` internals.
- **Package-level state vs goroutine safety.** All four subcommand flag-bag vars (`inboundCmdRot`, `systemCmdRot`, `appCmdMode`, `tunCmdMode`, etc.) are package-level singletons. This matches the existing pattern (current `proxy.go` uses a single `proxyCmdConfig` var via `newProxyCommand`). The CLI never invokes more than one subcommand per process, so no concurrency issue.
- **Why `panic` on `MarkFlagRequired` errors in `tun.go`.** `MarkFlagRequired` returns an error only if the flag name doesn't exist — a programmer error, not a runtime condition. Panic is appropriate (matches the test gating).
- **Web UI integration.** `web/services.go:181` builds a `pkgproxy.Config` directly from a JSON request body and calls `pkgproxy.New`. It does not go through the CLI layer. The Config struct shape is unchanged, so no changes are needed in `web/`.
