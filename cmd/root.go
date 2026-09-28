package cmd

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"

	"github.com/lilendian0x00/xray-knife/v11/cmd/cfscanner"
	dbcmd "github.com/lilendian0x00/xray-knife/v11/cmd/db"
	dpicmd "github.com/lilendian0x00/xray-knife/v11/cmd/dpi"
	xkexec "github.com/lilendian0x00/xray-knife/v11/cmd/exec"
	"github.com/lilendian0x00/xray-knife/v11/cmd/http"
	"github.com/lilendian0x00/xray-knife/v11/cmd/net"
	"github.com/lilendian0x00/xray-knife/v11/cmd/parse"
	"github.com/lilendian0x00/xray-knife/v11/cmd/proxy"
	"github.com/lilendian0x00/xray-knife/v11/cmd/subs"
	"github.com/lilendian0x00/xray-knife/v11/cmd/webui"
	"github.com/lilendian0x00/xray-knife/v11/database"
	"github.com/lilendian0x00/xray-knife/v11/utils/customlog"
	"github.com/lilendian0x00/xray-knife/v11/utils/exitcode"
	"github.com/lilendian0x00/xray-knife/v11/utils/interrupt"
	"github.com/lilendian0x00/xray-knife/v11/utils/xkhome"
	"github.com/spf13/cobra"
)

// version is stamped at build time:
//
//	go build -ldflags "-X github.com/lilendian0x00/xray-knife/v11/cmd.version=11.0.0"
//
// Left as "dev" for a plain `go build`, which then falls back to the module
// version recorded by `go install`.
var version = "dev"

// dbPathOverride backs the persistent --db flag. Empty means "use the default
// under XRAY_KNIFE_HOME (or ~/.xray-knife)".
var dbPathOverride string

// resolveVersion prefers the ldflags-stamped value, then the module version
// baked in by `go install`, so a source build never reports a stale release
// number it was never built from.
func resolveVersion() string {
	if version != "" && version != "dev" {
		return version
	}
	if info, ok := debug.ReadBuildInfo(); ok && info.Main.Version != "" && info.Main.Version != "(devel)" {
		return info.Main.Version
	}
	if version != "" {
		return version
	}
	return "dev"
}

// rootCmd is the top-level cobra command.
var rootCmd = &cobra.Command{
	Use:   "xray-knife",
	Short: "Swiss Army Knife for xray-core & sing-box",
	Example: `  # 1. Add a subscription and pull its configs into the local DB.
  #    Fetched links are also written to configs.txt.
  xray-knife subs add --url "https://example.com/sub" --remark "My VPN"
  xray-knife subs fetch --all

  # 2. Test the fetched configs; working ones land in valid.txt, fastest first.
  xray-knife http -f configs.txt

  # 3. Run a local SOCKS proxy on 127.0.0.1:9999 that rotates through them.
  xray-knife proxy inbound -f valid.txt`,
}

// Execute is called by main() to kick everything off. It exits the process
// with the code documented in utils/exitcode.
func Execute() {
	ctx, stop, interrupted := signalContext()
	cmd, err := rootCmd.ExecuteContextC(ctx)
	stop()
	os.Exit(exitCodeFor(cmd, err, interrupted()))
}

// signalContext returns a context cancelled by the first SIGINT/SIGTERM, so
// commands can stop and flush what they have. A second signal exits at once
// with 130 for when a command's cleanup hangs, unless the running command
// handles repeated signals itself (interrupt.Own).
func signalContext() (ctx context.Context, stop func(), interrupted func() bool) {
	ctx, cancel := context.WithCancel(context.Background())
	sigCh := make(chan os.Signal, 2)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	done := make(chan struct{})
	var got atomic.Bool
	go func() {
		select {
		case <-sigCh:
		case <-done:
			return
		}
		got.Store(true)
		cancel()
		for {
			select {
			case <-sigCh:
				if interrupt.Owned() {
					continue
				}
				fmt.Fprintln(os.Stderr, "\nInterrupted again, exiting immediately.")
				os.Exit(exitcode.Interrupted)
			case <-done:
				return
			}
		}
	}()
	stop = sync.OnceFunc(func() {
		close(done)
		signal.Stop(sigCh)
		cancel()
	})
	return ctx, stop, got.Load
}

// usageError marks errors caused by how the command was invoked (bad flag,
// argument or flag combination); they exit with code 2.
type usageError struct{ error }

func (u usageError) Unwrap() error { return u.error }

// usageMessages are the error prefixes cobra uses for argument and flag
// validation that does not pass through the flag error func.
var usageMessages = []string{
	"unknown command",
	"unknown flag",
	"unknown shorthand flag",
	"required flag(s)",
	"if any flags in the group",
	"at least one of the flags in the group",
	"accepts ",
	"requires at least",
	"requires at most",
	"invalid argument",
	"flag needs an argument",
}

func isUsageError(err error) bool {
	var u usageError
	if errors.As(err, &u) {
		return true
	}
	msg := err.Error()
	for _, p := range usageMessages {
		if strings.HasPrefix(msg, p) {
			return true
		}
	}
	return false
}

// exitCodeFor prints err (root silences cobra's own printing so errors go to
// stderr exactly once, without the full usage dump) and picks the exit code.
func exitCodeFor(cmd *cobra.Command, err error, interrupted bool) int {
	if err == nil {
		if interrupted {
			return exitcode.Interrupted
		}
		return exitcode.OK
	}
	// Only our own exitcode.ExitError picks the code. A child process's
	// *exec.ExitError deep in the chain (a failed helper such as networksetup)
	// is an ordinary error here: printed, exit 1. `exec` wraps its child's
	// status in a silent ExitError itself.
	if code, ok := exitcode.Of(err); ok {
		if !exitcode.IsSilent(err) {
			fmt.Fprintln(os.Stderr, "Error:", err)
		}
		return code
	}
	if interrupted || errors.Is(err, context.Canceled) {
		fmt.Fprintln(os.Stderr, "Interrupted.")
		return exitcode.Interrupted
	}
	fmt.Fprintln(os.Stderr, "Error:", err)
	if isUsageError(err) {
		path := rootCmd.CommandPath()
		if cmd != nil {
			path = cmd.CommandPath()
		}
		fmt.Fprintf(os.Stderr, "Run '%s --help' for usage.\n", path)
		return exitcode.Usage
	}
	return exitcode.Error
}

func addSubcommandPalettes() {
	rootCmd.AddCommand(parse.ParseCmd)
	rootCmd.AddCommand(subs.SubsCmd)
	rootCmd.AddCommand(http.HttpCmd)
	rootCmd.AddCommand(net.NetCmd)
	rootCmd.AddCommand(cfscanner.CFscannerCmd)
	rootCmd.AddCommand(proxy.ProxyCmd)
	rootCmd.AddCommand(webui.WebUICmd)
	rootCmd.AddCommand(xkexec.ExecCmd)
	rootCmd.AddCommand(dbcmd.DBCmd)
	rootCmd.AddCommand(dpicmd.DPICmd)
}

// quietFlag applies --quiet as soon as it is parsed, so it takes effect
// before any command runs without needing a pre-run hook (which a
// subcommand's own hook would shadow).
type quietFlag struct{}

func (quietFlag) String() string { return strconv.FormatBool(customlog.Quiet()) }
func (quietFlag) Type() string   { return "bool" }
func (quietFlag) Set(v string) error {
	b, err := strconv.ParseBool(v)
	if err != nil {
		return err
	}
	customlog.SetQuiet(b)
	return nil
}

// resolveDBPath is how the database package finds the file on first use:
// the database is opened lazily, so commands that never query it (parse,
// completion, --help) never create or migrate it.
func resolveDBPath() (string, error) {
	return xkhome.DBPath(dbPathOverride)
}

func init() {
	database.SetPathResolver(resolveDBPath)
	database.SetCompletionPathResolver(func() (string, error) { return xkhome.DBPathNoCreate(dbPathOverride) })

	// Errors are printed once by Execute, to stderr; usage is only pointed at
	// (not dumped) and only for usage errors.
	rootCmd.SilenceErrors = true
	rootCmd.SilenceUsage = true

	rootCmd.Version = resolveVersion()

	// -v is verbose in every subcommand; keep the root consistent by putting
	// --version on -V rather than letting the same letter mean two things.
	rootCmd.Flags().BoolP("version", "V", false, "version for xray-knife")
	rootCmd.SetVersionTemplate("{{.Name}} {{.Version}}\n")

	quiet := rootCmd.PersistentFlags().VarPF(quietFlag{}, "quiet", "",
		"Only print warnings and errors (no progress bars or info logs); data on stdout is unaffected")
	quiet.NoOptDefVal = "true"

	rootCmd.PersistentFlags().StringVar(&dbPathOverride, "db", "",
		"Path to the xray-knife SQLite database (default: $XRAY_KNIFE_HOME/xray-knife.db, else ~/.xray-knife/xray-knife.db)")

	rootCmd.SetFlagErrorFunc(flagErrorFunc)

	addSubcommandPalettes()
}
