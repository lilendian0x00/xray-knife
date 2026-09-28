// Package dpi implements `xray-knife dpi`, which finds the fragmentation
// (and SNI) settings that get one known config past DPI on this network.
package dpi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"sync"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/lilendian0x00/xray-knife/v11/pkg/core"
	pkgdpi "github.com/lilendian0x00/xray-knife/v11/pkg/dpi"
	"github.com/lilendian0x00/xray-knife/v11/utils"
	"github.com/lilendian0x00/xray-knife/v11/utils/customlog"
	"github.com/lilendian0x00/xray-knife/v11/utils/exitcode"
)

// ErrNoWorkaround is returned (exit code 3) when no tried setting got
// through, so scripts can tell "nothing works" apart from a usage error.
var ErrNoWorkaround = exitcode.New(exitcode.NothingPassed, errors.New("no working setting found"))

// DPICmd groups the DPI tools.
var DPICmd = &cobra.Command{
	Use:   "dpi",
	Short: "Find fragmentation/SNI settings that get a config past DPI on this network",
	Long: `Tools for working around deep packet inspection.

"dpi scan" takes one config that should work (e.g. it works from another
network) and tests it on this network without changes, then with a series of
TLS fragmentation settings and optional SNI overrides. It reports which
settings get through, recommends the best one, and dials the server directly
to tell an IP/port block from SNI filtering.`,
	RunE: func(cmd *cobra.Command, _ []string) error {
		return cmd.Help()
	},
}

type scanConfig struct {
	link        string
	file        string
	core        string
	testURL     string
	timeoutMs   int
	attempts    int
	threads     int
	mode        string
	specs       []string
	snis        []string
	mixedCase   bool
	stopAfter   int
	insecure    bool
	bind        string
	verbose     bool
	out         string
	jsonOut     bool
	listPresets bool
}

func newScanCmd() *cobra.Command {
	cfg := &scanConfig{}
	cmd := &cobra.Command{
		Use:   "scan",
		Short: "Test a config with many fragment/SNI settings and recommend the best",
		Example: `  # Quick scan (baseline + ~11 fragment settings, 3 attempts each)
  xray-knife dpi scan -c "vless://..."

  # Whole grid, stop at the first 3 working settings
  xray-knife dpi scan -c "vless://..." --mode full --stop-after 3

  # Try your own settings and alternative SNIs
  xray-knife dpi scan -c "vless://..." --fragment tlshello,100-200,10-20 --fragment 1-3,1-5,1-2 --sni www.speedtest.net

  # Use the result
  xray-knife http -c "vless://..." --fragment tlshello,100-200,10-20`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if cfg.listPresets {
				return printPresets(cmd.OutOrStdout(), cfg.mode)
			}
			return runScan(cmd, cfg)
		},
	}
	f := cmd.Flags()
	f.StringVarP(&cfg.link, "config", "c", "", "The config link to test")
	f.StringVarP(&cfg.file, "file", "f", "", "Read config links from a file (\"-\" = stdin); each is scanned in turn")
	f.StringVarP(&cfg.core, "core", "z", "auto", "Core type (auto, xray, singbox). sing-box only supports on/off fragmentation")
	f.StringVarP(&cfg.testURL, "url", "u", pkgdpi.DefaultTestURL, "URL fetched through the proxy on each attempt")
	f.IntVar(&cfg.timeoutMs, "timeout", 8000, "Timeout per attempt in ms")
	f.IntVar(&cfg.attempts, "attempts", 3, "Attempts per setting (DPI often lets the first handshake through)")
	f.IntVarP(&cfg.threads, "threads", "t", 4, "Settings tested at once (keep low: bursts can trigger rate-based blocking)")
	f.StringVar(&cfg.mode, "mode", "quick", "Built-in candidates: quick (~11 settings) or full (72-setting grid)")
	f.StringArrayVar(&cfg.specs, "fragment", nil, "Try this fragment setting instead of the built-ins (packets,length[,interval]); repeatable")
	f.StringArrayVar(&cfg.snis, "sni", nil, "Also try this SNI with every setting; repeatable")
	f.BoolVar(&cfg.mixedCase, "mixed-case-sni", false, "Also try the link's SNI in mixed case (beats byte-exact SNI filters)")
	f.IntVar(&cfg.stopAfter, "stop-after", 0, "Stop once this many settings pass (0 = test all)")
	f.BoolVarP(&cfg.insecure, "insecure", "e", false, "Allow insecure TLS in the cores")
	f.StringVar(&cfg.bind, "bind", "", "Bind all dials to an OS interface (e.g. eth0)")
	f.BoolVarP(&cfg.verbose, "verbose", "v", false, "Show core logs")
	f.StringVarP(&cfg.out, "out", "o", "", "Also write the full report as JSON to this file")
	f.BoolVarP(&cfg.jsonOut, "json", "j", false, "Print the report as JSON instead of a table")
	f.BoolVar(&cfg.listPresets, "list", false, "List the built-in settings for --mode and exit")
	_ = cmd.RegisterFlagCompletionFunc("core", func(*cobra.Command, []string, string) ([]string, cobra.ShellCompDirective) {
		return []string{"auto", "xray", "singbox"}, cobra.ShellCompDirectiveNoFileComp
	})
	_ = cmd.RegisterFlagCompletionFunc("mode", func(*cobra.Command, []string, string) ([]string, cobra.ShellCompDirective) {
		return []string{"quick", "full"}, cobra.ShellCompDirectiveNoFileComp
	})
	return cmd
}

func init() {
	DPICmd.AddCommand(newScanCmd())
}

func parseCore(s string) (core.CoreType, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "auto":
		return core.AutoCoreType, nil
	case "xray":
		return core.XrayCoreType, nil
	case "singbox", "sing-box":
		return core.SingboxCoreType, nil
	}
	return 0, fmt.Errorf("unknown core %q (want auto, xray or singbox)", s)
}

func printPresets(w io.Writer, modeStr string) error {
	mode, err := pkgdpi.ParseMode(modeStr)
	if err != nil {
		return err
	}
	for _, s := range pkgdpi.Specs(mode) {
		fmt.Fprintln(w, s)
	}
	return nil
}

func runScan(cmd *cobra.Command, cfg *scanConfig) error {
	coreType, err := parseCore(cfg.core)
	if err != nil {
		return exitcode.New(exitcode.Usage, err)
	}
	mode, err := pkgdpi.ParseMode(cfg.mode)
	if err != nil {
		return exitcode.New(exitcode.Usage, err)
	}
	if cfg.timeoutMs <= 0 {
		return exitcode.New(exitcode.Usage, errors.New("--timeout must be positive"))
	}
	if cfg.attempts < 1 || cfg.threads < 1 {
		return exitcode.New(exitcode.Usage, errors.New("--attempts and --threads must be at least 1"))
	}

	var links []string
	switch {
	case cfg.link != "" && cfg.file != "":
		return exitcode.New(exitcode.Usage, errors.New("use either --config or --file, not both"))
	case cfg.link != "":
		links = []string{strings.TrimSpace(cfg.link)}
	case cfg.file != "":
		if links, err = utils.ReadLinks(cfg.file); err != nil {
			return err
		}
	default:
		return exitcode.New(exitcode.Usage, errors.New("no config given: use -c <link> or -f <file>"))
	}

	// Root cancels this context on the first Ctrl-C (and exits on the second).
	ctx := cmd.Context()
	if ctx == nil {
		ctx = context.Background()
	}

	stdout := cmd.OutOrStdout()
	stderr := cmd.ErrOrStderr()
	var reports []*pkgdpi.Report
	anyWorking := false
	for i, link := range links {
		if ctx.Err() != nil {
			break
		}
		if len(links) > 1 {
			fmt.Fprintf(stderr, "\n== [%d/%d] %s\n", i+1, len(links), shorten(link, 80))
		}
		rep, err := scanOne(ctx, cfg, link, coreType, mode, stderr)
		if err != nil {
			if len(links) == 1 {
				return err
			}
			customlog.Printf(customlog.Failure, "%v\n", err)
			continue
		}
		reports = append(reports, rep)
		if rep.Best != nil && rep.Best.Status == pkgdpi.StatusPass {
			anyWorking = true
		}
		if !cfg.jsonOut {
			printReport(stdout, rep)
		}
	}

	if cfg.jsonOut {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		var v any = reports
		if len(reports) == 1 {
			v = reports[0]
		}
		if err := enc.Encode(v); err != nil {
			return err
		}
	}
	if cfg.out != "" {
		b, err := json.MarshalIndent(reports, "", "  ")
		if err != nil {
			return err
		}
		if err := os.WriteFile(cfg.out, append(b, '\n'), 0o644); err != nil {
			return fmt.Errorf("writing report: %w", err)
		}
		customlog.Printf(customlog.Success, "Report written to %s\n", cfg.out)
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if !anyWorking {
		return ErrNoWorkaround
	}
	return nil
}

func scanOne(ctx context.Context, cfg *scanConfig, link string, coreType core.CoreType, mode pkgdpi.Mode, progress io.Writer) (*pkgdpi.Report, error) {
	var (
		mu    sync.Mutex
		total int
		done  int
	)
	opts := pkgdpi.Options{
		Link:          link,
		CoreType:      coreType,
		TestURL:       cfg.testURL,
		Timeout:       time.Duration(cfg.timeoutMs) * time.Millisecond,
		Attempts:      cfg.attempts,
		Threads:       cfg.threads,
		Mode:          mode,
		Specs:         cfg.specs,
		SNIs:          cfg.snis,
		MixedCaseSNI:  cfg.mixedCase,
		StopAfter:     cfg.stopAfter,
		Insecure:      cfg.insecure,
		BindInterface: cfg.bind,
		Verbose:       cfg.verbose,
		OnStart: func(ps []pkgdpi.Profile) {
			mu.Lock()
			total = len(ps)
			mu.Unlock()
			fmt.Fprintf(progress, "Testing %d settings × %d attempts (timeout %dms each)...\n", len(ps), cfg.attempts, cfg.timeoutMs)
		},
		OnResult: func(r pkgdpi.Result) {
			mu.Lock()
			done++
			n, t := done, total
			mu.Unlock()
			if r.Status == pkgdpi.StatusSkipped {
				return
			}
			fmt.Fprintf(progress, "  [%*d/%d] %-34s %s\n", len(fmt.Sprint(t)), n, t, shorten(r.Profile.Label(), 34), statusText(r))
		},
	}
	return pkgdpi.Run(ctx, opts)
}

func statusText(r pkgdpi.Result) string {
	switch r.Status {
	case pkgdpi.StatusPass, pkgdpi.StatusPartial:
		s := fmt.Sprintf("%s %d/%d  median %dms", r.Status, r.Successes, r.Attempts, r.MedianDelay)
		if r.Status == pkgdpi.StatusPass {
			return customlog.GetColor(customlog.Success, s)
		}
		return customlog.GetColor(customlog.Warning, s)
	case pkgdpi.StatusError:
		return customlog.GetColor(customlog.Failure, "error: "+shorten(r.LastError, 60))
	default:
		return customlog.GetColor(customlog.Failure, fmt.Sprintf("%s 0/%d  %s", r.Status, r.Attempts, failureSummary(r)))
	}
}

func failureSummary(r pkgdpi.Result) string {
	if len(r.Failures) == 0 {
		return ""
	}
	kinds := make([]string, 0, len(r.Failures))
	for k := range r.Failures {
		kinds = append(kinds, k)
	}
	sort.Strings(kinds)
	parts := make([]string, 0, len(kinds))
	for _, k := range kinds {
		parts = append(parts, fmt.Sprintf("%s×%d", k, r.Failures[k]))
	}
	return strings.Join(parts, " ")
}

func printReport(w io.Writer, rep *pkgdpi.Report) {
	fmt.Fprintf(w, "\nConfig:   %s (%s core)\n", rep.Protocol, rep.Core)
	d := rep.Direct
	switch {
	case d.Transport == "udp":
		fmt.Fprintf(w, "Direct:   %s (UDP, not checked)\n", d.Address)
	case !d.Checked:
		fmt.Fprintf(w, "Direct:   not checked\n")
	case !d.TCPOK:
		fmt.Fprintf(w, "Direct:   %s TCP %s\n", d.Address, customlog.GetColor(customlog.Failure, "FAILED ("+d.TCPError+")"))
	default:
		line := fmt.Sprintf("Direct:   %s TCP ok %dms", d.Address, d.TCPDelay)
		if d.TLSChecked {
			if d.TLSOK {
				line += fmt.Sprintf(", TLS (sni %s) ok %dms", d.SNI, d.TLSDelay)
			} else {
				line += fmt.Sprintf(", TLS (sni %s) %s", d.SNI, customlog.GetColor(customlog.Failure, "FAILED ("+d.TLSKind+")"))
			}
		}
		fmt.Fprintln(w, line)
	}

	ranked := make([]pkgdpi.Result, 0, len(rep.Results))
	for _, r := range rep.Results {
		if r.Status != pkgdpi.StatusSkipped {
			ranked = append(ranked, r)
		}
	}
	sort.SliceStable(ranked, func(i, j int) bool {
		a, b := ranked[i], ranked[j]
		if a.SuccessRate() != b.SuccessRate() {
			return a.SuccessRate() > b.SuccessRate()
		}
		if a.MedianDelay != b.MedianDelay {
			if a.MedianDelay < 0 {
				return false
			}
			if b.MedianDelay < 0 {
				return true
			}
			return a.MedianDelay < b.MedianDelay
		}
		return a.Index < b.Index
	})

	fmt.Fprintln(w)
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "SETTING\tSNI\tSTATUS\tOK\tMEDIAN\tMIN\tFAILURES")
	for _, r := range ranked {
		sni := r.Profile.SNI
		if sni == "" {
			sni = "-"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%d/%d\t%s\t%s\t%s\n",
			r.Profile.Name, sni, r.Status, r.Successes, r.Attempts, ms(r.MedianDelay), ms(r.MinDelay), failureOrError(r))
	}
	_ = tw.Flush()

	fmt.Fprintf(w, "\nVerdict:  %s\n", verdictText(rep.Verdict))
	fmt.Fprintf(w, "          %s\n", rep.Advice)
	if b := rep.Best; b != nil && b.Status == pkgdpi.StatusPass && (b.Profile.Fragment != nil || b.Profile.SNI != "") {
		if flags := b.Profile.Flags(); flags != "" {
			fmt.Fprintf(w, "\nUse it:   %s", flags)
			if b.Profile.SNI != "" {
				fmt.Fprintf(w, "   (and set sni=%s in the link)", b.Profile.SNI)
			}
			fmt.Fprintln(w)
		} else {
			fmt.Fprintf(w, "\nUse it:   set sni=%s in the link\n", b.Profile.SNI)
		}
		if f := b.Profile.Fragment; f.FragmentsTCP() {
			fmt.Fprintf(w, "xray/v2rayN JSON: \"fragment\": {\"packets\": %q, \"length\": %q, \"interval\": %q}\n",
				f.Packets, f.Length.String(), f.Interval.String())
		}
	}
	fmt.Fprintf(w, "Took:     %s\n", rep.Duration.Round(100*time.Millisecond))
}

func verdictText(v string) string {
	switch v {
	case pkgdpi.VerdictNoInterference, pkgdpi.VerdictFragmentHelps:
		return customlog.GetColor(customlog.Success, v)
	case pkgdpi.VerdictPartial:
		return customlog.GetColor(customlog.Warning, v)
	}
	return customlog.GetColor(customlog.Failure, v)
}

func failureOrError(r pkgdpi.Result) string {
	if r.Status == pkgdpi.StatusError {
		return shorten(r.LastError, 50)
	}
	return failureSummary(r)
}

func ms(v int64) string {
	if v < 0 {
		return "-"
	}
	return fmt.Sprintf("%dms", v)
}

func shorten(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}
