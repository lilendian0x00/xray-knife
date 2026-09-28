package subs

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/lilendian0x00/xray-knife/v11/database"
	"github.com/lilendian0x00/xray-knife/v11/pkg/convert"
	"github.com/lilendian0x00/xray-knife/v11/utils"
	"github.com/lilendian0x00/xray-knife/v11/utils/customlog"
	"github.com/lilendian0x00/xray-knife/v11/utils/exitcode"
	"github.com/spf13/cobra"
)

// exportFormats are the --format values, in help order.
var exportFormats = []string{"base64", "plain", "clash", "singbox", "xray"}

type exportConfig struct {
	subIDs   []int64
	all      bool
	file     string
	protocol string
	status   string
	limit    int
	format   string
	out      string

	mixedPort    int
	listenAddr   string
	selectGroup  string
	autoGroup    string
	testURL      string
	testInterval time.Duration
	tolerance    int
	insecure     bool
}

// ExportCmd writes stored (optionally tested) configs as a subscription or a
// client config.
var ExportCmd = newExportCommand()

func newExportCommand() *cobra.Command {
	cfg := &exportConfig{}
	cmd := &cobra.Command{
		Use:   "export",
		Short: "Export configs as a subscription (base64/plain) or a Clash, sing-box or xray config",
		Long: `Writes configs as something a client can load: a base64 or plain
subscription (v2rayN, v2rayNG, Hiddify, Shadowrocket...), Clash/mihomo YAML,
a sing-box client config, or an xray config.

Sources (pick one):
  --sub-id N   configs of these subscriptions (repeatable; disabled ones too)
  --all        configs of every enabled subscription
  -f FILE      links from a file ("-" = stdin)

Filters:
  --status passed        only configs whose latest http test passed
  --status semi-passed   passed or semi-passed
                         (needs results saved with 'http --save-db'; with a
                         status filter the output is ordered fastest first)
  --protocol P, --limit N

Links a format cannot express (e.g. xhttp for sing-box, TUIC for xray,
MTProto for anything structured) are skipped and listed on stderr. When
nothing can be exported the command exits with code 3.

Examples:
  # Publish a tested subscription: test, keep the passed ones as Clash YAML
  xray-knife http --from-db --sub-id 1 --save-db
  xray-knife subs export --sub-id 1 --status passed --format clash -o best.yaml

  # base64 subscription of the 50 fastest passed configs of all subscriptions
  xray-knife subs export --all --status passed --limit 50 -o sub.txt

  # sing-box client config listening on 127.0.0.1:2080
  xray-knife subs export -f valid.txt --format singbox -o config.json`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runExport(cmd, cfg)
		},
	}
	f := cmd.Flags()
	f.Int64SliceVar(&cfg.subIDs, "sub-id", nil, "Export the configs of this subscription (repeatable, or comma-separated)")
	_ = cmd.RegisterFlagCompletionFunc("sub-id", completeSubscriptionIDs)
	f.BoolVar(&cfg.all, "all", false, "Export the configs of every enabled subscription")
	f.StringVarP(&cfg.file, "file", "f", "", `Export links from a file ("-" reads stdin)`)
	cmd.MarkFlagsMutuallyExclusive("sub-id", "all", "file")

	f.StringVar(&cfg.status, "status", "", "Only configs whose latest http test result is passed, or semi-passed (passed or semi-passed)")
	_ = cmd.RegisterFlagCompletionFunc("status", cobra.FixedCompletions([]string{"passed", "semi-passed"}, cobra.ShellCompDirectiveNoFileComp))
	f.StringVar(&cfg.protocol, "protocol", "", "Only configs of this protocol (database sources)")
	_ = cmd.RegisterFlagCompletionFunc("protocol", completeProtocols)
	f.IntVarP(&cfg.limit, "limit", "l", 0, "Export at most this many configs (0 = all)")

	f.StringVar(&cfg.format, "format", "base64", "Output format: "+strings.Join(exportFormats, ", "))
	_ = cmd.RegisterFlagCompletionFunc("format", cobra.FixedCompletions(exportFormats, cobra.ShellCompDirectiveNoFileComp))
	f.StringVarP(&cfg.out, "out", "o", "-", `Output file ("-" writes stdout)`)

	f.IntVar(&cfg.mixedPort, "mixed-port", 0, "clash/singbox: local HTTP+SOCKS port (default 7890 for clash, 2080 for singbox)")
	f.StringVar(&cfg.listenAddr, "listen", "", "singbox: mixed inbound address (default 127.0.0.1)")
	f.StringVar(&cfg.selectGroup, "select-group", "", `clash/singbox: name of the manual select group (default "PROXY" for clash, "proxy" for singbox)`)
	f.StringVar(&cfg.autoGroup, "auto-group", "", `clash/singbox: name of the url-test group (default "auto")`)
	f.StringVar(&cfg.testURL, "test-url", "", "clash/singbox: url-test probe URL (default https://www.gstatic.com/generate_204)")
	f.DurationVar(&cfg.testInterval, "test-interval", 0, "clash/singbox: url-test interval (default 5m)")
	f.IntVar(&cfg.tolerance, "tolerance", 0, "clash: url-test tolerance in ms (default 50)")
	f.BoolVarP(&cfg.insecure, "insecure", "e", false, "singbox: skip certificate verification on every TLS outbound")
	return cmd
}

func runExport(cmd *cobra.Command, cfg *exportConfig) error {
	cfg.format = strings.ToLower(strings.TrimSpace(cfg.format))
	if !containsString(exportFormats, cfg.format) {
		return usageErr(fmt.Sprintf("unknown --format %q (want %s)", cfg.format, strings.Join(exportFormats, ", ")))
	}
	if !database.ValidExportStatus(cfg.status) {
		return usageErr(fmt.Sprintf("unknown --status %q (want passed or semi-passed)", cfg.status))
	}
	if len(cfg.subIDs) == 0 && !cfg.all && cfg.file == "" {
		return usageErr("pick what to export: --sub-id N, --all or -f FILE")
	}
	if cfg.limit < 0 || cfg.mixedPort < 0 || cfg.mixedPort > 65535 || cfg.testInterval < 0 || cfg.tolerance < 0 {
		return usageErr("--limit, --mixed-port, --test-interval and --tolerance must not be negative (and the port at most 65535)")
	}
	for _, id := range cfg.subIDs {
		if id <= 0 {
			return usageErr(fmt.Sprintf("invalid --sub-id %d", id))
		}
	}

	links, err := selectExportLinks(cfg)
	if err != nil {
		return err
	}
	if len(links) == 0 {
		what := "no configs match"
		if cfg.status != "" {
			what += fmt.Sprintf(" (--status %s needs results saved by 'xray-knife http --save-db')", cfg.status)
		}
		return exitcode.New(exitcode.NothingPassed, errors.New(what))
	}

	data, report, err := render(cfg, links)
	if report != nil {
		printExportReport(report, cfg.format)
	}
	if errors.Is(err, convert.ErrNothingToExport) {
		return exitcode.New(exitcode.NothingPassed, fmt.Errorf("none of the %d configs can be exported as %s", len(links), cfg.format))
	}
	if err != nil {
		return err
	}

	if err := writeExport(cfg.out, data); err != nil {
		return err
	}
	exported := len(links)
	if report != nil {
		exported = report.Converted
	}
	if cfg.out != "-" {
		customlog.Printf(customlog.Success, "Exported %d config(s) as %s to %s\n", exported, cfg.format, cfg.out)
	}
	return nil
}

// selectExportLinks resolves the source and filters to a list of links.
func selectExportLinks(cfg *exportConfig) ([]string, error) {
	var rows []database.ExportedConfig
	if cfg.file != "" {
		fileLinks, err := utils.ReadLinks(cfg.file)
		if err != nil {
			return nil, err
		}
		fileLinks = uniqueStrings(fileLinks)
		if cfg.protocol != "" {
			customlog.Printf(customlog.Warning, "--protocol only filters database sources; ignored for -f\n")
		}
		if cfg.status == "" {
			if cfg.limit > 0 && len(fileLinks) > cfg.limit {
				fileLinks = fileLinks[:cfg.limit]
			}
			return fileLinks, nil
		}
		looked, err := database.LatestHttpResults(fileLinks)
		if err != nil {
			return nil, err
		}
		if rows, err = database.FilterExport(looked, cfg.status, cfg.limit); err != nil {
			return nil, err
		}
	} else {
		var err error
		rows, err = database.ConfigsForExport(database.ExportFilter{
			SubscriptionIDs: cfg.subIDs,
			Protocol:        cfg.protocol,
			Status:          cfg.status,
			Limit:           cfg.limit,
		})
		if err != nil {
			return nil, err
		}
	}
	out := make([]string, len(rows))
	for i, r := range rows {
		out[i] = r.Link
	}
	return out, nil
}

func render(cfg *exportConfig, links []string) ([]byte, *convert.Report, error) {
	switch cfg.format {
	case "plain":
		return convert.ToPlain(links), nil, nil
	case "base64":
		return convert.ToBase64(links), nil, nil
	case "clash":
		return convert.ToClash(links, convert.ClashOptions{
			MixedPort:     cfg.mixedPort,
			SelectGroup:   cfg.selectGroup,
			AutoGroup:     cfg.autoGroup,
			TestURL:       cfg.testURL,
			TestInterval:  int(cfg.testInterval / time.Second),
			TestTolerance: cfg.tolerance,
		})
	case "singbox":
		return convert.ToSingbox(links, convert.SingboxOptions{
			ListenAddress: cfg.listenAddr,
			ListenPort:    uint16(cfg.mixedPort),
			SelectTag:     cfg.selectGroup,
			AutoTag:       cfg.autoGroup,
			TestURL:       cfg.testURL,
			TestInterval:  cfg.testInterval,
			InsecureTLS:   cfg.insecure,
		})
	case "xray":
		return convert.ToXray(links)
	}
	return nil, nil, fmt.Errorf("unknown format %q", cfg.format)
}

// printExportReport lists skipped links on stderr, grouped by reason.
func printExportReport(r *convert.Report, format string) {
	if len(r.Skipped) == 0 {
		return
	}
	counts := map[string]int{}
	examples := map[string]string{}
	for _, s := range r.Skipped {
		counts[s.Reason]++
		if examples[s.Reason] == "" && s.Name != "" {
			examples[s.Reason] = s.Name
		}
	}
	reasons := make([]string, 0, len(counts))
	for reason := range counts {
		reasons = append(reasons, reason)
	}
	sort.Slice(reasons, func(i, j int) bool {
		if counts[reasons[i]] != counts[reasons[j]] {
			return counts[reasons[i]] > counts[reasons[j]]
		}
		return reasons[i] < reasons[j]
	})
	customlog.Printf(customlog.Warning, "%s: exported %d, skipped %d:\n", format, r.Converted, len(r.Skipped))
	for _, reason := range reasons {
		line := fmt.Sprintf("  %d × %s", counts[reason], reason)
		if ex := examples[reason]; ex != "" {
			line += fmt.Sprintf(" (e.g. %q)", ex)
		}
		fmt.Fprintln(os.Stderr, line)
	}
}

// writeExport writes data to path ("-" = stdout) via a temporary file and
// rename, so a reader of a published file never sees it half-written. An
// existing file keeps its mode (e.g. one made world-readable on purpose to
// be served); a new one is 0600, since exports carry credentials.
func writeExport(path string, data []byte) error {
	if path == "-" || path == "" {
		_, err := os.Stdout.Write(data)
		if err == nil && len(data) > 0 && data[len(data)-1] != '\n' {
			_, err = os.Stdout.Write([]byte("\n"))
		}
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("could not write %s: %w", path, err)
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return fmt.Errorf("could not write %s: %w", path, err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmp.Name())
		return err
	}
	mode := os.FileMode(0o600)
	if info, err := os.Stat(path); err == nil {
		mode = info.Mode().Perm()
	}
	if err := os.Chmod(tmp.Name(), mode); err != nil {
		os.Remove(tmp.Name())
		return err
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		os.Remove(tmp.Name())
		return fmt.Errorf("could not write %s: %w", path, err)
	}
	return nil
}

func containsString(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

func uniqueStrings(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := in[:0:0]
	for _, s := range in {
		if _, dup := seen[s]; dup {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}
