package cfscanner

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/lilendian0x00/xray-knife/v11/pkg/core/fragment"
	pkgscanner "github.com/lilendian0x00/xray-knife/v11/pkg/scanner"
	"github.com/lilendian0x00/xray-knife/v11/utils"
	"github.com/lilendian0x00/xray-knife/v11/utils/customlog"
	"github.com/lilendian0x00/xray-knife/v11/utils/exitcode"
	"github.com/spf13/cobra"
)

var (
	cliConfig pkgscanner.ScannerConfig

	// fragmentSpec and noiseSpecs are parsed into cliConfig.Fragment.
	fragmentSpec string
	noiseSpecs   []string
)

var CFscannerCmd = &cobra.Command{
	Use:   "cfscanner",
	Short: "Cloudflare's edge IP scanner with latency/speed tests and real-time resume.",
	Long: `Scans Cloudflare IP ranges to find optimal edge nodes. It supports latency testing,
speed testing, and can resume scans from previous results. The results are saved
in a CSV (or JSON/JSONL) file for easy analysis and reuse, checkpointed while the
scan runs, so an interrupted scan keeps its progress for --resume. You can provide
subnets directly, or pass a file containing one subnet per line.

Large ranges: every address is scanned by default, capped at --max-ips. Use
--sample-per-subnet N to test N random IPs per /24 (IPv4) or /48 (IPv6) instead,
which makes whole-provider and IPv6 scans practical.`,
	PreRunE: func(cmd *cobra.Command, args []string) error {
		return validateConfigLink(cliConfig.ConfigLink)
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg := cliConfig
		usage := func(err error) error { return exitcode.New(exitcode.Usage, err) }
		subnets, err := collectSubnets(cfg.Subnets)
		if err != nil {
			return usage(err)
		}
		cfg.Subnets = subnets

		if cfg.Port <= 0 || cfg.Port > 65535 {
			return usage(fmt.Errorf("invalid --port %d, must be 1..65535", cfg.Port))
		}
		if cfg.ThreadCount < 1 {
			return usage(fmt.Errorf("--threads must be at least 1, got %d", cfg.ThreadCount))
		}
		if cfg.MaxIPs == 0 {
			cfg.MaxIPs = -1 // the flag's 0 means "no cap"
		}
		if cfg.OutputFile, err = outputPath(cfg.OutputFile, cfg.OutputFormat); err != nil {
			return usage(err)
		}
		if cfg.Fragment, err = fragment.Build(fragmentSpec, noiseSpecs); err != nil {
			return usage(err)
		}
		if cfg.Fragment.Enabled() && cfg.ConfigLink == "" {
			return usage(fmt.Errorf("--fragment/--noise apply to the --config proxy's first hop; they need --config"))
		}
		// Runtime failures from here on are not usage mistakes.
		cmd.SilenceUsage = true

		if cfg.Port != 443 {
			customlog.Printf(customlog.Info, "Scanning on custom port %d (not 443).\n", cfg.Port)
		}

		service, err := pkgscanner.NewScannerService(cfg, log.New(os.Stderr, "", 0))
		if err != nil {
			return usage(fmt.Errorf("failed to create scanner: %w", err))
		}
		customlog.Printf(customlog.Processing, "Scanning up to %d IP(s) from %d subnet(s).\n", service.PlannedIPs(), len(subnets))

		// The root command cancels this context on the first Ctrl-C.
		ctx := cmd.Context()
		if ctx == nil {
			ctx = context.Background()
		}

		progressChan := make(chan *pkgscanner.ScanResult, cfg.ThreadCount)
		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			for res := range progressChan {
				switch {
				case res.Error != nil:
					if cfg.Verbose {
						customlog.Printf(customlog.Warning, "IP %s failed test: %v\n", res.IP, res.Error)
					}
				case res.SpeedErr != nil && !res.HasSpeed():
					if cfg.Verbose {
						customlog.Printf(customlog.Warning, "IP %s speed test failed: %v\n", res.IP, res.SpeedErr)
					}
				case res.HasSpeed():
					customlog.Printf(customlog.Success, "SPEEDTEST: %-20s | %-10v | %-15.2f | %-15.2f\n", res.IP, res.Latency.Round(time.Millisecond), res.DownSpeed, res.UpSpeed)
				default:
					customlog.Printf(customlog.Success, "LATENCY:   %-20s | %-10v %s\n", res.IP, res.Latency.Round(time.Millisecond), res.Colo)
				}
			}
		}()

		runErr := service.Run(ctx, progressChan)
		wg.Wait()

		printResultsToConsole(service.Results(), cfg.DoSpeedtest, cfg.OnlySpeedtestResults)

		switch {
		case runErr == nil:
			customlog.Printf(customlog.Success, "Scan finished. Final results saved to %s\n", cfg.OutputFile)
			return nil
		case errors.Is(runErr, context.Canceled):
			customlog.Printf(customlog.Warning, "Scan interrupted. Partial results saved to %s; rerun with --resume to continue.\n", cfg.OutputFile)
			return runErr // the root maps cancellation to exit code 130
		default:
			return fmt.Errorf("scan failed: %w", runErr)
		}
	},
}

// collectSubnets expands --subnets values (CIDRs, bare IPs, or files of
// them) and validates every entry, so a typo fails before scanning starts.
func collectSubnets(values []string) ([]string, error) {
	var all []string
	for _, arg := range values {
		arg = strings.TrimSpace(arg)
		if arg == "" {
			continue
		}
		if fileInfo, err := os.Stat(arg); err == nil && !fileInfo.IsDir() {
			lines, err := utils.ReadLinks(arg)
			if err != nil {
				return nil, fmt.Errorf("subnet file: %w", err)
			}
			all = append(all, lines...)
			continue
		}
		all = append(all, arg)
	}
	if len(all) == 0 {
		return nil, errors.New("no subnets found: provide a CIDR list or a file with one subnet per line to --subnets")
	}
	for i, s := range all {
		all[i] = utils.NormalizeCIDR(s)
	}
	if _, err := pkgscanner.ParsePrefixes(all); err != nil {
		return nil, err
	}
	return all, nil
}

// outputPath gives the output file the extension its format needs, so
// --resume can tell the format from the name.
func outputPath(path, format string) (string, error) {
	switch format {
	case "", "csv", "json", "jsonl":
	default:
		return "", fmt.Errorf("bad --type %q. Allowed: csv, json, jsonl", format)
	}
	if format == "" {
		format = "csv"
	}
	if path == "" || path == "-" {
		return path, nil
	}
	return strings.TrimSuffix(path, filepath.Ext(path)) + "." + format, nil
}

// validateConfigLink rejects a --config value that is not a proxy link. In v10
// the -c shorthand meant --speedtest-top, so a stale script passes an integer
// here; say so instead of failing later with an opaque parse error.
func validateConfigLink(link string) error {
	if link == "" || strings.Contains(link, "://") {
		return nil
	}
	return fmt.Errorf("--config expects a proxy link (e.g. vless://...), got %q\n"+
		"note: -c was --speedtest-top before v11; use --speedtest-top %s for the old behaviour", link, link)
}

func init() {
	f := CFscannerCmd.Flags()

	// Shorthands follow the canonical map in cmd/shorthands.go. Anything not
	// typed interactively week to week is long-only.
	f.StringSliceVarP(&cliConfig.Subnets, "subnets", "s", nil, "Subnet(s) or file containing subnets (e.g., \"1.1.1.1/24,2.2.2.2/16\")")
	f.IntVarP(&cliConfig.ThreadCount, "threads", "t", 100, "Count of threads for latency scan")
	f.StringVarP(&cliConfig.OutputFile, "out", "o", "results.csv", "Output file to save sorted results (in CSV format)")
	f.StringVarP(&cliConfig.ConfigLink, "config", "c", "", "Use a config link as a proxy to test IPs")
	f.IntVarP(&cliConfig.Port, "port", "p", 443, "TCP port to scan (Cloudflare also accepts 2053, 2083, 2087, 2096, 8443)")
	f.BoolVarP(&cliConfig.ShowTraceBody, "body", "b", false, "Show trace body output")
	f.BoolVarP(&cliConfig.Verbose, "verbose", "v", false, "Show verbose output with detailed errors")
	f.BoolVarP(&cliConfig.DoSpeedtest, "speedtest", "S", false, "Measure download/upload speed on the fastest IPs")

	// -e is deliberately left unbound in v11: it meant --shuffle-subnet in v10
	// and both flags are booleans, so rebinding it to --insecure would silently
	// change behaviour. It becomes --insecure in v12.
	f.BoolVar(&cliConfig.InsecureTLS, "insecure", false, "Allow insecure TLS connections for the proxy config")

	f.IntVar(&cliConfig.SpeedtestTop, "speedtest-top", 10, "Number of fastest IPs to select for speed testing (results are then ranked by download speed)")
	f.IntVar(&cliConfig.SpeedtestConcurrency, "speedtest-concurrency", 4, "Number of concurrent speed tests to run")
	f.IntVar(&cliConfig.SpeedtestTimeout, "speedtest-timeout", 30, "Measurement window in seconds for each speed test direction; a transfer cut short is measured on what moved")
	f.StringVar(&cliConfig.SpeedtestURL, "speedtest-url", "", "Speed test target: an https origin speaking Cloudflare's /__down and /__up, or a file URL to download (upload skipped). Default speed.cloudflare.com")
	f.IntVar(&cliConfig.RequestTimeout, "timeout", 5000, "Individual request timeout (in ms)")
	f.IntVar(&cliConfig.RetryCount, "retry", 1, "Number of times to retry TCP connection on failure")
	f.BoolVar(&cliConfig.OnlySpeedtestResults, "only-speedtest", false, "Only display results that have successful speedtest data")
	f.IntVar(&cliConfig.DownloadMB, "download-mb", 20, "Custom amount of data to download for speedtest (in MB, 0 skips download)")
	f.IntVar(&cliConfig.UploadMB, "upload-mb", 10, "Custom amount of data to upload for speedtest (in MB, 0 skips upload)")
	f.BoolVar(&cliConfig.ShuffleSubnets, "shuffle-subnet", false, "Shuffle list of Subnets")
	f.BoolVar(&cliConfig.ShuffleIPs, "shuffle-ip", false, "Shuffle list of IPs")
	f.BoolVar(&cliConfig.Resume, "resume", false, "Resume scan from previous results (file or DB)")
	f.BoolVar(&cliConfig.SaveToDB, "save-db", false, "Save scan results to the database")
	f.StringVar(&cliConfig.BindInterface, "bind", "", "Bind outbound dials to a specific OS interface (e.g. eth0). Linux: needs CAP_NET_RAW.")
	f.IntVar(&cliConfig.SamplePerSubnet, "sample-per-subnet", 0, "Test N random IPs from every /24 (IPv4) or /48 (IPv6) instead of every address (0 = all, at most 65536)")
	f.IntVar(&cliConfig.MaxIPs, "max-ips", pkgscanner.DefaultMaxIPs, "Stop after visiting this many IPs (0 = no cap)")
	f.StringVarP(&cliConfig.OutputFormat, "type", "x", "csv", "Output format: csv, json, jsonl (the --out extension follows it)")
	f.StringVar(&fragmentSpec, "fragment", "", "With --config: split the TLS ClientHello to evade SNI filtering, as packets,length[,interval] (e.g. tlshello,100-200,10-20)")
	f.StringArrayVar(&noiseSpecs, "noise", nil, "With --config (xray): send UDP noise before traffic, as type:packet[:delay] (e.g. rand:10-20:10-16). Repeatable")

	// --output was renamed to --out in v11 to match http and subs.
	f.StringVar(&cliConfig.OutputFile, "output", "results.csv", "Deprecated alias for --out")
	_ = f.MarkDeprecated("output", "use --out")

	_ = CFscannerCmd.MarkFlagRequired("subnets")
	_ = CFscannerCmd.RegisterFlagCompletionFunc("type", func(*cobra.Command, []string, string) ([]string, cobra.ShellCompDirective) {
		return []string{"csv", "json", "jsonl"}, cobra.ShellCompDirectiveNoFileComp
	})
}

func printResultsToConsole(results []*pkgscanner.ScanResult, doSpeedtest, onlySpeedtestResults bool) {
	var successfulResults, finalResults []*pkgscanner.ScanResult
	for _, r := range results {
		if r.Error == nil {
			successfulResults = append(successfulResults, r)
		}
	}

	if len(successfulResults) == 0 {
		customlog.Printf(customlog.Warning, "No successful IPs found to display.\n")
		return
	}

	if doSpeedtest && onlySpeedtestResults {
		for _, r := range successfulResults {
			if r.DownSpeed > 0 || r.UpSpeed > 0 {
				finalResults = append(finalResults, r)
			}
		}
	} else {
		finalResults = successfulResults
	}

	if len(finalResults) == 0 {
		customlog.Printf(customlog.Warning, "No results to display after filtering.\n")
		return
	}

	pkgscanner.SortResults(finalResults, doSpeedtest)

	var header string
	var outputLines []string
	if doSpeedtest {
		header = fmt.Sprintf("%-20s | %-10s | %-15s | %-15s", "IP", "Latency", "Downlink (Mbps)", "Uplink (Mbps)")
	} else {
		header = fmt.Sprintf("%-20s | %-10s", "IP", "Latency")
	}
	outputLines = append(outputLines, header)
	for _, result := range finalResults {
		outputLines = append(outputLines, formatResultLine(result, doSpeedtest))
	}
	customlog.Println(customlog.GetColor(customlog.None, "\n--- Sorted Results ---\n"))
	customlog.Println(customlog.GetColor(customlog.Success, strings.Join(outputLines, "\n")))
	customlog.Println(customlog.GetColor(customlog.None, "\n--------------------\n"))
}

func formatResultLine(result *pkgscanner.ScanResult, speedtestEnabled bool) string {
	if speedtestEnabled {
		return fmt.Sprintf("%-20s | %-10v | %-15.2f | %-15.2f", result.IP, result.Latency.Round(time.Millisecond), result.DownSpeed, result.UpSpeed)
	}
	return fmt.Sprintf("%-20s | %-10v", result.IP, result.Latency.Round(time.Millisecond))
}
