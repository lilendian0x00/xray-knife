package subs

import (
	"context"
	"database/sql"
	"fmt"
	"math"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/alitto/pond/v2"
	"github.com/lilendian0x00/xray-knife/v11/database"
	"github.com/lilendian0x00/xray-knife/v11/pkg/core"
	"github.com/lilendian0x00/xray-knife/v11/pkg/subscription"
	"github.com/lilendian0x00/xray-knife/v11/utils"
	"github.com/lilendian0x00/xray-knife/v11/utils/customlog"

	"github.com/spf13/cobra"
)

// FetchConfig holds the configuration for the fetch command
type FetchConfig struct {
	SubscriptionID  int64
	SubscriptionURL string
	UserAgent       string
	OutputFile      string
	Proxy           string
	FetchAll        bool
	FileInput       string
	Workers         int
	MaxBytes        int64
	MaxLinks        int
	Timeout         time.Duration
}

// FetchCommand holds state for the fetch subcommand.
type FetchCommand struct {
	config *FetchConfig
	core   core.Core
}

// NewFetchCommand builds the cobra command for fetching subscription configs.
func NewFetchCommand() *cobra.Command {
	fc := &FetchCommand{
		config: &FetchConfig{},
		core:   core.NewAutomaticCore(false, false), // For parsing remarks/protocols
	}
	return fc.createCommand()
}

func (fc *FetchCommand) createCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "fetch",
		Short: "Fetches configs from a subscription and saves them to the DB and a file.",
		Long: `Fetches proxy configurations from one or more subscription sources.

Supports multiple input modes:
  --sub-id <N>   Fetch from a subscription stored in the DB by its ID.
  --url <URL>    One-off fetch from a URL (configs saved to DB but not linked to a subscription).
  --all          Fetch from all enabled subscriptions in the DB.
  --file <PATH>  Read subscription URLs from a file (one per line, "-" for stdin,
                 # comments allowed) and fetch each concurrently.

Use --workers to control concurrency for --file and --all modes (default: 3).
Fetched configs are parsed, deduplicated, and upserted into the local database.
Each config remembers every subscription that returned it (after upgrading an
older database, run 'subs fetch --all' once so shared links know all their
sources).
Fetched configs are also written to a file (default: configs.txt); pass --out "" to disable,
or --out - to print them to stdout. Links several sources return are written once.

Examples:
  xray-knife subs fetch --sub-id 1
  xray-knife subs fetch --url "https://example.com/sub"
  xray-knife subs fetch --all
  xray-knife subs fetch --file urls.txt --workers 5
  xray-knife subs fetch --file urls.txt --out configs.txt`,
		RunE:         fc.runCommand,
		PreRunE:      fc.validateFlags,
		SilenceUsage: true,
	}
	fc.addFlags(cmd)
	return cmd
}

func (fc *FetchCommand) addFlags(cmd *cobra.Command) {
	flags := cmd.Flags()
	bindSubscriptionIDFlags(cmd, &fc.config.SubscriptionID, "The ID of the subscription from the DB")
	flags.StringVarP(&fc.config.SubscriptionURL, "url", "u", "", "A one-off subscription URL to fetch from")
	flags.StringVar(&fc.config.UserAgent, "user-agent", "", "Custom User-agent to be used (overrides DB value)")
	flags.StringVar(&fc.config.UserAgent, "useragent", "", "Deprecated alias for --user-agent")
	_ = flags.MarkDeprecated("useragent", "use --user-agent")
	flags.StringVarP(&fc.config.OutputFile, "out", "o", "configs.txt", "Output file for fetched configs (pass an empty string to disable)")
	flags.StringVar(&fc.config.Proxy, "proxy", "", "Proxy to use for fetching the subscription")
	flags.BoolVar(&fc.config.FetchAll, "all", false, "Fetch from all enabled subscriptions in the DB")
	flags.StringVarP(&fc.config.FileInput, "file", "f", "", "File containing subscription URLs (one per line)")
	flags.IntVarP(&fc.config.Workers, "workers", "w", 3, "Number of concurrent workers for --file and --all modes")

	flags.Int64Var(&fc.config.MaxBytes, "max-bytes", subscription.DefaultMaxBytes, "Maximum response bytes per subscription")
	flags.IntVar(&fc.config.MaxLinks, "max-links", subscription.DefaultMaxLinks, "Maximum links per subscription")
	flags.DurationVar(&fc.config.Timeout, "fetch-timeout", subscription.DefaultTimeout, "Overall timeout for each subscription fetch")

	cmd.MarkFlagsMutuallyExclusive("sub-id", "id", "url", "all", "file")
}

func (fc *FetchCommand) validateFlags(cmd *cobra.Command, args []string) error {
	if fc.config.SubscriptionID == 0 && fc.config.SubscriptionURL == "" && !fc.config.FetchAll && fc.config.FileInput == "" {
		return usageErr("one of --sub-id, --url, --all, or --file must be provided")
	}
	if fc.config.SubscriptionURL != "" {
		if err := validateSubscriptionURL(fc.config.SubscriptionURL); err != nil {
			return usageErr(err.Error())
		}
	}
	if fc.config.MaxBytes <= 0 || fc.config.MaxBytes == math.MaxInt64 || fc.config.MaxLinks <= 0 || fc.config.Timeout <= 0 {
		return fmt.Errorf("--max-bytes, --max-links, and --fetch-timeout must be positive and within supported limits")
	}
	if fc.config.Workers < 1 {
		return fmt.Errorf("--workers must be at least 1, got %d", fc.config.Workers)
	}
	if fc.config.Workers > 20 {
		return fmt.Errorf("--workers must be at most 20, got %d", fc.config.Workers)
	}
	return nil
}

// runCommand executes the fetch command logic
func (fc *FetchCommand) runCommand(cmd *cobra.Command, args []string) error {
	if fc.config.FetchAll {
		return fc.fetchAllSubscriptions(cmd.Context())
	}
	if fc.config.FileInput != "" {
		return fc.fetchFromFile(cmd.Context())
	}
	return fc.fetchSingle(cmd.Context())
}

// fetchSingle handles --id and --url modes (no concurrency needed)
func (fc *FetchCommand) fetchSingle(ctx context.Context) error {
	var subToFetch Subscription
	var subscriptionID sql.NullInt64

	if fc.config.SubscriptionID != 0 {
		dbSub, err := database.GetSubscriptionByID(fc.config.SubscriptionID)
		if err != nil {
			return err
		}
		subToFetch.Url = dbSub.URL
		subToFetch.UserAgent = dbSub.UserAgent.String
		subscriptionID = sql.NullInt64{Int64: dbSub.ID, Valid: true}
		customlog.Printf(customlog.Processing, "Fetching from DB subscription ID %d: %s\n", dbSub.ID, dbSub.URL)
	} else {
		subToFetch.Url = fc.config.SubscriptionURL
		subscriptionID.Valid = false // One-off fetch, not linked to a subscription
		customlog.Printf(customlog.Processing, "Fetching from URL: %s\n", subToFetch.Url)
	}

	if fc.config.UserAgent != "" {
		subToFetch.UserAgent = fc.config.UserAgent
	}
	subToFetch.Proxy = fc.config.Proxy

	return fc.doFetch(ctx, &subToFetch, subscriptionID)
}

// fetchAllSubscriptions handles --all mode with concurrency
func (fc *FetchCommand) fetchAllSubscriptions(ctx context.Context) error {
	subs, err := database.ListSubscriptions()
	if err != nil {
		return err
	}

	// Filter to enabled subscriptions only
	var enabled []database.Subscription
	for _, sub := range subs {
		if sub.Enabled {
			enabled = append(enabled, sub)
		}
	}

	if len(enabled) == 0 {
		customlog.Printf(customlog.Warning, "No enabled subscriptions found in the database.\n")
		return nil
	}

	workers := fc.config.Workers
	if workers > len(enabled) {
		workers = len(enabled)
	}

	customlog.Printf(customlog.Processing, "Fetching from %d enabled subscription(s) with %d worker(s)...\n", len(enabled), workers)

	pool := pond.NewPool(workers)
	defer pool.StopAndWait()

	var (
		mu          sync.Mutex
		allConfigs  []database.SubscriptionConfig
		totalRaw    int
		failedCount int32
		doneCount   int32
	)

	for _, sub := range enabled {
		sub := sub // capture loop variable
		pool.Submit(func() {
			remark := fmt.Sprintf("#%d", sub.ID)
			if sub.Remark.Valid && sub.Remark.String != "" {
				remark = sub.Remark.String
			}

			idx := atomic.AddInt32(&doneCount, 1)
			customlog.Printf(customlog.Processing, "[%d/%d] Fetching %q (%s)\n", idx, len(enabled), remark, sub.URL)

			subToFetch := Subscription{
				Remark:    remark,
				Url:       sub.URL,
				UserAgent: sub.UserAgent.String,
				Proxy:     fc.config.Proxy,
			}
			if fc.config.UserAgent != "" {
				subToFetch.UserAgent = fc.config.UserAgent
			}

			rawLinks, fetchErr := fc.fetchSource(ctx, &subToFetch)
			if fetchErr != nil {
				customlog.Printf(customlog.Failure, "Failed to fetch subscription %d (%s): %v\n", sub.ID, remark, fetchErr)
				atomic.AddInt32(&failedCount, 1)
				return
			}

			subID := sql.NullInt64{Int64: sub.ID, Valid: true}
			dbConfigs, unparsable := fc.parseLinks(rawLinks, subID)
			if unparsable > 0 {
				customlog.Printf(customlog.Warning, "Subscription %d (%s): %d link(s) could not be parsed; saved with unknown protocol.\n", sub.ID, remark, unparsable)
			}

			if len(dbConfigs) > 0 {
				if err := database.UpsertSubscriptionConfigs(dbConfigs); err != nil {
					customlog.Printf(customlog.Failure, "Failed to save configs for subscription %d: %v\n", sub.ID, err)
					atomic.AddInt32(&failedCount, 1)
					return
				}
				if err := database.UpdateSubscriptionFetched(sub.ID, time.Now()); err != nil {
					customlog.Printf(customlog.Warning, "Failed to update last fetched timestamp for %d: %v\n", sub.ID, err)
				}
				customlog.Printf(customlog.Success, "Subscription %d (%s): fetched %d links, saved %d configs.\n", sub.ID, remark, len(rawLinks), len(dbConfigs))
			} else {
				customlog.Printf(customlog.Warning, "Subscription %d (%s): no valid configs found.\n", sub.ID, remark)
			}

			mu.Lock()
			allConfigs = append(allConfigs, dbConfigs...)
			totalRaw += len(rawLinks)
			mu.Unlock()
		})
	}

	pool.StopAndWait()

	failed := atomic.LoadInt32(&failedCount)
	unique := dedupeConfigs(allConfigs)
	customlog.Printf(customlog.Finished, "All done: %d links fetched, %d unique configs saved, %d failed.\n", totalRaw, len(unique), failed)

	if err := fc.writeOutput(unique); err != nil {
		return err
	}

	if failed > 0 {
		return fmt.Errorf("%d out of %d subscriptions failed to fetch", failed, len(enabled))
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	fc.printNextStep(len(unique))
	return nil
}

// fetchFromFile handles --file mode with concurrency via pond
func (fc *FetchCommand) fetchFromFile(ctx context.Context) error {
	lines, err := utils.ReadLinks(fc.config.FileInput)
	if err != nil {
		return err
	}
	var urls []string
	for _, line := range lines {
		if err := validateSubscriptionURL(line); err != nil {
			customlog.Printf(customlog.Warning, "Skipping %v\n", err)
			continue
		}
		urls = append(urls, line)
	}
	if len(urls) == 0 {
		return fmt.Errorf("no valid http(s) URLs found in %q", fc.config.FileInput)
	}

	workers := fc.config.Workers
	if workers > len(urls) {
		workers = len(urls)
	}

	customlog.Printf(customlog.Processing, "Found %d URL(s) in %q — fetching with %d worker(s)...\n", len(urls), fc.config.FileInput, workers)

	pool := pond.NewPool(workers)
	defer pool.StopAndWait()

	var (
		mu          sync.Mutex
		allConfigs  []database.SubscriptionConfig
		totalRaw    int
		failedCount int32
		doneCount   int32
	)

	for _, rawURL := range urls {
		rawURL := rawURL // capture loop variable
		pool.Submit(func() {
			idx := atomic.AddInt32(&doneCount, 1)
			customlog.Printf(customlog.Processing, "[%d/%d] Fetching from %s\n", idx, len(urls), rawURL)

			subToFetch := Subscription{
				Url:   rawURL,
				Proxy: fc.config.Proxy,
			}
			if fc.config.UserAgent != "" {
				subToFetch.UserAgent = fc.config.UserAgent
			}

			rawLinks, fetchErr := fc.fetchSource(ctx, &subToFetch)
			if fetchErr != nil {
				customlog.Printf(customlog.Failure, "Failed to fetch %s: %v\n", rawURL, fetchErr)
				atomic.AddInt32(&failedCount, 1)
				return
			}

			// One-off fetches from file are not linked to a subscription
			subID := sql.NullInt64{Valid: false}
			dbConfigs, unparsable := fc.parseLinks(rawLinks, subID)
			if unparsable > 0 {
				customlog.Printf(customlog.Warning, "%s: %d link(s) could not be parsed; saved with unknown protocol.\n", rawURL, unparsable)
			}

			if len(dbConfigs) > 0 {
				if err := database.UpsertSubscriptionConfigs(dbConfigs); err != nil {
					customlog.Printf(customlog.Failure, "Failed to save configs from %s: %v\n", rawURL, err)
					atomic.AddInt32(&failedCount, 1)
					return
				}
				customlog.Printf(customlog.Success, "%s: fetched %d links, saved %d configs.\n", rawURL, len(rawLinks), len(dbConfigs))
			} else {
				customlog.Printf(customlog.Warning, "%s: no valid configs found.\n", rawURL)
			}

			mu.Lock()
			allConfigs = append(allConfigs, dbConfigs...)
			totalRaw += len(rawLinks)
			mu.Unlock()
		})
	}

	pool.StopAndWait()

	failed := atomic.LoadInt32(&failedCount)
	unique := dedupeConfigs(allConfigs)
	customlog.Printf(customlog.Finished, "All done: %d links fetched, %d unique configs saved, %d failed.\n", totalRaw, len(unique), failed)

	if err := fc.writeOutput(unique); err != nil {
		return err
	}

	if failed > 0 {
		return fmt.Errorf("%d out of %d URLs failed to fetch", failed, len(urls))
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	fc.printNextStep(len(unique))
	return nil
}

// doFetch is the shared logic for single-URL fetch (used by fetchSingle)
func (fc *FetchCommand) doFetch(ctx context.Context, sub *Subscription, subscriptionID sql.NullInt64) error {
	rawLinks, err := fc.fetchSource(ctx, sub)
	if err != nil {
		return fmt.Errorf("failed to fetch configurations: %w", err)
	}

	dbConfigs, unparsable := fc.parseLinks(rawLinks, subscriptionID)
	dbConfigs = dedupeConfigs(dbConfigs)
	if unparsable > 0 {
		customlog.Printf(customlog.Warning, "%d link(s) could not be parsed; saved with unknown protocol.\n", unparsable)
	}
	if len(dbConfigs) == 0 {
		customlog.Printf(customlog.Warning, "No valid configs found.\n")
		return fc.writeOutput(nil)
	}

	if err := database.UpsertSubscriptionConfigs(dbConfigs); err != nil {
		return fmt.Errorf("failed to save configurations to database: %w", err)
	}
	customlog.Printf(customlog.Success, "Fetched %d links, saved/updated %d configs in the database.\n", len(rawLinks), len(dbConfigs))

	if subscriptionID.Valid {
		if err := database.UpdateSubscriptionFetched(subscriptionID.Int64, time.Now()); err != nil {
			customlog.Printf(customlog.Warning, "Failed to update last fetched timestamp: %v\n", err)
		}
	}

	if err := fc.writeOutput(dbConfigs); err != nil {
		return err
	}

	fc.printNextStep(len(dbConfigs))
	return nil
}

// dedupeConfigs drops repeated links (the same link from several sources, or
// twice in one source), keeping the first occurrence.
func dedupeConfigs(configs []database.SubscriptionConfig) []database.SubscriptionConfig {
	seen := make(map[string]struct{}, len(configs))
	out := configs[:0:0]
	for _, c := range configs {
		if _, dup := seen[c.ConfigLink]; dup {
			continue
		}
		seen[c.ConfigLink] = struct{}{}
		out = append(out, c)
	}
	return out
}

// writeOutput writes the fetched links to --out. With nothing fetched the
// previous file is left alone (it may hold the last good fetch) but the user
// is told it is stale, rather than left to test yesterday's links.
func (fc *FetchCommand) writeOutput(configs []database.SubscriptionConfig) error {
	if fc.config.OutputFile == "" {
		return nil
	}
	if len(configs) == 0 {
		if fc.config.OutputFile != "-" {
			if _, err := os.Stat(fc.config.OutputFile); err == nil {
				customlog.Printf(customlog.Warning, "Nothing fetched; %q was not updated and still holds the previous fetch.\n", fc.config.OutputFile)
			}
		}
		return nil
	}
	if err := fc.saveConfigsToFile(configs); err != nil {
		return fmt.Errorf("failed to save configurations to file: %w", err)
	}
	if fc.config.OutputFile != "-" {
		customlog.Printf(customlog.Success, "%d configs have been written into %q\n", len(configs), fc.config.OutputFile)
	}
	return nil
}

// parseLinks accepts the subscriptionID to correctly populate the struct. It
// returns the parsed configs plus the number of links whose protocol could not
// be determined — those are still saved, but with an unknown protocol, so the
// caller reports the count rather than leaving the user to discover it via an
// empty --protocol filter later.
func (fc *FetchCommand) parseLinks(rawLinks []string, subID sql.NullInt64) ([]database.SubscriptionConfig, int) {
	var dbConfigs []database.SubscriptionConfig
	var unparsable int
	now := time.Now().UTC()

	for _, link := range rawLinks {
		trimmedLink := strings.TrimSpace(link)
		if trimmedLink == "" {
			continue
		}

		dbConf := database.SubscriptionConfig{
			SubscriptionID: subID,
			ConfigLink:     trimmedLink,
			LastSeenAt:     database.NullTime{Time: now, Valid: true},
		}

		// Malformed links (a parser panic included) must not crash the
		// program, but they do get counted.
		proto, remark, parsed := core.DescribeLink(fc.core, trimmedLink)
		dbConf.Protocol = sql.NullString{String: proto, Valid: proto != ""}
		dbConf.Remark = sql.NullString{String: remark, Valid: remark != ""}
		if !parsed {
			unparsable++
		}

		dbConfigs = append(dbConfigs, dbConf)
	}
	return dbConfigs, unparsable
}

// printNextStep tells the user what to run against what was just fetched.
// Fetching is never the goal on its own, and the file it wrote is the input to
// the next command.
func (fc *FetchCommand) printNextStep(saved int) {
	if saved == 0 {
		return
	}
	if fc.config.OutputFile != "" && fc.config.OutputFile != "-" {
		customlog.Printf(customlog.Info, "Next: xray-knife http -f %s\n", fc.config.OutputFile)
		return
	}
	customlog.Printf(customlog.Info, "Next: xray-knife http --from-db\n")
}

// saveConfigsToFile saves the parsed (filtered) configurations to a file
func (fc *FetchCommand) saveConfigsToFile(configs []database.SubscriptionConfig) error {
	var links []string
	for _, c := range configs {
		links = append(links, c.ConfigLink)
	}
	content := strings.Join(links, "\n") + "\n"
	return utils.WriteIntoFile(fc.config.OutputFile, []byte(content))
}

func (fc *FetchCommand) fetchSource(ctx context.Context, sub *Subscription) ([]string, error) {
	sub.MaxBytes = fc.config.MaxBytes
	sub.MaxLinks = fc.config.MaxLinks
	sub.Timeout = fc.config.Timeout
	links, err := sub.FetchAllContext(ctx)
	if err != nil {
		return nil, err
	}
	if summary := formatSummary(sub.Format, len(links), sub.Skipped); summary != "" {
		label := sub.Remark
		if label == "" {
			label = sub.Url
		}
		customlog.Printf(customlog.Info, "%s: %s\n", label, summary)
	}
	return links, nil
}
