package subs

import (
	"database/sql"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/alitto/pond/v2"
	"github.com/lilendian0x00/xray-knife/v9/database"
	"github.com/lilendian0x00/xray-knife/v9/pkg/core"
	"github.com/lilendian0x00/xray-knife/v9/utils"
	"github.com/lilendian0x00/xray-knife/v9/utils/customlog"

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
		Short: "Fetches configs from a subscription and saves them to the DB and optionally a file.",
		Long: `Fetches proxy configurations from one or more subscription sources.

Supports multiple input modes:
  --id <N>       Fetch from a subscription stored in the DB by its ID.
  --url <URL>    One-off fetch from a URL (configs saved to DB but not linked to a subscription).
  --all          Fetch from all enabled subscriptions in the DB.
  --file <PATH>  Read subscription URLs from a file (one per line) and fetch each concurrently.

Use --workers to control concurrency for --file and --all modes (default: 3).
Fetched configs are parsed, deduplicated, and upserted into the local database.
Optionally write the fetched configs to a file with --out.

Examples:
  xray-knife subs fetch --id 1
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
	flags.Int64Var(&fc.config.SubscriptionID, "id", 0, "The ID of the subscription from the DB")
	flags.StringVarP(&fc.config.SubscriptionURL, "url", "u", "", "A one-off subscription URL to fetch from")
	flags.StringVarP(&fc.config.UserAgent, "useragent", "a", "", "Custom User-agent to be used (overrides DB value)")
	flags.StringVarP(&fc.config.OutputFile, "out", "o", "configs.txt", "Output file for fetched configs (default: configs.txt).")
	flags.StringVarP(&fc.config.Proxy, "proxy", "p", "", "Proxy to use for fetching the subscription")
	flags.BoolVar(&fc.config.FetchAll, "all", false, "Fetch from all enabled subscriptions in the DB")
	flags.StringVarP(&fc.config.FileInput, "file", "f", "", "File containing subscription URLs (one per line)")
	flags.IntVarP(&fc.config.Workers, "workers", "w", 3, "Number of concurrent workers for --file and --all modes")

	cmd.MarkFlagsMutuallyExclusive("id", "url", "all", "file")
}

func (fc *FetchCommand) validateFlags(cmd *cobra.Command, args []string) error {
	if fc.config.SubscriptionID == 0 && fc.config.SubscriptionURL == "" && !fc.config.FetchAll && fc.config.FileInput == "" {
		return fmt.Errorf("one of --id, --url, --all, or --file must be provided")
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
		return fc.fetchAllSubscriptions()
	}
	if fc.config.FileInput != "" {
		return fc.fetchFromFile()
	}
	return fc.fetchSingle()
}

// fetchSingle handles --id and --url modes (no concurrency needed)
func (fc *FetchCommand) fetchSingle() error {
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
		customlog.Printf(customlog.Warning, "One-off fetch: configs will not be linked to any subscription.\n")
	}

	if fc.config.UserAgent != "" {
		subToFetch.UserAgent = fc.config.UserAgent
	}
	subToFetch.Proxy = fc.config.Proxy

	return fc.doFetch(&subToFetch, subscriptionID)
}

// fetchResult stores per-URL results for concurrent fetching
type fetchResult struct {
	url      string
	configs  []database.SubscriptionConfig
	rawCount int
	err      error
}

// fetchAllSubscriptions handles --all mode with concurrency
func (fc *FetchCommand) fetchAllSubscriptions() error {
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
				Url:       sub.URL,
				UserAgent: sub.UserAgent.String,
				Proxy:     fc.config.Proxy,
			}
			if fc.config.UserAgent != "" {
				subToFetch.UserAgent = fc.config.UserAgent
			}

			rawLinks, fetchErr := subToFetch.FetchAll()
			if fetchErr != nil {
				customlog.Printf(customlog.Failure, "Failed to fetch subscription %d (%s): %v\n", sub.ID, remark, fetchErr)
				atomic.AddInt32(&failedCount, 1)
				return
			}

			subID := sql.NullInt64{Int64: sub.ID, Valid: true}
			dbConfigs := fc.parseLinks(rawLinks, subID)

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
	customlog.Printf(customlog.Finished, "All done: %d links fetched, %d configs saved, %d failed.\n", totalRaw, len(allConfigs), failed)

	if fc.config.OutputFile != "" && len(allConfigs) > 0 {
		if err := fc.saveConfigsToFile(allConfigs); err != nil {
			return fmt.Errorf("failed to save configurations to file: %w", err)
		}
		customlog.Printf(customlog.Success, "%d configs have been written into %q\n", len(allConfigs), fc.config.OutputFile)
	}

	if failed > 0 {
		return fmt.Errorf("%d out of %d subscriptions failed to fetch", failed, len(enabled))
	}
	return nil
}

// fetchFromFile handles --file mode with concurrency via pond
func (fc *FetchCommand) fetchFromFile() error {
	urls := utils.ParseFileByNewline(fc.config.FileInput)
	if len(urls) == 0 {
		return fmt.Errorf("no URLs found in file %q", fc.config.FileInput)
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

			rawLinks, fetchErr := subToFetch.FetchAll()
			if fetchErr != nil {
				customlog.Printf(customlog.Failure, "Failed to fetch %s: %v\n", rawURL, fetchErr)
				atomic.AddInt32(&failedCount, 1)
				return
			}

			// One-off fetches from file are not linked to a subscription
			subID := sql.NullInt64{Valid: false}
			dbConfigs := fc.parseLinks(rawLinks, subID)

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
	customlog.Printf(customlog.Finished, "All done: %d links fetched, %d configs saved, %d failed.\n", totalRaw, len(allConfigs), failed)

	if fc.config.OutputFile != "" && len(allConfigs) > 0 {
		if err := fc.saveConfigsToFile(allConfigs); err != nil {
			return fmt.Errorf("failed to save configurations to file: %w", err)
		}
		customlog.Printf(customlog.Success, "%d configs have been written into %q\n", len(allConfigs), fc.config.OutputFile)
	}

	if failed > 0 {
		return fmt.Errorf("%d out of %d URLs failed to fetch", failed, len(urls))
	}
	return nil
}

// doFetch is the shared logic for single-URL fetch (used by fetchSingle)
func (fc *FetchCommand) doFetch(sub *Subscription, subscriptionID sql.NullInt64) error {
	rawLinks, err := sub.FetchAll()
	if err != nil {
		return fmt.Errorf("failed to fetch configurations: %w", err)
	}

	dbConfigs := fc.parseLinks(rawLinks, subscriptionID)
	if len(dbConfigs) == 0 {
		customlog.Printf(customlog.Warning, "No valid configs found.\n")
		return nil
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

	if fc.config.OutputFile != "" {
		if err := fc.saveConfigsToFile(dbConfigs); err != nil {
			return fmt.Errorf("failed to save configurations to file: %w", err)
		}
		customlog.Printf(customlog.Success, "%d configs have been written into %q\n", len(dbConfigs), fc.config.OutputFile)
	}

	return nil
}

// parseLinks accepts the subscriptionID to correctly populate the struct
func (fc *FetchCommand) parseLinks(rawLinks []string, subID sql.NullInt64) []database.SubscriptionConfig {
	var dbConfigs []database.SubscriptionConfig
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

		// Parse protocol info with panic recovery — malformed links must not crash the program
		func() {
			defer func() {
				if r := recover(); r != nil {
					// Silently skip — the config is still saved with unknown protocol
				}
			}()
			proto, err := fc.core.CreateProtocol(trimmedLink)
			if err == nil {
				if err := proto.Parse(); err == nil {
					g := proto.ConvertToGeneralConfig()
					dbConf.Protocol = sql.NullString{String: g.Protocol, Valid: g.Protocol != ""}
					dbConf.Remark = sql.NullString{String: g.Remark, Valid: g.Remark != ""}
				}
			}
		}()

		dbConfigs = append(dbConfigs, dbConf)
	}
	return dbConfigs
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
