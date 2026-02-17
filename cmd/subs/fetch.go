package subs

import (
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/lilendian0x00/xray-knife/v7/database"
	"github.com/lilendian0x00/xray-knife/v7/pkg/core"
	"github.com/lilendian0x00/xray-knife/v7/utils"
	"github.com/lilendian0x00/xray-knife/v7/utils/customlog"

	"github.com/spf13/cobra"
)

// FetchConfig holds the configuration for the fetch command
type FetchConfig struct {
	SubscriptionID  int64
	SubscriptionURL string
	UserAgent       string
	OutputFile      string
	Proxy           string
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
		RunE:  fc.runCommand,
		PreRunE: func(cmd *cobra.Command, args []string) error {
			if fc.config.SubscriptionID == 0 && fc.config.SubscriptionURL == "" {
				return fmt.Errorf("either --id or --url must be provided")
			}
			return nil
		},
	}
	fc.addFlags(cmd)
	return cmd
}

func (fc *FetchCommand) addFlags(cmd *cobra.Command) {
	flags := cmd.Flags()
	flags.Int64Var(&fc.config.SubscriptionID, "id", 0, "The ID of the subscription from the DB")
	flags.StringVarP(&fc.config.SubscriptionURL, "url", "u", "", "A one-off subscription url to fetch from")
	flags.StringVarP(&fc.config.UserAgent, "useragent", "a", "", "Custom User-agent to be used (overrides DB value)")
	flags.StringVarP(&fc.config.OutputFile, "out", "o", "", "The output file for fetched configs. Defaults to not writing a file.")
	flags.StringVarP(&fc.config.Proxy, "proxy", "p", "", "Proxy to use for fetching the subscription")
	cmd.MarkFlagsMutuallyExclusive("id", "url")
}

// runCommand executes the fetch command logic
func (fc *FetchCommand) runCommand(cmd *cobra.Command, args []string) error {
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

	rawLinks, err := subToFetch.FetchAll()
	if err != nil {
		return fmt.Errorf("failed to fetch configurations: %w", err)
	}

	dbConfigs := fc.parseLinks(rawLinks, subscriptionID)
	if err := database.UpsertSubscriptionConfigs(dbConfigs); err != nil {
		return fmt.Errorf("failed to save configurations to database: %w", err)
	}
	customlog.Printf(customlog.Success, "Saved/updated %d configs in the database.\n", len(dbConfigs))

	if subscriptionID.Valid {
		if err := database.UpdateSubscriptionFetched(subscriptionID.Int64, time.Now()); err != nil {
			customlog.Printf(customlog.Warning, "Failed to update last fetched timestamp: %v\n", err)
		}
	}

	if fc.config.OutputFile != "" {
		if err := fc.saveConfigsToFile(rawLinks); err != nil {
			return fmt.Errorf("failed to save configurations to file: %w", err)
		}
		customlog.Printf(customlog.Success, "%d configs have been written into %q\n", len(rawLinks), fc.config.OutputFile)
	}

	return nil
}

// parseLinks accepts the subscriptionID to correctly populate the struct
func (fc *FetchCommand) parseLinks(rawLinks []string, subID sql.NullInt64) []database.SubscriptionConfig {
	var dbConfigs []database.SubscriptionConfig
	now := time.Now()

	for _, link := range rawLinks {
		trimmedLink := strings.TrimSpace(link)
		if trimmedLink == "" {
			continue
		}

		dbConf := database.SubscriptionConfig{
			SubscriptionID: subID,
			ConfigLink:     trimmedLink,
			LastSeenAt:     sql.NullTime{Time: now, Valid: true},
		}

		proto, err := fc.core.CreateProtocol(trimmedLink)
		if err == nil {
			if err := proto.Parse(); err == nil {
				g := proto.ConvertToGeneralConfig()
				dbConf.Protocol = sql.NullString{String: g.Protocol, Valid: g.Protocol != ""}
				dbConf.Remark = sql.NullString{String: g.Remark, Valid: g.Remark != ""}
			}
		}

		dbConfigs = append(dbConfigs, dbConf)
	}
	return dbConfigs
}

// saveConfigsToFile saves the fetched configurations to a file
func (fc *FetchCommand) saveConfigsToFile(configs []string) error {
	content := strings.Join(configs, "\n") + "\n"
	return utils.WriteIntoFile(fc.config.OutputFile, []byte(content))
}
