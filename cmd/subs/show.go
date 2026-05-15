package subs

import (
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/lilendian0x00/xray-knife/v10/database"
	"github.com/spf13/cobra"
)

var showVerbose bool

// ShowCmd lists all subscriptions in the DB.
var ShowCmd = &cobra.Command{
	Use:   "show",
	Short: "Shows all subscriptions available in the DB",
	Long: `Lists all subscriptions stored in the local database in a table format.
By default, long URLs are truncated. Use --verbose to see full URLs.

Examples:
  xray-knife subs show
  xray-knife subs show --verbose`,
	RunE: func(cmd *cobra.Command, args []string) error {
		subs, err := database.ListSubscriptions()
		if err != nil {
			return err
		}

		if len(subs) == 0 {
			fmt.Println("No subscriptions found in the database. Use 'xray-knife subs add' to add one.")
			return nil
		}

		w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
		fmt.Fprintln(w, "ID\tREMARK\tURL\tENABLED\tCONFIGS\tLAST FETCHED")
		fmt.Fprintln(w, "--\t------\t---\t-------\t-------\t------------")

		for _, sub := range subs {
			remark := "N/A"
			if sub.Remark.Valid && sub.Remark.String != "" {
				remark = sub.Remark.String
			}

			lastFetched := "Never"
			if sub.LastFetchedAt.Valid {
				lastFetched = sub.LastFetchedAt.Time.Format("2006-01-02 15:04")
			}

			displayURL := sub.URL
			if !showVerbose && len(displayURL) > 50 {
				displayURL = displayURL[:47] + "..."
			}

			configCount, _ := database.CountSubscriptionConfigs(sub.ID)

			fmt.Fprintf(w, "%d\t%s\t%s\t%t\t%d\t%s\n", sub.ID, remark, displayURL, sub.Enabled, configCount, lastFetched)
		}

		return w.Flush()
	},
}

func init() {
	ShowCmd.Flags().BoolVarP(&showVerbose, "verbose", "v", false, "Show full URLs without truncation")
}
