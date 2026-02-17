package subs

import (
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/lilendian0x00/xray-knife/v7/database"
	"github.com/spf13/cobra"
)

// ShowCmd lists all subscriptions in the DB.
var ShowCmd = &cobra.Command{
	Use:   "show",
	Short: "Shows all subscriptions available in the DB",
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
		fmt.Fprintln(w, "ID\tREMARK\tURL\tENABLED\tLAST FETCHED")
		fmt.Fprintln(w, "--\t------\t---\t-------\t------------")

		for _, sub := range subs {
			remark := "N/A"
			if sub.Remark.Valid && sub.Remark.String != "" {
				remark = sub.Remark.String
			}

			lastFetched := "Never"
			if sub.LastFetchedAt.Valid {
				lastFetched = sub.LastFetchedAt.Time.Format("2006-01-02 15:04")
			}

			fmt.Fprintf(w, "%d\t%s\t%s\t%t\t%s\n", sub.ID, remark, sub.URL, sub.Enabled, lastFetched)
		}

		return w.Flush()
	},
}
