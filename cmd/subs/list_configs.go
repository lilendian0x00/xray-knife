package subs

import (
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/lilendian0x00/xray-knife/v10/database"
	"github.com/spf13/cobra"
)

var (
	listConfigsSubID    int64
	listConfigsProtocol string
	listConfigsLimit    int
)

// ListConfigsCmd lists configs from the DB.
var ListConfigsCmd = &cobra.Command{
	Use:   "list-configs",
	Short: "Lists fetched configs stored in the database",
	Long: `Lists proxy configurations that were fetched from subscriptions and stored in the database.
Results can be filtered by subscription ID and protocol.

Examples:
  xray-knife subs list-configs
  xray-knife subs list-configs --id 1
  xray-knife subs list-configs --protocol vless --limit 20`,
	RunE: func(cmd *cobra.Command, args []string) error {
		configs, err := database.ListSubscriptionConfigs(listConfigsSubID, listConfigsProtocol, listConfigsLimit)
		if err != nil {
			return err
		}

		if len(configs) == 0 {
			fmt.Println("No configs found. Use 'xray-knife subs fetch' to fetch configs from a subscription.")
			return nil
		}

		w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
		fmt.Fprintln(w, "ID\tSUB ID\tPROTOCOL\tREMARK\tLAST SEEN")
		fmt.Fprintln(w, "--\t------\t--------\t------\t---------")

		for _, c := range configs {
			subID := "N/A"
			if c.SubscriptionID.Valid {
				subID = fmt.Sprintf("%d", c.SubscriptionID.Int64)
			}

			protocol := "unknown"
			if c.Protocol.Valid && c.Protocol.String != "" {
				protocol = c.Protocol.String
			}

			remark := "N/A"
			if c.Remark.Valid && c.Remark.String != "" {
				remark = c.Remark.String
			}

			lastSeen := "N/A"
			if c.LastSeenAt.Valid {
				lastSeen = c.LastSeenAt.Time.Format("2006-01-02 15:04")
			}

			fmt.Fprintf(w, "%d\t%s\t%s\t%s\t%s\n", c.ID, subID, protocol, remark, lastSeen)
		}

		return w.Flush()
	},
}

func init() {
	ListConfigsCmd.Flags().Int64Var(&listConfigsSubID, "id", 0, "Filter by subscription ID")
	ListConfigsCmd.Flags().StringVar(&listConfigsProtocol, "protocol", "", "Filter by protocol (e.g. vless, vmess, trojan)")
	ListConfigsCmd.Flags().IntVar(&listConfigsLimit, "limit", 50, "Maximum number of configs to display")
}
