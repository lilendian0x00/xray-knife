package subs

import (
	"fmt"
	"os"
	"text/tabwriter"
	"time"

	"github.com/lilendian0x00/xray-knife/v11/database"
	"github.com/spf13/cobra"
)

var (
	listConfigsSubID    int64
	listConfigsProtocol string
	listConfigsLimit    int
	listConfigsJSON     bool
)

// configJSON is the --json shape of one stored config.
type configJSON struct {
	ID             int64      `json:"id"`
	SubscriptionID *int64     `json:"subscriptionId,omitempty"`
	Link           string     `json:"link"`
	Protocol       string     `json:"protocol,omitempty"`
	Remark         string     `json:"remark,omitempty"`
	AddedAt        time.Time  `json:"addedAt"`
	LastSeenAt     *time.Time `json:"lastSeenAt,omitempty"`
}

// ListConfigsCmd lists configs from the DB.
var ListConfigsCmd = &cobra.Command{
	Use:   "list-configs",
	Short: "Lists fetched configs stored in the database",
	Long: `Lists proxy configurations that were fetched from subscriptions and stored in the database.
Results can be filtered by subscription ID and protocol. --json prints the
full links (the table does not), e.g. to feed another tool.

Examples:
  xray-knife subs list-configs
  xray-knife subs list-configs --sub-id 1
  xray-knife subs list-configs --protocol vless --limit 20
  xray-knife subs list-configs --json --limit 0 | jq -r '.[].link'`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		if listConfigsLimit < 0 {
			return usageErr("--limit must not be negative (0 lists everything)")
		}
		configs, err := database.ListSubscriptionConfigs(listConfigsSubID, listConfigsProtocol, listConfigsLimit)
		if err != nil {
			return err
		}

		if listConfigsJSON {
			out := make([]configJSON, 0, len(configs))
			for _, c := range configs {
				j := configJSON{ID: c.ID, Link: c.ConfigLink, Protocol: c.Protocol.String, Remark: c.Remark.String, AddedAt: c.AddedAt}
				if c.SubscriptionID.Valid {
					id := c.SubscriptionID.Int64
					j.SubscriptionID = &id
				}
				if c.LastSeenAt.Valid {
					t := c.LastSeenAt.Time
					j.LastSeenAt = &t
				}
				out = append(out, j)
			}
			return printJSON(out)
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
				lastSeen = c.LastSeenAt.Time.Local().Format("2006-01-02 15:04")
			}

			fmt.Fprintf(w, "%d\t%s\t%s\t%s\t%s\n", c.ID, subID, protocol, remark, lastSeen)
		}

		return w.Flush()
	},
}

func init() {
	// --sub-id matches the same filter on `http --sub-id`; --id stays as a
	// deprecated alias.
	bindSubscriptionIDFlags(ListConfigsCmd, &listConfigsSubID, "Filter by subscription ID")
	ListConfigsCmd.Flags().StringVar(&listConfigsProtocol, "protocol", "", "Filter by protocol (e.g. vless, vmess, trojan)")
	_ = ListConfigsCmd.RegisterFlagCompletionFunc("protocol", completeProtocols)
	ListConfigsCmd.Flags().IntVarP(&listConfigsLimit, "limit", "l", 50, "Maximum number of configs to display (0 = all)")
	ListConfigsCmd.Flags().BoolVarP(&listConfigsJSON, "json", "j", false, "Print configs (with full links) as JSON")
}
