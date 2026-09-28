package subs

import (
	"github.com/lilendian0x00/xray-knife/v11/database"
	"github.com/lilendian0x00/xray-knife/v11/utils/customlog"
	"github.com/spf13/cobra"
)

var (
	addURL       string
	addRemark    string
	addUserAgent string
)

// AddCmd adds a new subscription to the DB.
var AddCmd = &cobra.Command{
	Use:   "add",
	Short: "Adds a new subscription to the database",
	Long: `Adds a new subscription URL to the local database.
The subscription can later be fetched with 'subs fetch --sub-id <ID>'.
Only http:// and https:// URLs are accepted.

Examples:
  xray-knife subs add --url "https://example.com/sub"
  xray-knife subs add --url "https://example.com/sub" --remark "My VPN" --user-agent "clash"`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := validateSubscriptionURL(addURL); err != nil {
			return usageErr(err.Error())
		}

		err := database.AddSubscription(addURL, addRemark, addUserAgent)
		if err != nil {
			return err
		}
		customlog.Printf(customlog.Success, "Successfully added subscription: %s\n", addURL)
		return nil
	},
}

func init() {
	AddCmd.Flags().StringVarP(&addURL, "url", "u", "", "URL of the subscription")
	AddCmd.Flags().StringVarP(&addRemark, "remark", "r", "", "A memorable name for the subscription")
	AddCmd.Flags().StringVar(&addUserAgent, "user-agent", "", "Custom User-Agent for fetching the subscription")
	AddCmd.MarkFlagRequired("url")
}
