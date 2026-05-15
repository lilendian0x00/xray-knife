package subs

import (
	"fmt"
	"net/url"

	"github.com/lilendian0x00/xray-knife/v10/database"
	"github.com/lilendian0x00/xray-knife/v10/utils/customlog"
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
The subscription can later be fetched with 'subs fetch --id <ID>'.

Examples:
  xray-knife subs add --url "https://example.com/sub"
  xray-knife subs add --url "https://example.com/sub" --remark "My VPN" --user-agent "clash"`,
	RunE: func(cmd *cobra.Command, args []string) error {
		// Validate URL before storing
		if _, err := url.ParseRequestURI(addURL); err != nil {
			return fmt.Errorf("invalid URL %q: %w", addURL, err)
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
	AddCmd.Flags().StringVarP(&addUserAgent, "user-agent", "a", "", "Custom User-Agent for fetching the subscription")
	AddCmd.MarkFlagRequired("url")
}
