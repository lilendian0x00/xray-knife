package subs

import (
	"github.com/lilendian0x00/xray-knife/v7/database"
	"github.com/lilendian0x00/xray-knife/v7/utils/customlog"
	"github.com/spf13/cobra"
)

var (
	addURL       string
	addRemark    string
	addUserAgent string
)

// AddCmd represents the add command
var AddCmd = &cobra.Command{
	Use:   "add",
	Short: "Adds a new subscription to the database",
	RunE: func(cmd *cobra.Command, args []string) error {
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
