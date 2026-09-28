package subs

import (
	"fmt"

	"github.com/lilendian0x00/xray-knife/v11/database"
	"github.com/lilendian0x00/xray-knife/v11/utils/customlog"
	"github.com/spf13/cobra"
)

var (
	updateID        int64
	updateURL       string
	updateRemark    string
	updateUserAgent string
	updateEnabled   string // "true"/"false"/""
)

// UpdateCmd updates an existing subscription in the DB.
var UpdateCmd = &cobra.Command{
	Use:   "update",
	Short: "Updates a subscription's properties",
	Long: `Updates one or more fields of an existing subscription.
Only the fields you specify will be changed; others remain untouched.

Examples:
  xray-knife subs update --sub-id 1 --remark "Renamed Sub"
  xray-knife subs update --sub-id 3 --enabled false
  xray-knife subs update --sub-id 2 --url "https://new-url.com/sub" --user-agent "clash"`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		if updateID <= 0 {
			return usageErr("--sub-id is required")
		}

		var urlPtr, remarkPtr, uaPtr *string
		var enabledPtr *bool

		if cmd.Flags().Changed("url") {
			if err := validateSubscriptionURL(updateURL); err != nil {
				return usageErr(err.Error())
			}
			urlPtr = &updateURL
		}
		if cmd.Flags().Changed("remark") {
			remarkPtr = &updateRemark
		}
		if cmd.Flags().Changed("user-agent") {
			uaPtr = &updateUserAgent
		}
		if cmd.Flags().Changed("enabled") {
			switch updateEnabled {
			case "true", "1":
				v := true
				enabledPtr = &v
			case "false", "0":
				v := false
				enabledPtr = &v
			default:
				return fmt.Errorf("--enabled must be 'true' or 'false', got %q", updateEnabled)
			}
		}

		if urlPtr == nil && remarkPtr == nil && uaPtr == nil && enabledPtr == nil {
			return fmt.Errorf("at least one field must be specified to update (--url, --remark, --user-agent, --enabled)")
		}

		if err := database.UpdateSubscription(updateID, urlPtr, remarkPtr, uaPtr, enabledPtr); err != nil {
			return err
		}
		customlog.Printf(customlog.Success, "Successfully updated subscription ID %d.\n", updateID)
		return nil
	},
}

func init() {
	bindSubscriptionIDFlags(UpdateCmd, &updateID, "ID of the subscription to update (required)")
	UpdateCmd.Flags().StringVarP(&updateURL, "url", "u", "", "New URL for the subscription")
	UpdateCmd.Flags().StringVarP(&updateRemark, "remark", "r", "", "New remark (pass empty string to clear)")
	UpdateCmd.Flags().StringVar(&updateUserAgent, "user-agent", "", "New User-Agent (pass empty string to clear)")
	UpdateCmd.Flags().StringVar(&updateEnabled, "enabled", "", "Enable or disable the subscription (true/false)")
	_ = UpdateCmd.RegisterFlagCompletionFunc("enabled", cobra.FixedCompletions([]string{"true", "false"}, cobra.ShellCompDirectiveNoFileComp))
}
