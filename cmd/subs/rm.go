package subs

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/lilendian0x00/xray-knife/v10/database"
	"github.com/lilendian0x00/xray-knife/v10/utils/customlog"
	"github.com/spf13/cobra"
)

var rmYes bool

// RmCmd deletes a subscription from the DB by ID.
var RmCmd = &cobra.Command{
	Use:   "rm [ID]",
	Short: "Removes a subscription from the DB by its ID",
	Long: `Removes a subscription and all its associated configs from the database.
This action is irreversible. By default, you will be prompted to confirm.

Examples:
  xray-knife subs rm 3
  xray-knife subs rm 3 --yes`,
	Args: cobra.ExactArgs(1), // Ensures exactly one argument is passed
	RunE: func(cmd *cobra.Command, args []string) error {
		id, err := strconv.ParseInt(args[0], 10, 64)
		if err != nil {
			return fmt.Errorf("invalid ID provided: %s. Please provide a numeric ID", args[0])
		}

		// Show subscription details and confirm deletion
		if !rmYes {
			sub, err := database.GetSubscriptionByID(id)
			if err != nil {
				return err
			}

			remark := "N/A"
			if sub.Remark.Valid && sub.Remark.String != "" {
				remark = sub.Remark.String
			}

			fmt.Printf("Subscription ID %d:\n", sub.ID)
			fmt.Printf("  URL:    %s\n", sub.URL)
			fmt.Printf("  Remark: %s\n", remark)

			count, _ := database.CountSubscriptionConfigs(id)
			if count > 0 {
				fmt.Printf("  Configs: %d (will also be deleted)\n", count)
			}

			fmt.Print("\nAre you sure you want to delete this subscription? [y/N]: ")
			reader := bufio.NewReader(os.Stdin)
			answer, _ := reader.ReadString('\n')
			answer = strings.TrimSpace(strings.ToLower(answer))
			if answer != "y" && answer != "yes" {
				fmt.Println("Cancelled.")
				return nil
			}
		}

		if err := database.DeleteSubscription(id); err != nil {
			return err
		}

		customlog.Printf(customlog.Success, "Successfully removed subscription with ID %d.\n", id)
		return nil
	},
}

func init() {
	RmCmd.Flags().BoolVarP(&rmYes, "yes", "y", false, "Skip confirmation prompt")
}
