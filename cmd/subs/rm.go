package subs

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/lilendian0x00/xray-knife/v11/database"
	"github.com/lilendian0x00/xray-knife/v11/utils/customlog"
	"github.com/spf13/cobra"
)

var rmYes bool

// stdinIsTerminal is swapped in tests.
var stdinIsTerminal = func() bool { return customlog.IsTerminal(os.Stdin) }

// RmCmd deletes a subscription from the DB by ID.
var RmCmd = &cobra.Command{
	Use:   "rm [ID]",
	Short: "Removes a subscription from the DB by its ID",
	Long: `Removes a subscription and the configs only it provides from the database.
Configs that another subscription also returns are kept.
This action is irreversible. By default, you will be prompted to confirm;
without a terminal (scripts, pipes) pass --yes.

Examples:
  xray-knife subs rm 3
  xray-knife subs rm 3 --yes`,
	Args:              cobra.ExactArgs(1), // Ensures exactly one argument is passed
	ValidArgsFunction: completeSubscriptionIDs,
	RunE: func(cmd *cobra.Command, args []string) error {
		id, err := strconv.ParseInt(args[0], 10, 64)
		if err != nil {
			return usageErr(fmt.Sprintf("invalid ID provided: %s. Please provide a numeric ID", args[0]))
		}

		// Show subscription details and confirm deletion
		if !rmYes {
			if !stdinIsTerminal() {
				return usageErr("refusing to delete without confirmation: stdin is not a terminal; pass --yes")
			}
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

			total, _ := database.CountSubscriptionConfigs(id)
			exclusive, _ := database.CountExclusiveSubscriptionConfigs(id)
			if exclusive > 0 {
				fmt.Printf("  Configs: %d (will also be deleted)\n", exclusive)
			}
			if shared := total - exclusive; shared > 0 {
				fmt.Printf("  Configs also provided by other subscriptions: %d (kept)\n", shared)
			}

			fmt.Print("\nAre you sure you want to delete this subscription? [y/N]: ")
			reader := bufio.NewReader(os.Stdin)
			answer, readErr := reader.ReadString('\n')
			answer = strings.TrimSpace(strings.ToLower(answer))
			if answer != "y" && answer != "yes" {
				if readErr != nil {
					return errors.New("no confirmation received; nothing deleted")
				}
				fmt.Println("Cancelled.")
				return nil
			}
		}

		deleted, err := database.DeleteSubscriptionCounted(id)
		if err != nil {
			return err
		}

		customlog.Printf(customlog.Success, "Successfully removed subscription with ID %d (%d config(s) deleted).\n", id, deleted)
		return nil
	},
}

func init() {
	RmCmd.Flags().BoolVarP(&rmYes, "yes", "y", false, "Skip confirmation prompt")
}
