package subs

import (
	"fmt"
	"github.com/lilendian0x00/xray-knife/v7/database"
	"github.com/lilendian0x00/xray-knife/v7/utils/customlog"
	"github.com/spf13/cobra"
	"strconv"
)

// RmCmd deletes a subscription from the DB by ID.
var RmCmd = &cobra.Command{
	Use:   "rm [ID]",
	Short: "Removes a subscription from the DB by its ID",
	Args:  cobra.ExactArgs(1), // Ensures exactly one argument is passed
	RunE: func(cmd *cobra.Command, args []string) error {
		id, err := strconv.ParseInt(args[0], 10, 64)
		if err != nil {
			return fmt.Errorf("invalid ID provided: %s. Please provide a numeric ID", args[0])
		}

		if err := database.DeleteSubscription(id); err != nil {
			return err
		}

		customlog.Printf(customlog.Success, "Successfully removed subscription with ID %d.\n", id)
		return nil
	},
}
