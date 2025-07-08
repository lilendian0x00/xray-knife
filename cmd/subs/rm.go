package subs

import (
	"fmt"

	"github.com/spf13/cobra"
)

// RmCmd represents the rm command
var RmCmd = &cobra.Command{
	Use:   "rm",
	Short: "Removes a subscription from the DB",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("rm called")
	},
}

func init() {

}
