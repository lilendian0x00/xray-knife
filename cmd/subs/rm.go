package subs

import (
	"fmt"

	"github.com/spf13/cobra"
)

// RmCmd represents the rm command
var RmCmd = &cobra.Command{
	Use:   "rm",
	Short: "Removes a subscription from the DB",
	Long: `A longer description that spans multiple lines and likely contains examples
and usage of using your command. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("rm called")
	},
}

func init() {

}
