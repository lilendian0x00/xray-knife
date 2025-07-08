package subs

import (
	"fmt"

	"github.com/spf13/cobra"
)

// ShowCmd represents the show command
var ShowCmd = &cobra.Command{
	Use:   "show",
	Short: "Shows all subscriptions available in the DB",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("show called")
	},
}

func init() {

}
