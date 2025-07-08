package subs

import (
	"github.com/spf13/cobra"
)

// SubsCmd represents the subs command
var SubsCmd = &cobra.Command{
	Use:   "subs",
	Short: "Fetch and manage proxy configurations from subscription links.",
	Run: func(cmd *cobra.Command, args []string) {
		cmd.Help()
	},
}

func addSubcommandPalettes() {
	SubsCmd.AddCommand(ShowCmd)
	SubsCmd.AddCommand(NewFetchCommand())
	SubsCmd.AddCommand(AddCmd)
	SubsCmd.AddCommand(RmCmd)
}

func init() {
	addSubcommandPalettes()
}
