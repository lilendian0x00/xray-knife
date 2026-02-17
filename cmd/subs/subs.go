package subs

import (
	"github.com/spf13/cobra"
)

// SubsCmd is the subs subcommand (manages subscription links).
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
