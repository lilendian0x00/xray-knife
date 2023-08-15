package net

import (
	"github.com/spf13/cobra"
)

// NetCmd represents the net command
var NetCmd = &cobra.Command{
	Use:   "net",
	Short: "Multiple network testing tool for one or multiple xray configs",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
		cmd.Help()
	},
}

func addSubcommandPalettes() {
	NetCmd.AddCommand(IcmpCmd)
	NetCmd.AddCommand(TcpCmd)
	NetCmd.AddCommand(HttpCmd)
}

func init() {
	addSubcommandPalettes()
}
