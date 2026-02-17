package net

import (
	"github.com/spf13/cobra"
)

// NetCmd is the net subcommand (groups network diagnostic tools).
var NetCmd = &cobra.Command{
	Use:   "net",
	Short: "Access a suite of network tools to diagnose and test proxy configurations (e.g., TCP, ICMP)",
	Run: func(cmd *cobra.Command, args []string) {
		cmd.Help()
	},
}

func addSubcommandPalettes() {
	//NetCmd.AddCommand(NewICMPCommand())
	NetCmd.AddCommand(TcpCmd)
	//NetCmd.AddCommand(NewHTTPCommand())
}

func init() {
	addSubcommandPalettes()
}
