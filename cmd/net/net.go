package net

import (
	"github.com/spf13/cobra"
)

// NetCmd is the net subcommand (groups network diagnostic tools).
var NetCmd = &cobra.Command{
	Use:   "net",
	Short: "Access a suite of network tools to diagnose and test proxy configurations (e.g., TCP)",
	// NoArgs turns `net <typo>` into an "unknown command" usage error
	// instead of printing help and exiting 0.
	Args: cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		_ = cmd.Help()
	},
}

func addSubcommandPalettes() {
	NetCmd.AddCommand(TcpCmd)
}

func init() {
	addSubcommandPalettes()
}
