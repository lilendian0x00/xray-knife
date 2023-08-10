package net

import (
	"github.com/spf13/cobra"
)

// NetCmd represents the net command
var NetCmd = &cobra.Command{
	Use:   "net",
	Short: "Multiple tools for testing one or multiple xray configs",
	Long: `
icmp: send icmp packets
tcp: establish tcp connection
http: connect and send a http req to the dest
`,
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
