package cmd

import (
	"github.com/spf13/cobra"
	"os"
	"xray-knife/cmd/net"
	"xray-knife/cmd/parse"
	"xray-knife/cmd/proxy"
	"xray-knife/cmd/scan"
	"xray-knife/cmd/subs"
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:     "xray-knife",
	Short:   "Swiss Army Knife for xray-core",
	Long:    ``,
	Version: "1.5.11",
	// Main Tools:
	//1. parse: Parses xray config link.
	//2. net: Multiple network tests for xray configs.
	//3. bot: A service to automatically switch outbound connections from a subscription or a file of configs.

	Run: func(cmd *cobra.Command, args []string) {
		cmd.Help()
	},
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func addSubcommandPalettes() {
	rootCmd.AddCommand(parse.ParseCmd)
	rootCmd.AddCommand(subs.SubsCmd)
	rootCmd.AddCommand(net.NetCmd)
	rootCmd.AddCommand(scan.ScanCmd)
	rootCmd.AddCommand(proxy.ProxyCmd)
}

func init() {
	addSubcommandPalettes()
}
