package cmd

import (
	"github.com/spf13/cobra"
	"os"
	"xray-knife/cmd/bot"
	"xray-knife/cmd/net"
	"xray-knife/cmd/parse"
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "xray-knife",
	Short: "Swiss Army Knife for xray-core",
	Long: `Main Tools:
1. parse: Parses xray config link.
2. net: Multiple network tests for xray configs.
3. bot: A service to automatically switch outbound connections from a subscription or a file of configs.`,

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
	rootCmd.AddCommand(net.NetCmd)
	rootCmd.AddCommand(parse.ParseCmd)
	rootCmd.AddCommand(bot.BotCmd)
}

func init() {
	rootCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
	addSubcommandPalettes()
}