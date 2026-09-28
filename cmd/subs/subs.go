package subs

import (
	"github.com/spf13/cobra"
)

// SubsCmd is the subs subcommand (manages subscription links).
var SubsCmd = &cobra.Command{
	Use:   "subs",
	Short: "Fetch and manage proxy configurations from subscription links.",
	Long: `Manage proxy subscription links and their fetched configurations.

Subcommands allow you to add, remove, update, fetch, and inspect subscriptions
and the proxy configs they contain.

Examples:
  xray-knife subs add --url "https://example.com/sub" --remark "My VPN"
  xray-knife subs show
  xray-knife subs fetch --sub-id 1
  xray-knife subs fetch --all
  xray-knife subs list-configs --sub-id 1`,
	Args: cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		_ = cmd.Help()
	},
}

func addSubcommandPalettes() {
	SubsCmd.AddCommand(ShowCmd)
	SubsCmd.AddCommand(NewFetchCommand())
	SubsCmd.AddCommand(AddCmd)
	SubsCmd.AddCommand(RmCmd)
	SubsCmd.AddCommand(UpdateCmd)
	SubsCmd.AddCommand(ListConfigsCmd)
	SubsCmd.AddCommand(ExportCmd)
}

func init() {
	addSubcommandPalettes()
}
