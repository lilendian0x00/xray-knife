package subs

import (
	"github.com/spf13/cobra"
)

// SubsCmd represents the subs command
var SubsCmd = &cobra.Command{
	Use:   "subs",
	Short: "Subscription management tool",
	Long: `
show: shows all subscriptions available in DB
fetch: fetches all configs from the subscription url to a file 
add: add a new subscription
rm: remove a subscription
`,
	Run: func(cmd *cobra.Command, args []string) {
		cmd.Help()
	},
}

func addSubcommandPalettes() {
	SubsCmd.AddCommand(ShowCmd)
	SubsCmd.AddCommand(FetchCmd)
	SubsCmd.AddCommand(AddCmd)
	SubsCmd.AddCommand(RmCmd)
}

func init() {
	addSubcommandPalettes()
}
