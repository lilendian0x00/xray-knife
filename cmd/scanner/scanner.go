package scanner

import (
	"github.com/spf13/cobra"
)

// ScanCmd represents the scan command
var ScanCmd = &cobra.Command{
	Use:   "scanner",
	Short: "Scan Cloudflare IP ranges to find optimal edge nodes with low latency and high speeds.",
	Run: func(cmd *cobra.Command, args []string) {
		cmd.Help()
	},
}

func addSubcommandPalettes() {
	ScanCmd.AddCommand(CFscannerCmd)
	ScanCmd.AddCommand(RealityscannerCmd)
}

func init() {
	addSubcommandPalettes()
}
