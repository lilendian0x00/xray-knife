package scan

import (
	"github.com/spf13/cobra"
)

// ScanCmd represents the scan command
var ScanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Scan IP ranges to find optimal edge nodes (e.g., Cloudflare) with low latency and high speeds.",
	Long:  ``,
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
