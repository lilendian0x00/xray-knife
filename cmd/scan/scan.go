package scan

import (
	"github.com/spf13/cobra"
)

// ScanCmd represents the scan command
var ScanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Scanning tools needed for bypassing GFW",
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

}
