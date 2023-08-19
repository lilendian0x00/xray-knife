package scan

import (
	"fmt"
	"github.com/spf13/cobra"
)

// ScanCmd represents the scan command
var ScanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Scanning tools needed for bypassing GFW",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("scan called")
	},
}

func init() {

}
