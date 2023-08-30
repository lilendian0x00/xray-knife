package scan

import (
	"fmt"

	"github.com/spf13/cobra"
)

// RealityscannerCmd represents the realityscanner command
var RealityscannerCmd = &cobra.Command{
	Use:   "realityscanner",
	Short: "xray-core TLS REALITY scanner",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("realityscanner called")
	},
}

func init() {

}
