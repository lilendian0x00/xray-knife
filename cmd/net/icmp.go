package net

import (
	"fmt"
	"github.com/spf13/cobra"
)

// IcmpCmd represents the icmp command
var IcmpCmd = &cobra.Command{
	Use:   "icmp",
	Short: "Send icmp packet",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("icmp called")
	},
}

func init() {

}
