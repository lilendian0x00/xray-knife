package net

import (
	"fmt"

	"github.com/spf13/cobra"
)

// TcpCmd represents the tcp command
var TcpCmd = &cobra.Command{
	Use:   "tcp",
	Short: "Establish TCP Connection",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("tcp called")
	},
}

func init() {

}
