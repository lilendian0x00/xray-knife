package net

import (
	"fmt"

	"github.com/spf13/cobra"
)

// TcpCmd represents the tcp command
var TcpCmd = &cobra.Command{
	Use:   "tcp",
	Short: "Examine TCP Connection delay to config's host",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("tcp called")
	},
}

func init() {

}
