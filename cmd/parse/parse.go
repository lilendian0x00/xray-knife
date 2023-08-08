package parse

import (
	"bufio"
	"fmt"
	"github.com/spf13/cobra"
	"os"
	"xray-knife/xray/vmess"
)

var (
	configLink string
)

// ParseCmd represents the parse command
var ParseCmd = &cobra.Command{
	Use:   "parse",
	Short: "Gives a detailed info about the config link",
	Long:  `Default reads from STDIN, you can use '-c' flags to pass xray config from arguments`,
	Run: func(cmd *cobra.Command, args []string) {
		if configLink == "" {
			reader := bufio.NewReader(os.Stdin)
			fmt.Println("Reading config from STDIN:")
			text, _ := reader.ReadString('\n')
			configLink = text

		}

		fmt.Printf("\n")

		parsedVmess, err := vmess.ParseVmess(configLink)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%v", parsedVmess)
			os.Exit(1)
		}
		fmt.Println(parsedVmess.Details())
	},
}

func init() {
	ParseCmd.Flags().StringVarP(&configLink, "config", "c", "", "The xray config link")

}
