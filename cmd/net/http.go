package net

import (
	"fmt"
	"github.com/spf13/cobra"
	"os"
	"xray-knife/xray"
)

var (
	configLink string
	destURL    string
	httpMethod string
)

// HttpCmd represents the http command
var HttpCmd = &cobra.Command{
	Use:   "http",
	Short: "Test the config[s] using http request",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
		_, err := xray.ParseXrayConfig(configLink)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%v", err)
			os.Exit(1)
		}
	},
}

func init() {
	HttpCmd.Flags().StringVarP(&configLink, "config", "c", "", "The xray config link")
	HttpCmd.Flags().StringVarP(&destURL, "url", "u", "https://www.google.com/", "The url to test config")
	HttpCmd.Flags().StringVarP(&httpMethod, "method", "m", "GET", "Http method")

}
