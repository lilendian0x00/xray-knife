package net

import (
	"fmt"
	"github.com/spf13/cobra"
	"os"
	"time"
	"xray-knife/xray"
)

var (
	configLink string
	destURL    string
	httpMethod string
	showBody   bool
)

// HttpCmd represents the http command
var HttpCmd = &cobra.Command{
	Use:   "http",
	Short: "Test the config[s] using http request",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
		parsed, err := xray.ParseXrayConfig(configLink)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%v", err)
			os.Exit(1)
		}

		fmt.Println("\n" + parsed.DetailsStr())

		instance, err := xray.StartXray(parsed, true, false)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%v", err)
			os.Exit(1)
			return
		}

		delay, err := xray.MeasureDelay(instance, time.Duration(15)*time.Second, showBody, destURL, httpMethod)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%v", err)
			os.Exit(1)
		}
		fmt.Printf("Delay: %dms\n", delay)
	},
}

func init() {
	HttpCmd.Flags().StringVarP(&configLink, "config", "c", "", "The xray config link")
	HttpCmd.Flags().StringVarP(&destURL, "url", "u", "http://api.ipify.org/", "The url to test config")
	HttpCmd.Flags().StringVarP(&httpMethod, "method", "m", "GET", "Http method")
	HttpCmd.Flags().BoolVarP(&showBody, "showbody", "s", false, "Show response body")

}
