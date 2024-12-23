package subs

import (
	"fmt"
	"os"
	"strings"

	"github.com/lilendian0x00/xray-knife/v2/utils"
	"github.com/lilendian0x00/xray-knife/v2/utils/customlog"
	"github.com/lilendian0x00/xray-knife/v2/xray"
	"github.com/spf13/cobra"
)

var (
	subscriptionURL string
	httpMethod      string
	userAgent       string
	outputFile      string
)

// FetchCmd represents the fetch command
var FetchCmd = &cobra.Command{
	Use:   "fetch",
	Short: "Fetches all config links from a subscription to a file",
	Long: `
--url, -u: subscription url
--method, -m: http method to be used
--out, -o: output file
--useragent, -x: useragent to be used
`,
	Run: func(cmd *cobra.Command, args []string) {
		sub := xray.Subscription{
			Url:         subscriptionURL,
			UserAgent:   userAgent,
			Method:      httpMethod,
			ConfigLinks: []string{},
		}
		configs, err := sub.FetchAll()
		if err != nil {
			fmt.Fprintf(os.Stderr, "%v", err)
			os.Exit(1)
		}
		err = utils.WriteIntoFile(outputFile, []byte(strings.Join(configs[:], "\n\n")))
		if err != nil {
			fmt.Fprintf(os.Stderr, "%v", err)
			os.Exit(1)
		}
		customlog.Printf(customlog.Success, "%d Configs have been saved into %s file\n", len(configs), outputFile)
	},
}

func init() {
	FetchCmd.Flags().StringVarP(&subscriptionURL, "url", "u", "", "The subscription url")
	FetchCmd.MarkFlagRequired("url")
	FetchCmd.Flags().StringVarP(&httpMethod, "method", "m", "GET", "Http method to be used")
	FetchCmd.Flags().StringVarP(&userAgent, "useragent", "x", "", "Useragent to be used")
	FetchCmd.Flags().StringVarP(&outputFile, "out", "o", "configs.txt", "The output file where the configs will be placed.")
}
