package subs

import (
	"log"
	"strings"

	"github.com/lilendian0x00/xray-knife/utils"
	"github.com/lilendian0x00/xray-knife/utils/customlog"
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
		sub := Subscription{
			Url:         subscriptionURL,
			UserAgent:   userAgent,
			Method:      httpMethod,
			ConfigLinks: []string{},
		}
		configs, err := sub.FetchAll()
		if err != nil {
			log.Fatal(err.Error())
		}

		err = utils.WriteIntoFile(outputFile, []byte(strings.Join(configs[:], "\n\n")))
		if err != nil {
			log.Fatal(err.Error())
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
