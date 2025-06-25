package scan

import (
	"os"
	"strings"

	"github.com/lilendian0x00/xray-knife/v4/utils"
	"github.com/lilendian0x00/xray-knife/v4/utils/customlog"

	"github.com/spf13/cobra"
)

var (
	subnets     string
	threadCount uint16
	shuffleIPs  bool
)

// CFscannerCmd represents the cfscanner command
var CFscannerCmd = &cobra.Command{
	Use:   "cfscanner",
	Short: "Cloudflare's edge IP scanner (delay, downlink, uplink)",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
		var cidrs []string
		var totalIPs []string

		if _, err := os.Stat(subnets); err == nil {
			cidrs = utils.ParseFileByNewline(subnets)
		} else {
			cidrs = strings.Split(subnets, ",")
		}

		for _, cidr := range cidrs {
			listIP, err := utils.CIDRtoListIP(cidr)
			if err != nil {
				customlog.Printf(customlog.Failure, "Error when parsing a CIDR: %v\n", err)
				continue
			}
			totalIPs = append(totalIPs, listIP...)
		}

		if len(totalIPs) <= 0 {
			customlog.Printf(customlog.Failure, "Scanner failed! => No IP detected\n")
		}

	},
}

func init() {
	ScanCmd.PersistentFlags().StringVarP(&subnets, "subnets", "s", "", "File or subnets: X.X.X.X/Y OR subnets.txt ")
	ScanCmd.PersistentFlags().Uint16VarP(&threadCount, "threads", "t", 10, "Count of threads")
	ScanCmd.Flags().BoolVarP(&shuffleIPs, "shuffle", "e", true, "Shuffle list of IPs")
}
