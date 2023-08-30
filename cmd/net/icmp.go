package net

import (
	"fmt"
	"github.com/spf13/cobra"
	"net"
	"os"
	"xray-knife/network"
	"xray-knife/utils/customlog"
	"xray-knife/xray"
)

var (
	destIP    net.IP
	testCount uint16
)

// IcmpCmd represents the icmp command
var IcmpCmd = &cobra.Command{
	Use:   "icmp",
	Short: "PING or ICMP test config's host",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
		parsed, err := xray.ParseXrayConfig(configLink)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%v", err)
			os.Exit(1)
		}

		generalDetails := parsed.ConvertToGeneralConfig()
		if err != nil {
			fmt.Fprintf(os.Stderr, "%v", err)
			os.Exit(1)
		}

		icmp, err := network.NewIcmpPacket(generalDetails.Address, testCount)
		if err != nil {
			customlog.Printf(customlog.Failure, "%v\n", err)
		}

		err = icmp.MeasureReplyDelay()
		if err != nil {
			customlog.Printf(customlog.Failure, "MeasureReplyDelay Error: %v", err)
			os.Exit(1)
		}
	},
}

func init() {
	IcmpCmd.Flags().StringVarP(&configLink, "config", "c", "", "The xray config link")
	IcmpCmd.Flags().Uint16VarP(&testCount, "count", "t", 4, "Count of tests")
}
