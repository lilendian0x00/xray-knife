package net

import (
	"fmt"
	"github.com/lilendian0x00/xray-knife/internal/xray"
	"net"
	"os"

	"github.com/lilendian0x00/xray-knife/utils/customlog"

	"github.com/lilendian0x00/xray-knife/network"
	"github.com/spf13/cobra"
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
		x := xray.NewXrayService(false, false)

		parsed, err := x.CreateProtocol(configLink)
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
