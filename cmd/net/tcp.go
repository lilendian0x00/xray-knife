package net

import (
	"github.com/lilendian0x00/xray-knife/v2/pkg/xray"
	"net"
	"os"
	"time"

	"github.com/lilendian0x00/xray-knife/v2/utils/customlog"

	"github.com/spf13/cobra"
)

// TcpCmd represents the tcp command
var TcpCmd = &cobra.Command{
	Use:   "tcp",
	Short: "Examine TCP Connection delay to config's host",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
		x := xray.NewXrayService(false, false)

		parsed, err := x.CreateProtocol(configLink)
		if err != nil {
			customlog.Printf(customlog.Failure, "Couldn't parse the config!\n")
			os.Exit(1)
		}
		generalDetails := parsed.ConvertToGeneralConfig()

		tcpAddr, err := net.ResolveTCPAddr("tcp", generalDetails.Address+":"+generalDetails.Port)
		if err != nil {
			customlog.Printf(customlog.Failure, "ResolveTCPAddr failed: %v\n", err)
			os.Exit(1)
		}
		start := time.Now()
		conn, err := net.DialTCP("tcp", nil, tcpAddr)
		if err != nil {
			customlog.Printf(customlog.Failure, "Couldn't establish tcp conn! : %v\n", err)
			os.Exit(1)
		}
		customlog.Printf(customlog.Success, "Established TCP connection in %dms\n", time.Since(start).Milliseconds())
		conn.Close()
	},
}

func init() {
	TcpCmd.Flags().StringVarP(&configLink, "config", "c", "", "The xray config link")
}
