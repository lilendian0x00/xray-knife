package net

import (
	"fmt"
	"net"
	"time"

	"github.com/lilendian0x00/xray-knife/v3/pkg/xray"
	"github.com/lilendian0x00/xray-knife/v3/utils/customlog"

	"github.com/spf13/cobra"
)

// TcpCmd represents the tcp command
var TcpCmd = &cobra.Command{
	Use:   "tcp",
	Short: "Examine TCP Connection delay to config's host",
	Long:  ``,
	RunE: func(cmd *cobra.Command, args []string) error {
		x := xray.NewXrayService(false, false)

		parsed, err := x.CreateProtocol(configLink)
		if err != nil {
			return fmt.Errorf("couldn't parse the config: %w", err)
		}
		generalDetails := parsed.ConvertToGeneralConfig()

		tcpAddr, err := net.ResolveTCPAddr("tcp", generalDetails.Address+":"+generalDetails.Port)
		if err != nil {
			return fmt.Errorf("ResolveTCPAddr failed: %w", err)
		}
		start := time.Now()
		conn, err := net.DialTCP("tcp", nil, tcpAddr)
		if err != nil {
			return fmt.Errorf("couldn't establish tcp conn: %w", err)
		}
		customlog.Printf(customlog.Success, "Established TCP connection in %dms\n", time.Since(start).Milliseconds())
		conn.Close()
		return nil
	},
}

func init() {
	TcpCmd.Flags().StringVarP(&configLink, "config", "c", "", "The xray config link")
}
