package net

import (
	"fmt"
	"net"
	"time"

	"github.com/lilendian0x00/xray-knife/v4/pkg/xray"
	"github.com/lilendian0x00/xray-knife/v4/utils/customlog"

	"github.com/spf13/cobra"
)

// Define a struct to hold the configuration for the TCP command
type tcpCmdConfig struct {
	configLink string
}

// TcpCmd represents the tcp command
var TcpCmd = newTcpCommand()

// newTcpCommand creates and returns the tcp command
func newTcpCommand() *cobra.Command {
	// cfg holds the configuration for this command, populated by flags
	cfg := &tcpCmdConfig{}

	cmd := &cobra.Command{
		Use:   "tcp",
		Short: "Examine TCP Connection delay to config's host",
		Long:  ``,
		RunE: func(cmd *cobra.Command, args []string) error {
			x := xray.NewXrayService(false, false)

			if cfg.configLink == "" {
				return fmt.Errorf("config link is required for the tcp command. Use -c or --config")
			}

			parsed, err := x.CreateProtocol(cfg.configLink)
			if err != nil {
				return fmt.Errorf("couldn't parse the config: %w", err)
			}
			generalDetails := parsed.ConvertToGeneralConfig()

			if generalDetails.Address == "" || generalDetails.Port == "" {
				return fmt.Errorf("parsed config (from %s) does not yield a valid address or port", cfg.configLink)
			}
			targetAddr := generalDetails.Address + ":" + generalDetails.Port

			tcpAddr, err := net.ResolveTCPAddr("tcp", targetAddr)
			if err != nil {
				return fmt.Errorf("ResolveTCPAddr failed for '%s': %w", targetAddr, err)
			}
			start := time.Now()
			conn, err := net.DialTCP("tcp", nil, tcpAddr)
			if err != nil {
				return fmt.Errorf("couldn't establish tcp conn to '%s': %w", targetAddr, err)
			}
			customlog.Printf(customlog.Success, "Established TCP connection in %dms\n", time.Since(start).Milliseconds())
			conn.Close()
			return nil
		},
	}

	cmd.Flags().StringVarP(&cfg.configLink, "config", "c", "", "The xray config link")
	// cmd.MarkFlagRequired("config")
	return cmd
}
