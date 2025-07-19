package webui

import (
	"fmt"
	"github.com/lilendian0x00/xray-knife/v6/utils/customlog"

	"github.com/lilendian0x00/xray-knife/v6/web"
	"github.com/spf13/cobra"
)

// webuiCmdConfig holds the configuration for the webui command
type webuiCmdConfig struct {
	ListenAddress string
	Port          uint16
}

// WebUICmd represents the webui command
var WebUICmd = newWebUICommand()

func newWebUICommand() *cobra.Command {
	cfg := &webuiCmdConfig{}

	cmd := &cobra.Command{
		Use:   "webui",
		Short: "Starts a web-based user interface for managing xray-knife.",
		Long: `Launches a local web server to provide a graphical user interface
for all of xray-knife's core functionalities, including proxy management,
configuration testing, and scanning.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			// Use fmt to print to console before customlog is redirected by the server
			fmt.Printf("%s Starting Web UI server on http://%s:%d\n", customlog.GetColor(customlog.Success, "[+]"), cfg.ListenAddress, cfg.Port)
			fmt.Printf("%s Press CTRL+C to stop the server.\n", customlog.GetColor(customlog.Info, "[i]"))

			addr := fmt.Sprintf("%s:%d", cfg.ListenAddress, cfg.Port)

			server, err := web.NewServer(addr)
			if err != nil {
				return fmt.Errorf("could not create web server: %w", err)
			}

			return server.Run()
		},
	}

	cmd.Flags().StringVarP(&cfg.ListenAddress, "addr", "a", "127.0.0.1", "The IP address for the web server to listen on.")
	cmd.Flags().Uint16VarP(&cfg.Port, "port", "p", 8080, "The port for the web server to listen on.")

	return cmd
}
