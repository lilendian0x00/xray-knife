package proxy

import (
	"github.com/spf13/cobra"
)

var (
	listenAddr string
	listenPort uint16
	link       string
)

// BotCmd represents the bot command
var ProxyCmd = &cobra.Command{
	Use:   "proxy",
	Short: "Creates proxy server",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {

	},
}

func init() {
	ProxyCmd.Flags().StringVarP(&listenAddr, "addr", "a", "127.0.0.1", "Listen ip address")
	ProxyCmd.Flags().Uint16VarP(&listenPort, "port", "p", 9999, "Listen port number")
	ProxyCmd.Flags().StringVarP(&link, "config", "c", "", "The xray config link")
}
