package cmd

import (
	"github.com/lilendian0x00/xray-knife/v5/cmd/http"
	"github.com/lilendian0x00/xray-knife/v5/cmd/scanner"
	"github.com/lilendian0x00/xray-knife/v5/cmd/webui"
	"os"

	"github.com/lilendian0x00/xray-knife/v5/cmd/net"
	"github.com/lilendian0x00/xray-knife/v5/cmd/parse"
	"github.com/lilendian0x00/xray-knife/v5/cmd/proxy"
	"github.com/lilendian0x00/xray-knife/v5/cmd/subs"

	"github.com/spf13/cobra"
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:     "xray-knife",
	Short:   "Swiss Army Knife for xray-core & sing-box",
	Version: "6.0.0",
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func addSubcommandPalettes() {
	rootCmd.AddCommand(parse.ParseCmd)
	rootCmd.AddCommand(subs.SubsCmd)
	rootCmd.AddCommand(http.HttpCmd)
	rootCmd.AddCommand(net.NetCmd)
	rootCmd.AddCommand(scanner.ScanCmd)
	rootCmd.AddCommand(proxy.ProxyCmd)
	rootCmd.AddCommand(webui.WebUICmd)
}

func init() {
	addSubcommandPalettes()
}
