package cmd

import (
	"log"
	"os"
	"path/filepath"

	"github.com/lilendian0x00/xray-knife/v7/cmd/cfscanner"
	"github.com/lilendian0x00/xray-knife/v7/cmd/http"
	"github.com/lilendian0x00/xray-knife/v7/cmd/net"
	"github.com/lilendian0x00/xray-knife/v7/cmd/parse"
	"github.com/lilendian0x00/xray-knife/v7/cmd/proxy"
	"github.com/lilendian0x00/xray-knife/v7/cmd/subs"
	"github.com/lilendian0x00/xray-knife/v7/cmd/webui"
	"github.com/lilendian0x00/xray-knife/v7/database"
	"github.com/lilendian0x00/xray-knife/v7/utils/customlog"
	"github.com/spf13/cobra"
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:     "xray-knife",
	Short:   "Swiss Army Knife for xray-core & sing-box",
	Version: "7.3.9",
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
	rootCmd.AddCommand(cfscanner.CFscannerCmd)
	rootCmd.AddCommand(proxy.ProxyCmd)
	rootCmd.AddCommand(webui.WebUICmd)
}

// Set up the application's configuration and initialize the database.
func initConfig() {
	// Find home directory.
	home, err := os.UserHomeDir()
	if err != nil {
		log.Fatalf("Could not find user home directory: %v", err)
	}

	// Define the application's config directory path (~/.xray-knife)
	configDir := filepath.Join(home, ".xray-knife")

	// Create the config directory if it doesn't exist.
	if _, err := os.Stat(configDir); os.IsNotExist(err) {
		if err := os.MkdirAll(configDir, 0755); err != nil {
			log.Fatalf("Could not create config directory at %s: %v", configDir, err)
		}
	}

	// Define the database path.
	dbPath := filepath.Join(configDir, "xray-knife.db")

	// Initialize the database.
	// This opens the connection and runs migrations.
	if err := database.InitDB(dbPath); err != nil {
		customlog.Printf(customlog.Failure, "Failed to initialize database: %v\n", err)
		os.Exit(1)
	}
}

func init() {
	cobra.OnInitialize(initConfig)

	addSubcommandPalettes()
}
