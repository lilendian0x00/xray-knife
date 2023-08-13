package parse

import (
	"bufio"
	"fmt"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"os"
	"time"
	"xray-knife/utils"
	"xray-knife/xray"
)

var (
	readFromSTDIN   bool
	configLink      string
	configLinksFile string
)

// ParseCmd represents the parse command
var ParseCmd = &cobra.Command{
	Use:   "parse",
	Short: "Gives a detailed info about the config link",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) < 1 && readFromSTDIN != true && configLink == "" && configLinksFile == "" {
			cmd.Help()
			return
		}
		if readFromSTDIN {
			reader := bufio.NewReader(os.Stdin)
			fmt.Println("Reading config from STDIN:")
			text, _ := reader.ReadString('\n')
			configLink = text

		} else if configLinksFile != "" {
			links := utils.ParseFileByNewline(configLinksFile)
			//fmt.Println(links)
			d := color.New(color.FgCyan, color.Bold)
			for i, link := range links {
				d.Printf("Config Number: %d\n", i+1)
				protocol, err := xray.ParseXrayConfig(link)
				if err != nil {
					fmt.Fprintf(os.Stderr, "%v", err)
					os.Exit(1)
				}
				fmt.Println(protocol.DetailsStr() + "\n")
				time.Sleep(time.Duration(25) * time.Millisecond)
			}
			return

		}

		if readFromSTDIN || configLink != "" {
			fmt.Printf("\n")
			protocol, err := xray.ParseXrayConfig(configLink)
			if err != nil {
				fmt.Fprintf(os.Stderr, "%v", err)
				os.Exit(1)
			}
			fmt.Println(protocol.DetailsStr())
		}
	},
}

func init() {
	ParseCmd.Flags().BoolVarP(&readFromSTDIN, "stdin", "i", false, "Read config link from STDIN")
	ParseCmd.Flags().StringVarP(&configLink, "config", "c", "", "The config link")
	ParseCmd.Flags().StringVarP(&configLinksFile, "file", "f", "", "Read config links from a file")
}
