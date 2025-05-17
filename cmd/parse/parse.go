package parse

import (
	"bufio"
	"fmt"
	"os"
	"time"

	"github.com/lilendian0x00/xray-knife/v3/pkg"
	"github.com/lilendian0x00/xray-knife/v3/utils"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
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

		core := pkg.NewAutomaticCore(true, true)
		var links []string

		if readFromSTDIN {
			reader := bufio.NewReader(os.Stdin)
			fmt.Println("Enter your config link:")
			text, _ := reader.ReadString('\n')
			links = append(links, text)
		} else if configLink != "" {
			links = append(links, configLink)
		} else if configLinksFile != "" {
			links = utils.ParseFileByNewline(configLinksFile)
			//fmt.Println(links)
		}

		d := color.New(color.FgCyan, color.Bold)
		for i, link := range links {
			if len(links) > 1 {
				d.Printf("Config Number: %d", i+1)
			}

			fmt.Printf("\n")
			p, err := core.CreateProtocol(link)
			if err != nil {
				fmt.Fprintf(os.Stderr, "%v", err)
				os.Exit(1)
			}

			fmt.Println(p.DetailsStr())

			time.Sleep(time.Duration(25) * time.Millisecond)
		}
	},
}

func init() {
	ParseCmd.Flags().BoolVarP(&readFromSTDIN, "stdin", "i", false, "Read config link from the console")
	ParseCmd.Flags().StringVarP(&configLink, "config", "c", "", "The config link")
	ParseCmd.Flags().StringVarP(&configLinksFile, "file", "f", "", "Read config links from a file")
}
