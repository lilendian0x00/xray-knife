package parse

import (
	"bufio"
	"fmt"
	"github.com/lilendian0x00/xray-knife/v2/pkg"
	"github.com/lilendian0x00/xray-knife/v2/pkg/protocol"
	"log"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/lilendian0x00/xray-knife/v2/utils"
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

		xrayCore := pkg.CoreFactory(pkg.XrayCoreType, false, false)
		singboxCore := pkg.CoreFactory(pkg.SingboxCoreType, false, false)
		SelectedCore := map[string]pkg.Core{
			protocol.VmessIdentifier:       xrayCore,
			protocol.VlessIdentifier:       xrayCore,
			protocol.ShadowsocksIdentifier: xrayCore,
			protocol.TrojanIdentifier:      xrayCore,
			protocol.SocksIdentifier:       singboxCore,
			protocol.WireguardIdentifier:   singboxCore,
			protocol.Hysteria2Identifier:   singboxCore,
			"hy2":                          singboxCore,
		}

		var core pkg.Core

		if readFromSTDIN {
			reader := bufio.NewReader(os.Stdin)
			fmt.Println("Enter your config link:")
			text, _ := reader.ReadString('\n')
			configLink = text

		} else if configLinksFile != "" {
			links := utils.ParseFileByNewline(configLinksFile)
			//fmt.Println(links)
			d := color.New(color.FgCyan, color.Bold)
			for i, link := range links {
				d.Printf("Config Number: %d\n", i+1)
				protocol, err := core.CreateProtocol(link)
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
			// Remove any spaces
			configLink = strings.TrimSpace(configLink)

			uri, err := url.Parse(configLink)
			if err != nil {
				log.Fatalf("Couldn't parse the config: %v\n", err)
			}

			coreAuto, ok := SelectedCore[uri.Scheme]
			if !ok {
				log.Fatalln("Couldn't parse the config: invalid protocol")
			}

			fmt.Printf("\n")
			p, err := coreAuto.CreateProtocol(configLink)
			if err != nil {
				fmt.Fprintf(os.Stderr, "%v", err)
				os.Exit(1)
			}
			err = p.Parse()
			if err != nil {
				fmt.Fprintf(os.Stderr, "%v", err)
				os.Exit(1)
			}

			fmt.Println(p.DetailsStr())
		}
	},
}

func init() {
	ParseCmd.Flags().BoolVarP(&readFromSTDIN, "stdin", "i", false, "Read config link from the console")
	ParseCmd.Flags().StringVarP(&configLink, "config", "c", "", "The config link")
	ParseCmd.Flags().StringVarP(&configLinksFile, "file", "f", "", "Read config links from a file")
}
