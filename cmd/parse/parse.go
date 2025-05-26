package parse

import (
	"bufio"
	"fmt"
	"github.com/lilendian0x00/xray-knife/v3/utils/customlog"
	"os"
	"strings"
	"time"

	"github.com/lilendian0x00/xray-knife/v3/pkg"
	"github.com/lilendian0x00/xray-knife/v3/utils"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

// parseCmdConfig holds the configuration for the parse command
type parseCmdConfig struct {
	readFromSTDIN   bool
	configLink      string
	configLinksFile string
}

// ParseCmd represents the parse command
var ParseCmd = newParseCommand()

func newParseCommand() *cobra.Command {
	cfg := &parseCmdConfig{}

	cmd := &cobra.Command{
		Use:   "parse",
		Short: "Gives a detailed info about the config link",
		Long:  ``,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) < 1 && !cfg.readFromSTDIN && cfg.configLink == "" && cfg.configLinksFile == "" {
				cmd.Help()
				return nil
			}

			core := pkg.NewAutomaticCore(true, true)
			var links []string

			if cfg.readFromSTDIN {
				reader := bufio.NewReader(os.Stdin)
				fmt.Println("Enter your config link:")
				text, err := reader.ReadString('\n')
				if err != nil {
					return fmt.Errorf("error reading from stdin: %w", err)
				}
				links = append(links, text)
			} else if cfg.configLink != "" {
				links = append(links, cfg.configLink)
			} else if cfg.configLinksFile != "" {
				// Assuming utils.ParseFileByNewline internally handles and logs errors
				// or consider changing it to return an error.
				parsedLinks := utils.ParseFileByNewline(cfg.configLinksFile)
				if len(parsedLinks) == 0 && cfg.configLinksFile != "" {
					// This condition might indicate an empty file or a parsing issue.
					// If utils.ParseFileByNewline doesn't return an error, this check is minimal.
					customlog.Printf(customlog.Processing, "Warning: File '%s' was empty or failed to parse any links.\n", cfg.configLinksFile)
				}
				links = append(links, parsedLinks...)
			}

			if len(links) == 0 {
				return fmt.Errorf("no config links provided or found")
			}

			d := color.New(color.FgCyan, color.Bold)
			for i, link := range links {
				trimmedLink := strings.TrimSpace(link)
				if trimmedLink == "" {
					continue
				}
				if len(links) > 1 {
					d.Printf("Config Number: %d\n", i+1)
				}

				fmt.Printf("\n")
				p, err := core.CreateProtocol(trimmedLink)
				if err != nil {
					return fmt.Errorf("failed to create protocol for link %d ('%s'): %w", i+1, trimmedLink, err)
				}

				fmt.Println(p.DetailsStr())

				time.Sleep(time.Duration(25) * time.Millisecond)
			}
			return nil
		},
	}

	cmd.Flags().BoolVarP(&cfg.readFromSTDIN, "stdin", "i", false, "Read config link from the console")
	cmd.Flags().StringVarP(&cfg.configLink, "config", "c", "", "The config link")
	cmd.Flags().StringVarP(&cfg.configLinksFile, "file", "f", "", "Read config links from a file")
	return cmd
}
