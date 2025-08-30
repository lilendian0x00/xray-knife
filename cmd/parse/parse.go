package parse

import (
	"bufio"
	"encoding/json"
	"fmt"
	"github.com/GFW-knocker/Xray-core/infra/conf"
	"github.com/lilendian0x00/xray-knife/v7/pkg/core"
	"github.com/lilendian0x00/xray-knife/v7/pkg/core/xray"
	"github.com/lilendian0x00/xray-knife/v7/utils/customlog"
	"os"
	"reflect"
	"strings"
	"time"

	"github.com/lilendian0x00/xray-knife/v7/utils"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

// parseCmdConfig holds the configuration for the parse command
type parseCmdConfig struct {
	readFromSTDIN   bool
	configLink      string
	configLinksFile string
	outputJSON      bool
}

// ParseCmd represents the parse command
var ParseCmd = newParseCommand()

// removeEmptyValues recursively traverses a map or slice and removes keys/elements
// that are nil, false, 0, empty strings, or empty collections.
func removeEmptyValues(data interface{}) interface{} {
	if data == nil {
		return nil
	}

	val := reflect.ValueOf(data)

	switch val.Kind() {
	case reflect.Map:
		// Create a new map to hold the non-empty values
		cleanMap := make(map[string]interface{})
		for _, key := range val.MapKeys() {
			v := val.MapIndex(key)
			// Recurse on the value
			cleanedValue := removeEmptyValues(v.Interface())
			// Check if the cleaned value is non-empty before adding it
			if cleanedValue != nil {
				cleanMap[key.String()] = cleanedValue
			}
		}
		// If the cleaned map is empty, return nil to remove it from parent
		if len(cleanMap) == 0 {
			return nil
		}
		return cleanMap

	case reflect.Slice:
		// If the slice is empty, return nil
		if val.Len() == 0 {
			return nil
		}
		// Create a new slice to hold non-empty elements
		var cleanSlice []interface{}
		for i := 0; i < val.Len(); i++ {
			cleanedElement := removeEmptyValues(val.Index(i).Interface())
			if cleanedElement != nil {
				cleanSlice = append(cleanSlice, cleanedElement)
			}
		}
		// If the cleaned slice is empty, return nil
		if len(cleanSlice) == 0 {
			return nil
		}
		return cleanSlice

	case reflect.Ptr, reflect.Interface:
		if val.IsNil() {
			return nil
		}
		// Recurse on the element pointed to by the pointer/interface
		return removeEmptyValues(val.Elem().Interface())

	case reflect.String:
		if val.String() == "" {
			return nil
		}
	case reflect.Bool:
		if !val.Bool() {
			return nil
		}
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		if val.Int() == 0 {
			return nil
		}
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		if val.Uint() == 0 {
			return nil
		}
	case reflect.Float32, reflect.Float64:
		if val.Float() == 0 {
			return nil
		}
	}

	// If the value is not considered empty, return it
	return data
}

// generateAndPrintXrayJSON creates a full xray-core configuration from a link and prints it.
func generateAndPrintXrayJSON(configLink string) error {
	xrayCore := xray.NewXrayService(false, false)

	// Create and parse the outbound protocol from the provided link
	outboundProto, err := xrayCore.CreateProtocol(configLink)
	if err != nil {
		return fmt.Errorf("failed to create outbound protocol from link: %w", err)
	}
	xrayOutbound, ok := outboundProto.(xray.Protocol)
	if !ok {
		return fmt.Errorf("provided link is not a supported xray-core protocol")
	}

	if err := xrayOutbound.Parse(); err != nil {
		return fmt.Errorf("failed to parse outbound protocol: %w", err)
	}
	outboundDetour, err := xrayOutbound.BuildOutboundDetourConfig(false)
	if err != nil {
		return fmt.Errorf("failed to build outbound detour: %w", err)
	}

	// Create a default SOCKS inbound
	defaultInbound := &xray.Socks{
		Address: "127.0.0.1",
		Port:    "1080",
	}
	inboundDetour, err := defaultInbound.BuildInboundDetourConfig()
	if err != nil {
		return fmt.Errorf("failed to build default inbound detour: %w", err)
	}

	// Assemble the final configuration structure
	finalConfig := &conf.Config{
		LogConfig: &conf.LogConfig{
			LogLevel: "warning",
		},
		InboundConfigs:  []conf.InboundDetourConfig{*inboundDetour},
		OutboundConfigs: []conf.OutboundDetourConfig{*outboundDetour},
	}

	// Marshal to verbose JSON first
	verboseBytes, err := json.Marshal(finalConfig)
	if err != nil {
		return fmt.Errorf("failed to marshal config to verbose JSON: %w", err)
	}

	// Unmarshal into a generic map
	var genericConfig map[string]interface{}
	if err := json.Unmarshal(verboseBytes, &genericConfig); err != nil {
		return fmt.Errorf("failed to unmarshal verbose JSON to map: %w", err)
	}

	// Clean the map by removing empty/zero values
	cleanedConfig := removeEmptyValues(genericConfig)

	// Marshal the cleaned map back to indented JSON and print
	cleanBytes, err := json.MarshalIndent(cleanedConfig, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal cleaned config to JSON: %w", err)
	}

	fmt.Println(string(cleanBytes))
	return nil
}

func newParseCommand() *cobra.Command {
	cfg := &parseCmdConfig{}

	cmd := &cobra.Command{
		Use:   "parse",
		Short: "Decode and display a detailed, human-readable breakdown of a proxy configuration link.",
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) < 1 && !cfg.readFromSTDIN && cfg.configLink == "" && cfg.configLinksFile == "" {
				cmd.Help()
				return nil
			}

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

			// New logic branch for JSON output
			if cfg.outputJSON {
				if len(links) > 1 {
					return fmt.Errorf("--json flag only supports one config link at a time")
				}
				trimmedLink := strings.TrimSpace(links[0])
				if trimmedLink == "" {
					return fmt.Errorf("provided config link is empty")
				}
				return generateAndPrintXrayJSON(trimmedLink)
			}

			c := core.NewAutomaticCore(true, true)

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
				p, err := c.CreateProtocol(trimmedLink)
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
	cmd.Flags().BoolVarP(&cfg.outputJSON, "json", "j", false, "Output full xray-core JSON configuration with a default inbound")
	return cmd
}
