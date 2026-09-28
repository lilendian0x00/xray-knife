package parse

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"reflect"
	"strings"

	"github.com/lilendian0x00/xray-knife/v11/pkg/core"
	"github.com/lilendian0x00/xray-knife/v11/pkg/core/xray"
	"github.com/lilendian0x00/xray-knife/v11/utils"
	"github.com/lilendian0x00/xray-knife/v11/utils/customlog"
	"github.com/xtls/xray-core/infra/conf"

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

// ParseCmd is the parse subcommand.
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

// generateAndPrintXrayJSON builds a full xray-core config from a link and prints it as cleaned JSON.
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

// stdinIsTerminal is swapped in tests.
var stdinIsTerminal = func() bool { return customlog.IsTerminal(os.Stdin) }

// readStdinLinks reads links from stdin until EOF, or until ctx is cancelled
// (Ctrl-C) while waiting. On a terminal it prompts on stderr, so stdout
// stays clean for --json.
func readStdinLinks(ctx context.Context, in io.Reader, interactive bool) ([]string, error) {
	if interactive {
		fmt.Fprintln(os.Stderr, "Paste config link(s), one per line, then press Ctrl-D:")
	}
	type result struct {
		links []string
		err   error
	}
	done := make(chan result, 1)
	go func() {
		links, err := utils.ReadLinksFrom(in)
		done <- result{links, err}
	}()
	select {
	case r := <-done:
		if r.err != nil {
			return nil, fmt.Errorf("error reading from stdin: %w", r.err)
		}
		return r.links, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// collectLinks gathers links from positional arguments, -c, -f and stdin.
// With no explicit source and piped stdin, stdin is read.
func collectLinks(ctx context.Context, cfg *parseCmdConfig, args []string) ([]string, error) {
	var links []string
	for _, a := range args {
		if a = strings.TrimSpace(a); a != "" {
			links = append(links, a)
		}
	}
	if cfg.configLink != "" {
		links = append(links, strings.TrimSpace(cfg.configLink))
	}
	if cfg.configLinksFile != "" {
		fileLinks, err := utils.ReadLinks(cfg.configLinksFile)
		if err != nil {
			return nil, err
		}
		links = append(links, fileLinks...)
	}
	readStdin := cfg.readFromSTDIN || (len(links) == 0 && cfg.configLinksFile == "" && !stdinIsTerminal())
	if readStdin && cfg.configLinksFile != "-" {
		stdinLinks, err := readStdinLinks(ctx, os.Stdin, stdinIsTerminal())
		if err != nil {
			return nil, err
		}
		links = append(links, stdinLinks...)
	}
	return links, nil
}

func newParseCommand() *cobra.Command {
	cfg := &parseCmdConfig{}

	cmd := &cobra.Command{
		Use:   "parse [link...]",
		Short: "Decode and display a detailed, human-readable breakdown of a proxy configuration link.",
		Long: `Decodes proxy share links and prints their fields.

Links can be given as arguments, with -c, from a file with -f ("-" for stdin),
or on stdin with -i (also read automatically when stdin is a pipe). With
--json, the full xray-core JSON configuration (with a default SOCKS inbound)
is printed for a single link; nothing else is written to stdout.

Examples:
  xray-knife parse "vless://..."
  xray-knife parse -f configs.txt
  cat configs.txt | xray-knife parse
  xray-knife parse -i --json < link.txt > config.json`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 && !cfg.readFromSTDIN && cfg.configLink == "" && cfg.configLinksFile == "" && stdinIsTerminal() {
				return cmd.Help()
			}

			links, err := collectLinks(cmd.Context(), cfg, args)
			if err != nil {
				return err
			}
			if len(links) == 0 {
				return fmt.Errorf("no config links provided or found")
			}

			if cfg.outputJSON {
				if len(links) > 1 {
					return fmt.Errorf("--json only supports one config link at a time (got %d)", len(links))
				}
				return generateAndPrintXrayJSON(links[0])
			}

			c := core.NewAutomaticCore(true, true)

			d := color.New(color.FgCyan, color.Bold)
			failed := 0
			for i, link := range links {
				if len(links) > 1 {
					d.Printf("Config Number: %d\n", i+1)
				}

				fmt.Printf("\n")
				p, err := c.CreateProtocol(link)
				if err == nil {
					err = p.Parse()
				}
				if err != nil {
					failed++
					customlog.Printf(customlog.Failure, "Link %d could not be parsed: %v\n", i+1, err)
					continue
				}

				fmt.Println(p.DetailsStr())
			}
			if failed > 0 {
				return fmt.Errorf("%d of %d link(s) could not be parsed", failed, len(links))
			}
			return nil
		},
	}

	cmd.Flags().BoolVarP(&cfg.readFromSTDIN, "stdin", "i", false, "Read config links from stdin (one per line)")
	cmd.Flags().StringVarP(&cfg.configLink, "config", "c", "", "The config link")
	cmd.Flags().StringVarP(&cfg.configLinksFile, "file", "f", "", "Read config links from a file (\"-\" for stdin)")
	cmd.Flags().BoolVarP(&cfg.outputJSON, "json", "j", false, "Output full xray-core JSON configuration with a default inbound")
	return cmd
}
