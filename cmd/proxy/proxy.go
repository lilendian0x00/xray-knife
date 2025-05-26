package proxy

import (
	"bufio"
	"fmt"
	"math/rand"
	"os"
	"os/signal"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/lilendian0x00/xray-knife/v3/cmd/net"
	"github.com/lilendian0x00/xray-knife/v3/pkg"
	"github.com/lilendian0x00/xray-knife/v3/pkg/protocol"
	"github.com/lilendian0x00/xray-knife/v3/pkg/singbox"
	pkGxray "github.com/lilendian0x00/xray-knife/v3/pkg/xray" // Alias to avoid conflict
	"github.com/lilendian0x00/xray-knife/v3/utils"
	"github.com/lilendian0x00/xray-knife/v3/utils/customlog"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

// proxyCmdConfig holds the configuration for the proxy command
type proxyCmdConfig struct {
	CoreType            string
	interval            uint32
	configLinksFile     string
	readConfigFromSTDIN bool
	listenAddr          string
	listenPort          string
	configLink          string
	verbose             bool
	insecureTLS         bool
	chainOutbounds      bool // This flag is defined but seems unused in the core logic
	maximumAllowedDelay uint16
}

// ProxyCmd represents the proxy command
var ProxyCmd = newProxyCommand()

func newProxyCommand() *cobra.Command {
	cfg := &proxyCmdConfig{}

	cmd := &cobra.Command{
		Use:   "proxy",
		Short: "Creates proxy server",
		Long:  ``,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) < 1 && (!cfg.readConfigFromSTDIN && cfg.configLink == "" && cfg.configLinksFile == "") {
				cmd.Help()
				return nil
			}

			var core pkg.Core
			var inbound protocol.Protocol

			switch cfg.CoreType {
			case "xray":
				core = pkg.CoreFactory(pkg.XrayCoreType, cfg.insecureTLS, cfg.verbose)
				// Ensure correct type assertion or use the specific struct if known
				inbound = &pkGxray.Socks{ // Use alias for xray package's Socks
					Remark:  "Listener",
					Address: cfg.listenAddr,
					Port:    cfg.listenPort,
				}
			case "singbox":
				core = pkg.CoreFactory(pkg.SingboxCoreType, cfg.insecureTLS, cfg.verbose)
				inbound = &singbox.Socks{
					Remark:  "Listener",
					Address: cfg.listenAddr,
					Port:    cfg.listenPort,
				}
			default:
				return fmt.Errorf("allowed core types: (xray, singbox), got: %s", cfg.CoreType)
			}

			inErr := core.SetInbound(inbound)
			if inErr != nil {
				return fmt.Errorf("failed to set inbound: %w", inErr)
			}

			r := rand.New(rand.NewSource(time.Now().Unix()))
			var links []string
			var parsedConfigs []protocol.Protocol

			if cfg.readConfigFromSTDIN {
				reader := bufio.NewReader(os.Stdin)
				fmt.Println("Reading config from STDIN:")
				text, err := reader.ReadString('\n')
				if err != nil {
					return fmt.Errorf("error reading config from stdin: %w", err)
				}
				links = append(links, text)
			} else if cfg.configLink != "" {
				links = append(links, cfg.configLink)
			} else if cfg.configLinksFile != "" {
				links = utils.ParseFileByNewline(cfg.configLinksFile)
			}

			if len(links) == 0 {
				return fmt.Errorf("no configuration links provided or found")
			}

			for _, cLink := range links {
				trimmedLink := strings.TrimSpace(cLink)
				if trimmedLink == "" {
					continue
				}
				conf, err := core.CreateProtocol(trimmedLink)
				if err != nil {
					customlog.Printf(customlog.Failure, "Couldn't parse the config %s: %v\n", trimmedLink, err)
					continue // Skip unparseable configs
				}
				parsedConfigs = append(parsedConfigs, conf)
			}

			if len(parsedConfigs) == 0 {
				return fmt.Errorf("no valid configs could be parsed from the provided sources")
			}

			utils.ClearTerminal()

			examinerOpts := pkg.Options{
				CoreInstance:           core,
				MaxDelay:               cfg.maximumAllowedDelay,
				Verbose:                cfg.verbose, // Pass proxy's verbose to examiner
				InsecureTLS:            cfg.insecureTLS,
				TestEndpoint:           "https://cloudflare.com/cdn-cgi/trace", // Default, can be exposed if needed
				TestEndpointHttpMethod: "GET",
				// Speedtest options can be added if proxy needs to perform them internally
			}
			examiner, errExaminer := pkg.NewExaminer(examinerOpts)
			if errExaminer != nil {
				return fmt.Errorf("failed to create examiner: %w", errExaminer)
			}

			fmt.Println(color.RedString("\n==========INBOUND=========="))
			fmt.Printf("%v", inbound.DetailsStr())
			fmt.Println(color.RedString("============================\n"))

			var currentInstance protocol.Instance
			var err error // Local error variable for loops/functions

			signalChannel := make(chan os.Signal, 1)
			signal.Notify(signalChannel, os.Interrupt, syscall.SIGINT)

			go func() {
				sig := <-signalChannel
				customlog.Printf(customlog.Processing, "Received signal: %v\n", sig)
				customlog.Printf(customlog.Processing, "Closing core service...")
				if currentInstance != nil {
					_ = currentInstance.Close() // Best effort
				}
				os.Exit(0) // Graceful shutdown on signal
			}()

			if len(links) > 1 { // Use original links count for rotation logic
				// This net.Config is for the ResultProcessor, which is part of the TestManager.
				// If proxy rotation doesn't *save* test results itself, this part could be simplified.
				// Assuming TestManager needs it for internal processing:
				netTestConfig := &net.Config{
					OutputType: "txt", // Default, or expose flags for these too
				}
				processor := net.NewResultProcessor(netTestConfig)

				customlog.Printf(customlog.Processing, "Looking for a working outbound config...\n")

				connectAndRun := func() error {
					var lastConfigLink string
					var activeOutbound protocol.Protocol

					testCount := 25
					if len(links) < testCount {
						testCount = len(links)
					}
					if testCount == 0 {
						return fmt.Errorf("no links available to test for proxy rotation")
					}

					// Find an initial working config
					for activeOutbound == nil {
						r.Shuffle(len(links), func(i, j int) { links[i], links[j] = links[j], links[i] })

						linksToTest := links
						if len(links) >= testCount {
							linksToTest = links[:testCount]
						}
						if len(linksToTest) == 0 {
							customlog.Printf(customlog.Processing, "No links to test in current batch, waiting...\n")
							time.Sleep(10 * time.Second) // Avoid tight loop if all links exhausted or problematic
							continue
						}

						// Use cfg.verbose for TestManager if deeper insight into testing is needed
						testManager := net.NewTestManager(examiner, processor, 50, false)
						results := testManager.TestConfigs(linksToTest)
						sort.Sort(results) // Sorts by delay (fastest first)

						foundNew := false
						for _, res := range results {
							if res.ConfigLink != lastConfigLink && res.Status == "passed" && res.Protocol != nil {
								activeOutbound = res.Protocol
								lastConfigLink = res.ConfigLink
								foundNew = true
								break
							}
						}
						if !foundNew {
							customlog.Printf(customlog.Processing, "Could not find a new working config in this batch, retrying or waiting...\n")
							// Add a small delay to prevent hammering if no configs work
							time.Sleep(5 * time.Second)
						}
					}
					if activeOutbound == nil {
						return fmt.Errorf("failed to find any working outbound configuration")
					}

					fmt.Println(color.RedString("==========OUTBOUND=========="))
					fmt.Printf("%v", activeOutbound.DetailsStr())
					fmt.Println(color.RedString("============================"))

					instance, err := core.MakeInstance(activeOutbound)
					if err != nil {
						return fmt.Errorf("error making core instance with '%s': %w", lastConfigLink, err)
					}
					currentInstance = instance // Store for cleanup

					err = currentInstance.Start()
					if err != nil {
						currentInstance.Close() // Attempt cleanup
						currentInstance = nil
						return fmt.Errorf("error starting core instance with '%s': %w", lastConfigLink, err)
					}
					customlog.Printf(customlog.Success, "Started listening for new connections...")
					fmt.Printf("\n")

					// Timer and input logic
					clickChan := make(chan bool, 1)
					finishChan := make(chan bool, 1)
					timeout := time.Duration(cfg.interval) * time.Second

					// Goroutine for countdown display
					go func() {
						ticker := time.NewTicker(time.Second)
						defer ticker.Stop()
						endTime := time.Now().Add(timeout)
						for {
							select {
							case <-finishChan:
								return
							case <-ticker.C:
								remaining := endTime.Sub(time.Now())
								if remaining < 0 {
									remaining = 0
								}
								fmt.Printf("\r%s", color.YellowString("[>] Enter to load the next config [Reloading in %v] >>> ", remaining.Round(time.Second)))
								if remaining == 0 {
									// Ensure the select in the main part of connectAndRun can timeout
									return
								}
							}
						}
					}()

					// Goroutine for Enter key press
					go func() {
						consoleReader := bufio.NewReaderSize(os.Stdin, 1)
						// Non-blocking read attempt or a way to interrupt it
						for {
							select {
							case <-finishChan: // If main loop signals finish (e.g. timeout)
								return
							default:
								// This can block, making the goroutine unresponsive to finishChan if stdin isn't providing input
								// A more robust way would involve select with a quit channel for this goroutine too.
								// For simplicity, keeping as is, but it's a known limitation.
								// Consider os.Stdin.SetReadDeadline for a more advanced solution.
								input, readErr := consoleReader.ReadByte()
								if readErr != nil { // EOF or other error
									return // Exit goroutine on read error
								}
								if input == 13 || input == 10 { // Enter or LF
									clickChan <- true
									return
								}
							}
						}
					}()

					select {
					case <-clickChan:
						customlog.Printf(customlog.Processing, "\nEnter pressed, switching config...\n")
					case <-time.After(timeout):
						customlog.Printf(customlog.Processing, "\nInterval reached, switching config...\n")
					}
					// Signal goroutines to stop
					close(finishChan) // Better to use close to signal multiple goroutines

					return nil // Indicate successful run for this interval
				} // End of connectAndRun

				for { // Main rotation loop
					if currentInstance != nil {
						customlog.Printf(customlog.Processing, "Closing current outbound instance...\n")
						errClose := currentInstance.Close()
						if errClose != nil {
							customlog.Printf(customlog.Failure, "Error closing instance: %v\n", errClose)
							// Potentially a more serious error, but attempt to continue
						}
						currentInstance = nil
					}

					customlog.Printf(customlog.Processing, "Attempting to connect to a new outbound...\n")
					err = connectAndRun()
					if err != nil {
						customlog.Printf(customlog.Failure, "Error in connection cycle: %v. Retrying rotation after a delay...\n", err)
						// Depending on the error, might want to exit or have a more sophisticated retry
						time.Sleep(10 * time.Second) // Wait before retrying the whole cycle
					}
					// Loop continues to the next rotation
				}

			} else { // Single config mode (using the first successfully parsed config)
				singleOutbound := parsedConfigs[0]

				fmt.Println(color.RedString("==========OUTBOUND=========="))
				fmt.Printf("%v", singleOutbound.DetailsStr())
				fmt.Println(color.RedString("============================"))

				instance, err := core.MakeInstance(singleOutbound)
				if err != nil {
					return fmt.Errorf("error making instance with single config: %w", err)
				}
				currentInstance = instance

				err = currentInstance.Start()
				if err != nil {
					currentInstance.Close() // Attempt cleanup
					return fmt.Errorf("error starting instance with single config: %w", err)
				}
				customlog.Printf(customlog.Success, "Started listening for new connections...")
				fmt.Printf("\n")
				select {} // Keep running indefinitely until signal
			}
			// This part should ideally not be reached in normal operation due to infinite loops/selects
			// return nil
		},
	}

	cmd.Flags().BoolVarP(&cfg.readConfigFromSTDIN, "stdin", "i", false, "Read config link from STDIN")
	cmd.Flags().StringVarP(&cfg.configLinksFile, "file", "f", "", "Read config links from a file")
	cmd.Flags().Uint32VarP(&cfg.interval, "interval", "t", 300, "Interval to change outbound connection in seconds (for multiple configs)")
	cmd.Flags().Uint16VarP(&cfg.maximumAllowedDelay, "mdelay", "d", 3000, "Maximum allowed delay (ms) for testing configs during rotation")

	cmd.Flags().StringVarP(&cfg.CoreType, "core", "z", "singbox", "Core types: (xray, singbox)")

	cmd.Flags().StringVarP(&cfg.listenAddr, "addr", "a", "127.0.0.1", "Listen ip address for the proxy server")
	cmd.Flags().StringVarP(&cfg.listenPort, "port", "p", "9999", "Listen port number for the proxy server")
	cmd.Flags().StringVarP(&cfg.configLink, "config", "c", "", "The single xray/sing-box config link to use")

	cmd.Flags().BoolVarP(&cfg.verbose, "verbose", "v", false, "Enable verbose logging for the selected core")
	cmd.Flags().BoolVarP(&cfg.insecureTLS, "insecure", "e", false, "Allow insecure TLS connections (e.g., self-signed certs, skip verify)")

	cmd.Flags().BoolVarP(&cfg.chainOutbounds, "chain", "n", false, "Chain multiple outbounds (This feature is not currently implemented)")

	return cmd
}
