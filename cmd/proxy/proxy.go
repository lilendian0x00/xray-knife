package proxy

import (
	"bufio"
	"context" // Added for managing goroutine lifecycles
	"errors"
	"fmt"
	"io"
	"math/rand"
	"os"
	"os/signal"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/lilendian0x00/xray-knife/v5/cmd/http"
	"github.com/xtls/xray-core/common/uuid"

	"github.com/lilendian0x00/xray-knife/v5/pkg"
	"github.com/lilendian0x00/xray-knife/v5/pkg/protocol"
	"github.com/lilendian0x00/xray-knife/v5/pkg/singbox"
	pkGxray "github.com/lilendian0x00/xray-knife/v5/pkg/xray" // Alias to avoid conflict
	"github.com/lilendian0x00/xray-knife/v5/utils"
	"github.com/lilendian0x00/xray-knife/v5/utils/customlog"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

const (
	BatchAmount = 50 // Number of configs to test in one batch
)

// proxyCmdConfig holds the configuration for the proxy command
type proxyCmdConfig struct {
	CoreType            string
	rotationInterval    uint32
	inboundProtocol     string
	inboundTransport    string
	inboundUUID         string
	mode                string
	configLinksFile     string
	readConfigFromSTDIN bool
	listenAddr          string
	listenPort          string
	configLink          string
	verbose             bool
	insecureTLS         bool
	chainOutbounds      bool
	maximumAllowedDelay uint16
	inboundConfigLink   string
}

var InboundProtocols = []string{"vless", "vmess", "socks"}

// ProxyCmd represents the proxy command
var ProxyCmd = newProxyCommand()

// findAndStartWorkingConfig attempts to find a working configuration from the list,
// starts it, and returns the instance and its link.
func findAndStartWorkingConfig(
	cfg *proxyCmdConfig,
	core pkg.Core,
	examiner *pkg.Examiner,
	processor *http.ResultProcessor,
	allLinks []string,
	r *rand.Rand,
	lastUsedLink string,
) (protocol.Instance, string, error) {
	var activeOutbound protocol.Protocol
	var activeOutboundLink string

	if len(allLinks) == 0 {
		return nil, "", fmt.Errorf("no configuration links available to test")
	}

	// Create a mutable copy for shuffling
	availableLinks := make([]string, len(allLinks))
	copy(availableLinks, allLinks)

	maxAttemptsToFindWorkingConfig := 3 // Try a few broad attempts if the first batch fails
	for attempt := 0; attempt < maxAttemptsToFindWorkingConfig; attempt++ {
		r.Shuffle(len(availableLinks), func(i, j int) { availableLinks[i], availableLinks[j] = availableLinks[j], availableLinks[i] })

		testCount := BatchAmount
		if len(availableLinks) < testCount {
			testCount = len(availableLinks)
		}
		if testCount == 0 {
			customlog.Printf(customlog.Processing, "No links left to test in current attempt.\n")
			if attempt < maxAttemptsToFindWorkingConfig-1 {
				time.Sleep(5 * time.Second) // Wait before next major attempt
			}
			continue
		}

		linksToTestThisRound := availableLinks[:testCount]
		customlog.Printf(customlog.Processing, "Testing a batch of %d configs (Attempt %d/%d)...\n", len(linksToTestThisRound), attempt+1, maxAttemptsToFindWorkingConfig)

		testManager := http.NewTestManager(examiner, processor, 50, false) // Verbosity for TM itself
		results := testManager.TestConfigs(linksToTestThisRound, false)
		sort.Sort(results) // Sorts by delay (fastest first)

		foundNewWorkingConfig := false
		for _, res := range results {
			if res.Status == "passed" && res.Protocol != nil && res.ConfigLink != lastUsedLink {
				activeOutbound = res.Protocol
				activeOutboundLink = res.ConfigLink
				customlog.Printf(customlog.Success, "Found working config: %s (Delay: %dms)\n", res.ConfigLink, res.Delay)
				foundNewWorkingConfig = true
				break
			}
		}

		if foundNewWorkingConfig {
			break // Exit attempt loop, we found one
		} else {
			customlog.Printf(customlog.Processing, "No new working config found in this batch.\n")
			if attempt < maxAttemptsToFindWorkingConfig-1 {
				customlog.Printf(customlog.Processing, "Waiting before trying next batch...\n")
				time.Sleep(5 * time.Second)
			}
		}
	}

	if activeOutbound == nil {
		return nil, "", fmt.Errorf("failed to find any working outbound configuration after %d attempts", maxAttemptsToFindWorkingConfig)
	}

	fmt.Println(color.RedString("==========OUTBOUND=========="))
	fmt.Printf("%v", activeOutbound.DetailsStr())
	fmt.Println(color.RedString("============================"))

	instance, err := core.MakeInstance(activeOutbound)
	if err != nil {
		return nil, activeOutboundLink, fmt.Errorf("error making core instance with '%s': %w", activeOutboundLink, err)
	}

	err = instance.Start()
	if err != nil {
		instance.Close() // Attempt cleanup
		return nil, activeOutboundLink, fmt.Errorf("error starting core instance with '%s': %w", activeOutboundLink, err)
	}

	return instance, activeOutboundLink, nil
}

// manageActiveProxyPeriod handles the timer and user input for the currently active proxy.
// It returns an error (e.g., "timer expired", "user input") to signal why rotation should occur.
// It also takes a parent context to allow cancellation from the main signal handler.
func manageActiveProxyPeriod(parentCtx context.Context, cfg *proxyCmdConfig) error {
	customlog.Printf(customlog.Success, "Instance active. Interval: %ds. Press Enter to switch.\n", cfg.rotationInterval)

	// Derive a new context from parent for this specific active period.
	// This allows manageActiveProxyPeriod to manage its own goroutines cleanly.
	ctx, cancel := context.WithCancel(parentCtx)
	defer cancel() // Signal local goroutines to stop when this function returns

	inputChan := make(chan bool, 1) // Signals that Enter was pressed
	timer := time.NewTimer(time.Duration(cfg.rotationInterval) * time.Second)
	defer timer.Stop() // Clean up the timer

	// Goroutine for Enter key press
	go func() {
		defer customlog.Printf(customlog.Processing, "Input listener goroutine stopped.\n")
		consoleReader := bufio.NewReaderSize(os.Stdin, 1)

		// Goroutine to perform the blocking read and send result/error on channels
		readResultChan := make(chan byte)
		readErrChan := make(chan error)
		go func() {
			defer close(readResultChan) // Important for select below to not hang if this goroutine exits
			defer close(readErrChan)
			input, err := consoleReader.ReadByte() // This blocks
			if err != nil {
				select {
				case readErrChan <- err:
				case <-ctx.Done(): // If context is cancelled while trying to send error
				}
				return
			}
			select {
			case readResultChan <- input:
			case <-ctx.Done(): // If context is cancelled while trying to send result
			}
		}()

		// Select loop to wait for read result or context cancellation
		select {
		case <-ctx.Done(): // If the main function cancels this active period
			return
		case input, ok := <-readResultChan:
			if ok && (input == 13 || input == 10) { // Enter or LF
				select {
				case inputChan <- true:
				case <-ctx.Done(): // Don't block if context is already done
				}
			} else if !ok {
				// readResultChan was closed, possibly due to error in ReadByte
			}
		case err := <-readErrChan:
			if err != nil {
				customlog.Printf(customlog.Failure, "Error reading input: %v. Input listener stopping.\n", err)
			}
			return
		}
	}()

	// Goroutine for countdown display
	displayTicker := time.NewTicker(time.Second)
	defer displayTicker.Stop()
	endTime := time.Now().Add(time.Duration(cfg.rotationInterval) * time.Second)

	updateDisplay := func() { // Function to update the display
		remaining := endTime.Sub(time.Now())
		if remaining < 0 {
			remaining = 0
		}
		// Ensure terminal output is clear for the prompt
		fmt.Printf("\r%s\033[K", color.YellowString("[>] Enter to load the next config [Reloading in %v] >>> ", remaining.Round(time.Second)))
	}
	updateDisplay() // Initial display

	for {
		select {
		case <-ctx.Done(): // If the main function cancels this active period (e.g. SIGINT)
			fmt.Println() // New line after prompt
			return fmt.Errorf("active proxy period cancelled by signal or parent context")
		case <-inputChan:
			fmt.Println() // New line after prompt
			// cancel() // No need to call cancel() here, returning will trigger the defer cancel()
			return fmt.Errorf("user requested config switch")
		case <-timer.C:
			fmt.Println() // New line after prompt
			// cancel()
			return fmt.Errorf("interval timer expired")
		case <-displayTicker.C:
			updateDisplay()
		}
	}
}

func newProxyCommand() *cobra.Command {
	cfg := &proxyCmdConfig{}

	cmd := &cobra.Command{
		Use:   "proxy",
		Short: "Run a local inbound proxy that tunnels traffic through a remote configuration. Supports automatic rotation of outbound proxies.",
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) < 1 && (!cfg.readConfigFromSTDIN && cfg.configLink == "" && cfg.configLinksFile == "") {
				cmd.Help()
				return nil
			}

			u := uuid.New()
			var core pkg.Core
			var inbound protocol.Protocol
			var err error

			// Instantiate core based on type first. This is needed for creating protocols from links.
			switch cfg.CoreType {
			case "xray":
				core = pkg.CoreFactory(pkg.XrayCoreType, cfg.insecureTLS, cfg.verbose)
			case "sing-box":
				core = pkg.CoreFactory(pkg.SingboxCoreType, cfg.insecureTLS, cfg.verbose)
			default:
				return fmt.Errorf("allowed core types: (xray, singbox), got: %s", cfg.CoreType)
			}

			// If a custom inbound config link is provided, use it to create the inbound.
			if cfg.inboundConfigLink != "" {
				inbound, err = core.CreateProtocol(cfg.inboundConfigLink)
				if err != nil {
					return fmt.Errorf("failed to create inbound from config link: %w", err)
				}
				if err := inbound.Parse(); err != nil {
					return fmt.Errorf("failed to parse inbound config link: %w", err)
				}
			} else {
				switch cfg.mode {
				case "inbound":
					switch cfg.CoreType {
					case "xray":
						switch cfg.inboundProtocol {
						case "socks":
							user, errUsr := utils.GeneratePassword(4)
							if errUsr != nil {
								return errUsr
							}

							pass, errPass := utils.GeneratePassword(4)
							if errPass != nil {
								return errPass
							}

							inbound = &pkGxray.Socks{
								Remark:   "Listener",
								Address:  cfg.listenAddr,
								Port:     cfg.listenPort,
								Username: user,
								Password: pass,
							}
							break
						case "vmess":
							uuidv4 := cfg.inboundUUID
							if cfg.inboundUUID == "random" {
								uuidv4 = u.String()
							}
							switch cfg.inboundTransport {
							case "xhttp":
								inbound = &pkGxray.Vmess{
									Remark:   "Listener",
									Address:  cfg.listenAddr,
									Port:     cfg.listenPort,
									Network:  "xhttp",
									Host:     "snapp.ir",
									Path:     "/",
									Security: "none",
									ID:       uuidv4,
								}
							case "tcp":
								inbound = &pkGxray.Vmess{
									Remark:  "Listener",
									Address: cfg.listenAddr,
									Port:    cfg.listenPort,
									Type:    "tcp",
									ID:      uuidv4,
								}
							}
							break

						case "vless":
							uuidv4 := cfg.inboundUUID
							if cfg.inboundUUID == "random" {
								uuidv4 = u.String()
							}
							switch cfg.inboundTransport {
							case "xhttp":
								inbound = &pkGxray.Vless{
									Remark:   "Listener",
									Address:  cfg.listenAddr,
									Port:     cfg.listenPort,
									Type:     "xhttp",
									Host:     "snapp.ir",
									Path:     "/",
									Security: "none",
									ID:       uuidv4,
									Mode:     "auto",
								}
							case "tcp":
								inbound = &pkGxray.Vless{
									Remark:  "Listener",
									Address: cfg.listenAddr,
									Port:    cfg.listenPort,
									Type:    "tcp",
									ID:      uuidv4,
								}
							}
							break
						}

					case "sing-box":
						user, errUsr := utils.GeneratePassword(4)
						if errUsr != nil {
							return errUsr
						}
						pass, errPass := utils.GeneratePassword(4)
						if errPass != nil {
							return errPass
						}

						inbound = &singbox.Socks{
							Remark:   "Listener",
							Address:  cfg.listenAddr,
							Port:     cfg.listenPort,
							Username: user,
							Password: pass,
						}
					default:
						return fmt.Errorf("allowed core types: (xray, sing-box), got: %s", cfg.CoreType)
					}
				case "system":
					return errors.New(`mode "system" hasn't yet implemented`)
				default:
					return fmt.Errorf("unknown --mode %q (must be inbound|system)", cfg.mode)
				}
			}

			if inbound == nil {
				return fmt.Errorf("inbound configuration could not be created. Please provide an --inbound-config or use flags like --inbound, --port, etc")
			}

			inErr := core.SetInbound(inbound)
			if inErr != nil {
				return fmt.Errorf("failed to set inbound: %w", inErr)
			}

			r := rand.New(rand.NewSource(time.Now().Unix()))
			var links []string // Raw links from input
			//var parsedConfigs []protocol.Protocol // Parsed and validated configs

			if cfg.readConfigFromSTDIN {
				reader := bufio.NewReader(os.Stdin)
				fmt.Println("Reading config from STDIN:")
				var err error
				var line []byte
				for err == nil {
					line, _, err = reader.ReadLine()
					links = append(links, string(line))
				}
				if !errors.Is(err, io.EOF) {
					return err
				}
			} else if cfg.configLink != "" {
				links = append(links, cfg.configLink)
			} else if cfg.configLinksFile != "" {
				links = utils.ParseFileByNewline(cfg.configLinksFile)
			}

			if len(links) == 0 {
				return fmt.Errorf("no configuration links provided or found")
			}

			// Filter out empty or unparseable links once at the beginning
			var validRawLinks []string
			for _, cLink := range links {
				trimmedLink := strings.TrimSpace(cLink)
				if trimmedLink == "" {
					continue
				}
				// Basic pre-validation if needed, or let CreateProtocol handle it
				validRawLinks = append(validRawLinks, trimmedLink)
			}

			if len(validRawLinks) == 0 {
				return fmt.Errorf("no valid (non-empty) configuration links found")
			}
			links = validRawLinks // Update links to only contain non-empty, trimmed strings

			examinerOpts := pkg.Options{
				// CoreInstance: core, // Examiner can create its own core or use one if passed for specific tests
				Core:                   cfg.CoreType, // Let examiner pick based on config
				MaxDelay:               cfg.maximumAllowedDelay,
				Verbose:                cfg.verbose, // Pass proxy's verbose to examiner for its own logging
				InsecureTLS:            cfg.insecureTLS,
				TestEndpoint:           "https://cloudflare.com/cdn-cgi/trace",
				TestEndpointHttpMethod: "GET",
				// Add speedtest options if examiner needs to do speedtests when selecting proxy
				DoSpeedtest: false, // Assuming proxy rotation doesn't need speedtest for selection
			}
			examiner, errExaminer := pkg.NewExaminer(examinerOpts)
			if errExaminer != nil {
				return fmt.Errorf("failed to create examiner: %w", errExaminer)
			}

			fmt.Println(color.RedString("\n==========INBOUND=========="))
			fmt.Printf("%v%s: %v\n", inbound.DetailsStr(), color.RedString("Link"), inbound.GetLink())
			fmt.Println(color.RedString("============================\n"))

			// Context for the main proxy loop, cancelled by SIGINT
			mainLoopCtx, mainLoopCancel := context.WithCancel(context.Background())
			defer mainLoopCancel()

			signalChannel := make(chan os.Signal, 1)
			signal.Notify(signalChannel, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)

			// Goroutine to handle OS signals and cancel the mainLoopCtx
			go func() {
				sig := <-signalChannel
				customlog.Printf(customlog.Processing, "Received signal: %v. Shutting down...\n", sig)
				mainLoopCancel() // Cancel the main proxy loop context
			}()

			if len(links) > 1 { // Rotation mode
				netTestConfig := &http.Config{OutputType: "txt"} // For ResultProcessor in TestManager
				processor := http.NewResultProcessor(netTestConfig)
				var currentInstance protocol.Instance
				var currentLink string

				for { // Main rotation loop
					select {
					case <-mainLoopCtx.Done():
						customlog.Printf(customlog.Processing, "Main proxy loop exiting due to signal.\n")
						if currentInstance != nil {
							customlog.Printf(customlog.Processing, "Closing final active instance...\n")
							_ = currentInstance.Close()
						}
						return nil // Normal exit on signal
					default:
						// Proceed with rotation
					}

					if currentInstance != nil {
						customlog.Printf(customlog.Processing, "Closing current outbound instance for link: %s\n", currentLink)
						errClose := currentInstance.Close()
						if errClose != nil {
							customlog.Printf(customlog.Failure, "Error closing instance: %v\n", errClose)
						}
						currentInstance = nil
						currentLink = ""
					}

					customlog.Printf(customlog.Processing, "Attempting to find and start a new outbound...\n")
					newInstance, newLink, errConnect := findAndStartWorkingConfig(
						cfg, core, examiner, processor, links, r, currentLink, /* pass last used link */
					)
					if errConnect != nil {
						customlog.Printf(customlog.Failure, "Error finding/starting config: %v. Retrying rotation after delay...\n", errConnect)
						select {
						case <-time.After(10 * time.Second): // Wait before retrying
						case <-mainLoopCtx.Done(): // If signalled during wait
							customlog.Printf(customlog.Processing, "Shutdown signalled during retry delay.\n")
							return nil
						}
						continue // Retry finding a config
					}
					currentInstance = newInstance
					currentLink = newLink
					customlog.Printf(customlog.Success, "Successfully started instance\n")

					// Manage the active period for currentInstance
					// Pass mainLoopCtx so manageActiveProxyPeriod can also be cancelled by SIGINT
					errActive := manageActiveProxyPeriod(mainLoopCtx, cfg)
					if errActive != nil {
						customlog.Printf(customlog.Processing, "Switching config. Reason: %v\n", errActive)
						// The loop will now close currentInstance and find a new one
						// If errActive is due to mainLoopCtx.Done(), the next iteration's select will catch it.
					} else {
						// This case should ideally not be reached if manageActiveProxyPeriod always signals rotation
						customlog.Printf(customlog.Processing, "manageActiveProxyPeriod returned nil, implies clean exit. Shutting down.\n")
						mainLoopCancel() // Ensure everything winds down
					}
				}
			} else { // Single config mode
				singleLink := links[0]
				outboundParsed, err := core.CreateProtocol(singleLink)
				if err != nil {
					return fmt.Errorf("couldn't parse the single config %s: %w", singleLink, err)
				}
				err = outboundParsed.Parse()
				if err != nil {
					return fmt.Errorf("failed to parse single outbound config: %w", err)
				}

				fmt.Println(color.RedString("==========OUTBOUND=========="))
				fmt.Printf("%v%s: %v\n", outboundParsed.DetailsStr(), color.RedString("Link"), outboundParsed.GetLink())
				fmt.Println(color.RedString("============================"))

				instance, err := core.MakeInstance(outboundParsed)
				if err != nil {
					return fmt.Errorf("error making instance with single config: %w", err)
				}
				defer instance.Close() // Ensure instance is closed on exit

				err = instance.Start()
				if err != nil {
					return fmt.Errorf("error starting instance with single config: %w", err)
				}
				customlog.Printf(customlog.Success, "Started listening for new connections with single config...")
				fmt.Printf("\n")

				// Wait for context cancellation (SIGINT)
				<-mainLoopCtx.Done()
				customlog.Printf(customlog.Processing, "Shutting down single config proxy due to signal.\n")
				return nil
			}
		},
	}

	cmd.Flags().BoolVarP(&cfg.readConfigFromSTDIN, "stdin", "i", false, "Read config link from STDIN")
	cmd.Flags().StringVarP(&cfg.configLinksFile, "file", "f", "", "Read config links from a file")
	cmd.Flags().Uint32VarP(&cfg.rotationInterval, "rotate", "t", 300, "How often to rotate outbounds (seconds)")

	cmd.Flags().StringVarP(&cfg.listenAddr, "addr", "a", "127.0.0.1", "Listen ip address for the proxy server")
	cmd.Flags().StringVarP(&cfg.listenPort, "port", "p", "9999", "Listen port number for the proxy server")
	cmd.Flags().StringVarP(&cfg.inboundProtocol, "inbound", "j", "socks", "Inbound protocol to use (vless, vmess, socks)")
	cmd.Flags().StringVarP(&cfg.inboundTransport, "transport", "u", "tcp", "Inbound transport to use (tcp, xhttp)")
	cmd.Flags().StringVarP(&cfg.inboundUUID, "uuid", "g", "random", "Inbound custom UUID to use (default: random)")
	cmd.Flags().StringVarP(&cfg.mode, "mode", "m", "inbound", "proxy operating mode:  • inbound  – expose local SOCKS/HTTP listener (default)\n"+
		"                       • system   – create TUN device and route all host traffic through it")

	cmd.RegisterFlagCompletionFunc("mode", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return []string{"system", "inbound"}, cobra.ShellCompDirectiveNoFileComp
	})

	cmd.Flags().Uint16VarP(&cfg.maximumAllowedDelay, "mdelay", "d", 3000, "Maximum allowed delay (ms) for testing configs during rotation")

	cmd.Flags().StringVarP(&cfg.CoreType, "core", "z", "xray", "Core types: (xray, sing-box)")
	cmd.RegisterFlagCompletionFunc("core", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return []string{"xray", "sing-box"}, cobra.ShellCompDirectiveNoFileComp
	})
	cmd.Flags().StringVarP(&cfg.configLink, "config", "c", "", "The single xray/sing-box config link to use")
	cmd.Flags().StringVarP(&cfg.inboundConfigLink, "inbound-config", "I", "", "Custom config link for the inbound proxy")
	// only one can exist as they override each other. runtime error better than unexpected behavior
	cmd.MarkFlagsMutuallyExclusive("inbound-config", "mode", "inbound")

	cmd.Flags().BoolVarP(&cfg.verbose, "verbose", "v", false, "Enable verbose logging for the selected core")
	cmd.Flags().BoolVarP(&cfg.insecureTLS, "insecure", "e", false, "Allow insecure TLS connections (e.g., self-signed certs, skip verify)")

	cmd.Flags().BoolVarP(&cfg.chainOutbounds, "chain", "n", false, "Chain multiple outbounds (This feature is not currently implemented)")

	return cmd
}
