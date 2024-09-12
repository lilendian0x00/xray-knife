package proxy

import (
	"bufio"
	"fmt"
	"github.com/lilendian0x00/xray-knife/internal"
	"github.com/lilendian0x00/xray-knife/internal/protocol"
	"github.com/lilendian0x00/xray-knife/internal/singbox"
	"github.com/lilendian0x00/xray-knife/internal/xray"
	"log"
	"math/rand"
	"os"
	"os/signal"
	"sort"
	"syscall"
	"time"

	"github.com/fatih/color"
	"github.com/lilendian0x00/xray-knife/cmd/net"
	"github.com/lilendian0x00/xray-knife/utils"
	"github.com/lilendian0x00/xray-knife/utils/customlog"
	"github.com/spf13/cobra"
)

var (
	CoreType            string
	interval            uint32
	configLinksFile     string
	readConfigFromSTDIN bool
	listenAddr          string
	listenPort          string
	link                string
	verbose             bool
	insecureTLS         bool
	chainOutbounds      bool
	maximumAllowedDelay uint16
)

// ProxyCmd BotCmd represents the bot command
var ProxyCmd = &cobra.Command{
	Use:   "proxy",
	Short: "Creates proxy server",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) < 1 && (!readConfigFromSTDIN && link == "" && configLinksFile == "") {
			cmd.Help()
			return
		}

		var core internal.Core
		var inbound protocol.Protocol

		switch CoreType {
		case "xray":
			core = internal.CoreFactory(internal.XrayCoreType)

			inbound = &xray.Socks{
				Remark:  "Listener",
				Address: listenAddr,
				Port:    listenPort,
			}
			break
		case "singbox":
			core = internal.CoreFactory(internal.SingboxCoreType)

			inbound = &singbox.Socks{
				Remark:  "Listener",
				Address: listenAddr,
				Port:    listenPort,
			}
			break
		default:
			log.Fatalln("Allowed core types: (xray, singbox)")
		}

		inErr := core.SetInbound(inbound)
		if inErr != nil {
			log.Fatalln(inErr)
		}

		r := rand.New(rand.NewSource(time.Now().Unix()))
		var links []string
		var configs []protocol.Protocol

		if configLinksFile != "" {
			// Get configs from file
			links = utils.ParseFileByNewline(configLinksFile)

		} else if readConfigFromSTDIN {
			// Get config from STDIN
			reader := bufio.NewReader(os.Stdin)
			fmt.Println("Reading config from STDIN:")
			link, _ = reader.ReadString('\n')
			links = append(links, link)
		}

		// Parse all the links
		for _, c := range links {
			conf, err := core.CreateProtocol(c)
			if err != nil {
				log.Println(color.RedString("Couldn't parse the config : %v", err))
			}
			configs = append(configs, conf)
		}

		// Clear the terminal
		utils.ClearTerminal()

		// Make an examiner
		examiner, err1 := internal.NewExaminer(internal.Options{
			// TODO: Variable core
			CoreInstance: core,
			MaxDelay:     2000,
		})
		if err1 != nil {
			customlog.Printf(customlog.Failure, "%v", err1)
			os.Exit(1)
		}

		fmt.Println(color.RedString("\n==========INBOUND=========="))
		fmt.Printf("%v", inbound.DetailsStr())
		fmt.Println(color.RedString("============================\n"))

		var instance protocol.Instance = nil

		var err error

		// Create a channel to receive signals.
		signalChannel := make(chan os.Signal, 1)

		// Notify the signalChannel on receiving interrupt signals (e.g., Ctrl+C).
		signal.Notify(signalChannel, os.Interrupt, syscall.SIGINT)

		// Create a goroutine to handle the received signals.
		go func() {
			// Wait for a signal to be received.
			sig := <-signalChannel

			// Print the received signal.
			customlog.Printf(customlog.Processing, "Received signal: %v\n", sig)

			// Perform some actions before exiting.
			customlog.Printf(customlog.Processing, "Closing xray service...")

			// Close xray service
			if instance != nil {
				err := instance.Close()
				if err != nil {

				}
			}
			// Exit the program.
			os.Exit(0)
		}()

		if len(configs) > 1 {
			//var currentIndex int
			//var lastIndex int

			customlog.Printf(customlog.Processing, "Looking for a working outbound config...\n")

			connect := func() {
				var lastConfig string
				var currentConfig protocol.Protocol = nil

				// Decide how many configs we are going to test
				var testCount int = 25
				if len(links) < 25 {
					testCount = len(links)
				}
				for currentConfig == nil {
					// Shuffle all links
					r.Shuffle(len(links), func(i, j int) { links[i], links[j] = links[j], links[i] })
					results := net.HttpTestMultipleConfigs(examiner, links[0:testCount-1], 50, false)
					sort.Sort(results)
					for _, v := range results {
						if v.ConfigLink != lastConfig {
							currentConfig = v.Protocol
							lastConfig = v.ConfigLink
							break
						}
					}
				}

				fmt.Println(color.RedString("==========OUTBOUND=========="))
				fmt.Printf("%v", currentConfig.DetailsStr())
				fmt.Println(color.RedString("============================"))

				// Make xray instance
				instance, err = core.MakeInstance(currentConfig)
				if err != nil {
					customlog.Printf(customlog.Failure, "Error making a xray instance: %s\n", err.Error())
					// Remove config from slice if it doesn't work
					//configs = append(configs[:currentIndex], configs[currentIndex+1:]...)
				}

				// Start the xray instance
				err = instance.Start()
				if err != nil {
					customlog.Printf(customlog.Failure, "Error starting xray instance: %s\n", err.Error())
					// Remove config from slice if it doesn't work
					//configs = append(configs[:currentIndex], configs[currentIndex+1:]...)
				}
				customlog.Printf(customlog.Success, "Started listening for new connections...")
				fmt.Printf("\n")

				//time.Sleep(time.Duration(interval) * time.Second)

				clickChan := make(chan bool)
				defer close(clickChan)

				finishChan := make(chan bool)
				defer close(finishChan)

				timeout := time.Duration(interval) * time.Second

				go func() {
					// Timer
					ticker := time.NewTicker(time.Second)
					defer ticker.Stop()

					endTime := time.Now().Add(time.Duration(interval) * time.Second)

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

							break
						}
					}
				}()

				go func() {
					for {
						consoleReader := bufio.NewReaderSize(os.Stdin, 1)
						select {
						case <-time.After(timeout):
							return
						default:
							input, _ := consoleReader.ReadByte()
							ascii := input
							if ascii == 13 || ascii == 10 { // Enter => 13 || 10 MacOS Return
								finishChan <- true
								clickChan <- true
								return
							}
						}
					}
				}()

				select {
				case <-clickChan:
					return
				case <-time.After(timeout):
					finishChan <- true
					fmt.Printf("\n") // Need new line coz we got input
					return
				}
			}

			for {
				// The procedure of selecting a new outbound and starting it
				// Do it for the first time before first tick starts
				connect()

				customlog.Printf(customlog.Processing, "Switching outbound connection...\n")

				// Check if any core is running
				if instance != nil {
					err = instance.Close()
					if err != nil {
						log.Fatalf(err.Error())
					}
				}
			}
		} else {
			// Configuring outbound
			outboundParsed, err := core.CreateProtocol(link)
			if err != nil {
				log.Fatalf("Couldn't parse the config : %v", err)
			}

			err = outboundParsed.Parse()
			if err != nil {
				log.Fatalln(err.Error())
			}

			fmt.Println(color.RedString("==========OUTBOUND=========="))
			fmt.Printf("%v", outboundParsed.DetailsStr())
			fmt.Println(color.RedString("============================"))

			instance, err = core.MakeInstance(outboundParsed)
			if err != nil {
				log.Fatalln(err.Error())
			}

			// Start the xray instance
			err = instance.Start()
			if err != nil {
				log.Fatalln(err.Error())
			}
			customlog.Printf(customlog.Success, "Started listening for new connections...")
			fmt.Printf("\n")
			select {}
		}

	},
}

func init() {
	ProxyCmd.Flags().BoolVarP(&readConfigFromSTDIN, "stdin", "i", false, "Read config link from STDIN")
	ProxyCmd.Flags().StringVarP(&configLinksFile, "file", "f", "", "Read config links from a file")
	ProxyCmd.Flags().Uint32VarP(&interval, "interval", "t", 300, "Interval to change outbound connection in seconds")
	ProxyCmd.Flags().Uint16VarP(&maximumAllowedDelay, "mdelay", "d", 3000, "Maximum allowed delay")

	ProxyCmd.Flags().StringVarP(&CoreType, "core", "z", "singbox", "Core types: (xray, singbox)")

	ProxyCmd.Flags().StringVarP(&listenAddr, "addr", "a", "127.0.0.1", "Listen ip address")
	ProxyCmd.Flags().StringVarP(&listenPort, "port", "p", "9999", "Listen port number")
	ProxyCmd.Flags().StringVarP(&link, "config", "c", "", "The xray config link")

	ProxyCmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Verbose xray-core")
	ProxyCmd.Flags().BoolVarP(&insecureTLS, "insecure", "e", false, "Insecure tls connection (fake SNI)")

	ProxyCmd.Flags().BoolVarP(&chainOutbounds, "chain", "n", false, "Chain multiple outbounds")

}
