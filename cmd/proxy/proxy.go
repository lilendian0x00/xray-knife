package proxy

import (
	"bufio"
	"fmt"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/xtls/xray-core/core"
	"log"
	"math/rand"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"
	"xray-knife/utils"
	"xray-knife/utils/customlog"
	"xray-knife/xray"
)

var (
	interval            uint32
	configLinksFile     string
	readConfigFromSTDIN bool
	listenAddr          string
	listenPort          uint16
	link                string
	verbose             bool
	insecureTLS         bool
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
		r := rand.New(rand.NewSource(time.Now().Unix()))
		var links []string
		var configs []xray.Protocol

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
			conf, err := xray.ParseXrayConfig(c)
			if err != nil {
				log.Println(color.RedString("Couldn't parse the config : %v", err))
			}
			configs = append(configs, conf)
		}

		// Make the inbound
		inbound := &xray.Socks{
			Remark:  "Listener",
			Address: listenAddr,
			Port:    strconv.Itoa(int(listenPort)),
		}
		// Clear the terminal
		utils.ClearTerminal()
		// Make a new xray service
		xs := xray.NewXrayService(verbose, insecureTLS, xray.WithInbound(inbound))

		fmt.Println(color.RedString("\n==========INBOUND=========="))
		fmt.Printf("%v", inbound.DetailsStr())
		fmt.Println(color.RedString("============================\n"))

		var xrayInstance *core.Instance = nil
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
			if xrayInstance != nil {
				err := xrayInstance.Close()
				if err != nil {

				}
			}
			// Exit the program.
			os.Exit(0)
		}()

		if len(configs) > 1 {
			var currentIndex int
			var lastIndex int

			connect := func() {
				// Check for config availability
				if len(configs) > 1 {
					// If we have more have 1, then select another inside
					for currentIndex == lastIndex {
						currentIndex = r.Intn(len(configs))
					}
					lastIndex = currentIndex
				} else {
					// If we have 1 config then set the index to 0
					currentIndex = 0
				}

				fmt.Println(color.RedString("==========OUTBOUND=========="))
				fmt.Printf("%v", configs[currentIndex].DetailsStr())
				fmt.Println(color.RedString("============================"))

				// Make xray instance
				xrayInstance, err = xs.MakeXrayInstance(configs[currentIndex])
				if err != nil {
					log.Println(err.Error())
					// Remove config from slice if it doesn't work
					configs = append(configs[:currentIndex], configs[currentIndex+1:]...)
				}

				// Start the xray instance
				err = xrayInstance.Start()
				if err != nil {
					log.Println(err.Error())
					// Remove config from slice if it doesn't work
					configs = append(configs[:currentIndex], configs[currentIndex+1:]...)
				}
				customlog.Printf(customlog.Success, "Started listening for new connections...")
				fmt.Printf("\n")
			}
			// The procedure of selecting a new outbound and starting it
			connect()

			// A ticker for the interval in which the outbound changes
			ticker := time.NewTicker(time.Duration(interval) * time.Second)
			for range ticker.C {
				customlog.Printf(customlog.Processing, "Switching outbound connection...\n")

				// Check if any xrayInstance is running
				if xrayInstance != nil {
					err = xrayInstance.Close()
					if err != nil {
						log.Fatalf(err.Error())
					}
				}

				// The procedure of selecting a new outbound and starting it
				// Do it for the first time before first tick starts
				connect()
			}
		} else {
			// Configuring outbound
			outboundParsed, err := xray.ParseXrayConfig(link)
			if err != nil {
				log.Fatalf("Couldn't parse the config : %v", err)
			}
			fmt.Println(color.RedString("==========OUTBOUND=========="))
			fmt.Printf("%v", outboundParsed.DetailsStr())
			fmt.Println(color.RedString("============================"))

			// Make xray instance
			xrayInstance, err = xs.MakeXrayInstance(outboundParsed)
			if err != nil {
				log.Fatalln(err.Error())
			}

			// Start the xray instance
			err = xrayInstance.Start()
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

	ProxyCmd.Flags().StringVarP(&listenAddr, "addr", "a", "127.0.0.1", "Listen ip address")
	ProxyCmd.Flags().Uint16VarP(&listenPort, "port", "p", 9999, "Listen port number")
	ProxyCmd.Flags().StringVarP(&link, "config", "c", "", "The xray config link")

	ProxyCmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Verbose xray-core")
	ProxyCmd.Flags().BoolVarP(&insecureTLS, "insecure", "e", false, "Insecure tls connection (fake SNI)")

}
