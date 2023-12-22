package proxy

import (
	"bufio"
	"fmt"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"log"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"xray-knife/utils"
	"xray-knife/xray"
)

var (
	readConfigFromSTDIN bool

	listenAddr  string
	listenPort  uint16
	link        string
	verbose     bool
	insecureTLS bool
)

// ProxyCmd BotCmd represents the bot command
var ProxyCmd = &cobra.Command{
	Use:   "proxy",
	Short: "Creates proxy server",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) < 1 && readConfigFromSTDIN != true && link == "" {
			cmd.Help()
			return
		}
		if readConfigFromSTDIN {
			reader := bufio.NewReader(os.Stdin)
			fmt.Println("Reading config from STDIN:")
			link, _ = reader.ReadString('\n')
		}

		inbound := &xray.Socks{
			Remark:  "Listener",
			Address: listenAddr,
			Port:    strconv.Itoa(int(listenPort)),
		}
		utils.ClearTerminal()
		xs := xray.NewXrayService(verbose, insecureTLS, xray.WithInbound(inbound))

		fmt.Println(color.RedString("\n==========INBOUND=========="))
		fmt.Printf("%v", inbound.DetailsStr())
		fmt.Println(color.RedString("============================\n"))

		// Configuring outbound
		outboundParsed, err := xray.ParseXrayConfig(link)
		if err != nil {
			log.Fatalf("Couldn't parse the config : %v", err)
		}
		fmt.Println(color.RedString("==========OUTBOUND=========="))
		fmt.Printf("%v", outboundParsed.DetailsStr())
		fmt.Println(color.RedString("============================"))

		// Make xray instance
		xrayInstance, err := xs.MakeXrayInstance(outboundParsed)
		if err != nil {
			fmt.Println("Error:", err.Error())
			return
		}

		// Create a channel to receive signals.
		signalChannel := make(chan os.Signal, 1)

		// Notify the signalChannel on receiving interrupt signals (e.g., Ctrl+C).
		signal.Notify(signalChannel, os.Interrupt, syscall.SIGINT)

		// Create a goroutine to handle the received signals.
		go func() {
			// Wait for a signal to be received.
			sig := <-signalChannel

			// Print the received signal.
			fmt.Printf(color.RedString("\nReceived signal: %v\n", sig))

			// Perform some actions before exiting.
			fmt.Println(color.RedString("Closing xray service..."))

			// Close xray service
			xrayInstance.Close()

			// Exit the program.
			os.Exit(0)
		}()

		// Start xray instance
		err = xrayInstance.Start()
		if err != nil {
			return
		}
		fmt.Println(color.GreenString("\nStarted listening for new connections..."))
		fmt.Printf("\n")

		// Don't let the program exit
		select {}
	},
}

func init() {
	ProxyCmd.Flags().BoolVarP(&readConfigFromSTDIN, "stdin", "i", false, "Read config link from STDIN")

	ProxyCmd.Flags().StringVarP(&listenAddr, "addr", "a", "127.0.0.1", "Listen ip address")
	ProxyCmd.Flags().Uint16VarP(&listenPort, "port", "p", 9999, "Listen port number")
	ProxyCmd.Flags().StringVarP(&link, "config", "c", "", "The xray config link")

	ProxyCmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Verbose xray-core")
	ProxyCmd.Flags().BoolVarP(&insecureTLS, "insecure", "e", false, "Insecure tls connection (fake SNI)")

}
