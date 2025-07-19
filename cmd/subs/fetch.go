package subs

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/lilendian0x00/xray-knife/v6/utils"
	"github.com/lilendian0x00/xray-knife/v6/utils/customlog"

	"github.com/spf13/cobra"
)

// FetchConfig holds the configuration for the fetch command
type FetchConfig struct {
	SubscriptionURL string
	HTTPMethod      string
	UserAgent       string
	OutputFile      string
	Proxy           string
}

// FetchCommand encapsulates the fetch command functionality
type FetchCommand struct {
	config *FetchConfig
}

// NewFetchCommand creates a new instance of the fetch command
func NewFetchCommand() *cobra.Command {
	fc := &FetchCommand{
		config: &FetchConfig{},
	}
	return fc.createCommand()
}

// createCommand creates and configures the cobra command
func (fc *FetchCommand) createCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "fetch",
		Short: "Fetches all config links from a subscription to a file",
		RunE:  fc.runCommand,
	}

	fc.addFlags(cmd)
	return cmd
}

// addFlags adds command-line flags to the command
func (fc *FetchCommand) addFlags(cmd *cobra.Command) {
	flags := cmd.Flags()

	flags.StringVarP(&fc.config.SubscriptionURL, "url", "u", "", "The subscription url")
	flags.StringVarP(&fc.config.HTTPMethod, "method", "m", "GET", "Http method to be used")
	flags.StringVarP(&fc.config.UserAgent, "useragent", "x", "", "Useragent to be used")
	flags.StringVarP(&fc.config.OutputFile, "out", "o", "-", "The output file where the configs will be placed. - means stdout")
	flags.StringVarP(&fc.config.Proxy, "proxy", "p", "", "proxy to connect to for fetching the subscription, in form of")
}

// runCommand executes the fetch command logic
func (fc *FetchCommand) runCommand(cmd *cobra.Command, args []string) error {
	sub := Subscription{
		Url:         fc.config.SubscriptionURL,
		UserAgent:   fc.config.UserAgent,
		Method:      fc.config.HTTPMethod,
		ConfigLinks: []string{},
		Proxy:       fc.config.Proxy,
	}

	if sub.Url == "" {
		reader := bufio.NewReader(os.Stdin)
		fmt.Println("Enter your subscription url:")
		text, _ := reader.ReadString('\n')
		sub.Url = strings.TrimSpace(text)
	}

	configs, err := sub.FetchAll()
	if err != nil {
		return fmt.Errorf("failed to fetch configurations: %w", err)
	}

	if err := fc.saveConfigs(configs); err != nil {
		return fmt.Errorf("failed to save configurations: %w", err)
	}

	customlog.Printf(customlog.Success, "%d Configs have been written into %q\n",
		len(configs), fc.config.OutputFile)
	return nil
}

// saveConfigs saves the fetched configurations to a file
func (fc *FetchCommand) saveConfigs(configs []string) error {
	content := strings.Join(configs, "\n") + "\n"
	return utils.WriteIntoFile(fc.config.OutputFile, []byte(content))
}
