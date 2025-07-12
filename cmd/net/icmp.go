package net

import (
	"bufio"
	"fmt"
	"github.com/lilendian0x00/xray-knife/v5/pkg/core/xray"
	"net"
	"os"
	"strings"

	"github.com/lilendian0x00/xray-knife/v5/network"
	"github.com/lilendian0x00/xray-knife/v5/pkg"
	"github.com/lilendian0x00/xray-knife/v5/pkg/core/protocol"

	"github.com/spf13/cobra"
)

// ICMPConfig holds the configuration for the ICMP command
type ICMPConfig struct {
	ConfigLink string
	TestCount  uint16
	DestIP     net.IP
}

// ICMPCommand encapsulates the ICMP command functionality
type ICMPCommand struct {
	config *ICMPConfig
	xray   pkg.Core
}

// NewICMPCommand creates a new instance of the ICMP command
func NewICMPCommand() *cobra.Command {
	ic := &ICMPCommand{
		config: &ICMPConfig{},
		xray:   xray.NewXrayService(false, false),
	}
	return ic.createCommand()
}

// createCommand creates and configures the cobra command
func (ic *ICMPCommand) createCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "icmp",
		Short: "PING or ICMP test config's host",
		Long:  `Tests the connectivity and measures latency to a host using ICMP (ping) packets`,
		RunE:  ic.runCommand,
	}

	ic.addFlags(cmd)
	return cmd
}

// addFlags adds command-line flags to the command
func (ic *ICMPCommand) addFlags(cmd *cobra.Command) {
	flags := cmd.Flags()
	flags.StringVarP(&ic.config.ConfigLink, "config", "c", "", "The xray config link")
	flags.Uint16VarP(&ic.config.TestCount, "count", "t", 4, "Count of tests")
}

// runCommand executes the ICMP command logic
func (ic *ICMPCommand) runCommand(cmd *cobra.Command, args []string) error {
	protocol, err := ic.parseConfig()
	if err != nil {
		return fmt.Errorf("failed to parse configuration: %w", err)
	}

	err = protocol.Parse()
	if err != nil {
		return fmt.Errorf("failed to parse configuration: %w", err)
	}

	generalConfig, err := ic.getGeneralConfig(protocol)
	if err != nil {
		return fmt.Errorf("failed to get general configuration: %w", err)
	}

	return ic.performICMPTest(generalConfig)
}

// parseConfig parses the provided configuration
func (ic *ICMPCommand) parseConfig() (protocol.Protocol, error) {
	if ic.config.ConfigLink == "" {
		reader := bufio.NewReader(os.Stdin)
		fmt.Println("Enter your config link:")
		text, _ := reader.ReadString('\n')
		ic.config.ConfigLink = strings.TrimSpace(text)
	}
	protocol, err := ic.xray.CreateProtocol(ic.config.ConfigLink)
	if err != nil {
		return nil, fmt.Errorf("failed to create protocol: %w", err)
	}
	return protocol, nil
}

// getGeneralConfig converts the protocol to general configuration
func (ic *ICMPCommand) getGeneralConfig(protocol protocol.Protocol) (protocol.GeneralConfig, error) {
	generalConfig := protocol.ConvertToGeneralConfig()
	//if generalConfig == nil {
	//	return nil, fmt.Errorf("failed to convert to general configuration")
	//}
	return generalConfig, nil
}

// performICMPTest executes the ICMP test
func (ic *ICMPCommand) performICMPTest(config protocol.GeneralConfig) error {
	icmp, err := network.NewIcmpPacket(config.Address, ic.config.TestCount)
	if err != nil {
		return fmt.Errorf("failed to create ICMP packet: %w", err)
	}

	if err := icmp.MeasureReplyDelay(); err != nil {
		return fmt.Errorf("failed to measure reply delay: %w", err)
	}

	return nil
}
