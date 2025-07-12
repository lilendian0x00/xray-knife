package proxy

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/lilendian0x00/xray-knife/v5/pkg/core"
	"github.com/lilendian0x00/xray-knife/v5/pkg/core/protocol"
	pkgsingbox "github.com/lilendian0x00/xray-knife/v5/pkg/core/singbox"
	pkgxray "github.com/lilendian0x00/xray-knife/v5/pkg/core/xray"
	pkghttp "github.com/lilendian0x00/xray-knife/v5/pkg/http"
	"github.com/lilendian0x00/xray-knife/v5/utils"
	"github.com/lilendian0x00/xray-knife/v5/utils/customlog"
	"github.com/xtls/xray-core/common/uuid"

	"github.com/fatih/color"
)

// Config holds all the settings for the proxy service.
type Config struct {
	CoreType          string
	InboundProtocol   string
	InboundTransport  string
	InboundUUID       string
	ListenAddr        string
	ListenPort        string
	InboundConfigLink string
	Mode              string
	Verbose           bool
	InsecureTLS       bool

	// Rotation-specific settings
	RotationInterval    uint32
	MaximumAllowedDelay uint16
	ConfigLinks         []string
}

// Service is the main proxy service engine.
type Service struct {
	config Config
	core   core.Core
}

// New creates a new proxy Service.
func New(config Config) (*Service, error) {
	s := &Service{config: config}

	switch config.CoreType {
	case "xray":
		s.core = core.CoreFactory(core.XrayCoreType, config.InsecureTLS, config.Verbose)
	case "sing-box":
		s.core = core.CoreFactory(core.SingboxCoreType, config.InsecureTLS, config.Verbose)
	default:
		return nil, fmt.Errorf("allowed core types: (xray, singbox), got: %s", config.CoreType)
	}

	inbound, err := s.createInbound()
	if err != nil {
		return nil, fmt.Errorf("failed to create inbound: %w", err)
	}

	if err := s.core.SetInbound(inbound); err != nil {
		return nil, fmt.Errorf("failed to set inbound: %w", err)
	}

	customlog.Printf(customlog.Info, "\n==========INBOUND==========\n")
	fmt.Printf("%v%s: %v\n", inbound.DetailsStr(), color.RedString("Link"), inbound.GetLink())
	customlog.Printf(customlog.Info, "============================\n\n")

	return s, nil
}

// Run starts the proxy service and blocks until the context is canceled.
func (s *Service) Run(ctx context.Context, forceRotate <-chan struct{}) error {
	if len(s.config.ConfigLinks) == 0 {
		return errors.New("no configuration links provided")
	}

	if len(s.config.ConfigLinks) == 1 {
		return s.runSingleMode(ctx, s.config.ConfigLinks[0])
	}

	return s.runRotationMode(ctx, forceRotate)
}

func (s *Service) runSingleMode(ctx context.Context, link string) error {
	outbound, err := s.core.CreateProtocol(link)
	if err != nil {
		return fmt.Errorf("couldn't parse the single config %s: %w", link, err)
	}
	if err := outbound.Parse(); err != nil {
		return fmt.Errorf("failed to parse single outbound config: %w", err)
	}

	customlog.Printf(customlog.Info, "==========OUTBOUND==========\n")
	fmt.Printf("%v%s: %v\n", outbound.DetailsStr(), color.RedString("Link"), outbound.GetLink())
	customlog.Printf(customlog.Info, "============================\n")

	instance, err := s.core.MakeInstance(outbound)
	if err != nil {
		return fmt.Errorf("error making instance: %w", err)
	}
	defer instance.Close()

	if err := instance.Start(); err != nil {
		return fmt.Errorf("error starting instance: %w", err)
	}
	customlog.Printf(customlog.Success, "Started listening for new connections...")

	<-ctx.Done() // Wait for shutdown signal
	customlog.Printf(customlog.Processing, "Shutting down proxy...\n")
	return nil
}

func (s *Service) runRotationMode(ctx context.Context, forceRotate <-chan struct{}) error {
	examiner, err := s.createExaminer()
	if err != nil {
		return err
	}

	r := rand.New(rand.NewSource(time.Now().Unix()))
	processor := pkghttp.NewResultProcessor(pkghttp.ResultProcessorOptions{OutputType: "txt"})
	var currentInstance protocol.Instance
	var currentLink string

	for {
		select {
		case <-ctx.Done():
			customlog.Printf(customlog.Processing, "Main proxy loop exiting.\n")
			if currentInstance != nil {
				customlog.Printf(customlog.Processing, "Closing final active instance...\n")
				_ = currentInstance.Close()
			}
			return nil
		default:
		}

		if currentInstance != nil {
			_ = currentInstance.Close()
			currentInstance = nil
		}

		newInstance, newLink, err := findAndStartWorkingConfig(s.core, examiner, processor, s.config.ConfigLinks, r, currentLink)
		if err != nil {
			customlog.Printf(customlog.Failure, "Error finding new config: %v. Retrying after delay...\n", err)
			select {
			case <-time.After(10 * time.Second):
			case <-ctx.Done():
				return nil
			}
			continue
		}

		currentInstance = newInstance
		currentLink = newLink
		customlog.Printf(customlog.Success, "Successfully started new instance.\n")

		reason := manageActiveProxyPeriod(ctx, s.config.RotationInterval, forceRotate)
		customlog.Printf(customlog.Processing, "Switching config. Reason: %s\n", reason)
	}
}

// GetConfigLinks is a helper to centralize the logic of reading links from various sources.
func GetConfigLinks(fromFile, fromLink string, fromSTDIN bool) ([]string, error) {
	var links []string
	if fromSTDIN {
		scanner := bufio.NewScanner(os.Stdin)
		fmt.Println("Reading config links from STDIN (press CTRL+D when done):")
		for scanner.Scan() {
			if trimmed := strings.TrimSpace(scanner.Text()); trimmed != "" {
				links = append(links, trimmed)
			}
		}
		if err := scanner.Err(); err != nil && !errors.Is(err, io.EOF) {
			return nil, err
		}
	} else if fromLink != "" {
		links = append(links, fromLink)
	} else if fromFile != "" {
		links = utils.ParseFileByNewline(fromFile)
	}

	if len(links) == 0 {
		return nil, errors.New("no configuration links provided or found")
	}
	return links, nil
}

func (s *Service) createExaminer() (*pkghttp.Examiner, error) {
	return pkghttp.NewExaminer(pkghttp.Options{
		Core:                   "auto",
		MaxDelay:               s.config.MaximumAllowedDelay,
		Verbose:                s.config.Verbose,
		InsecureTLS:            s.config.InsecureTLS,
		TestEndpoint:           "https://cloudflare.com/cdn-cgi/trace",
		TestEndpointHttpMethod: "GET",
		DoSpeedtest:            false,
	})
}

func (s *Service) createInbound() (protocol.Protocol, error) {
	if s.config.InboundConfigLink != "" {
		inbound, err := s.core.CreateProtocol(s.config.InboundConfigLink)
		if err != nil {
			return nil, fmt.Errorf("failed to create inbound from config link: %w", err)
		}
		if err := inbound.Parse(); err != nil {
			return nil, fmt.Errorf("failed to parse inbound config link: %w", err)
		}
		return inbound, nil
	}

	if s.config.Mode == "system" {
		return nil, errors.New(`mode "system" is not yet implemented`)
	}

	u := uuid.New()
	uuidV4 := s.config.InboundUUID
	if uuidV4 == "random" {
		uuidV4 = u.String()
	}

	switch s.config.CoreType {
	case "xray":
		return createXrayInbound(s.config, uuidV4)
	case "sing-box":
		return createSingboxInbound(s.config)
	}
	return nil, fmt.Errorf("inbound could not be created for core type: %s", s.config.CoreType)
}

func findAndStartWorkingConfig(
	c core.Core,
	examiner *pkghttp.Examiner,
	processor *pkghttp.ResultProcessor,
	allLinks []string,
	r *rand.Rand,
	lastUsedLink string,
) (protocol.Instance, string, error) {
	// ... (same logic as before)
	const BatchAmount = 50
	availableLinks := make([]string, len(allLinks))
	copy(availableLinks, allLinks)
	r.Shuffle(len(availableLinks), func(i, j int) { availableLinks[i], availableLinks[j] = availableLinks[j], availableLinks[i] })

	testCount := BatchAmount
	if len(availableLinks) < testCount {
		testCount = len(availableLinks)
	}
	linksToTest := availableLinks[:testCount]
	customlog.Printf(customlog.Processing, "Testing a batch of %d configs...\n", len(linksToTest))

	testManager := pkghttp.NewTestManager(examiner, processor, 50, false)
	results := testManager.TestConfigs(linksToTest, false)
	sort.Sort(results)

	for _, res := range results {
		if res.Status == "passed" && res.Protocol != nil && res.ConfigLink != lastUsedLink {
			customlog.Printf(customlog.Success, "Found working config: %s (Delay: %dms)\n", res.ConfigLink, res.Delay)
			fmt.Println(color.RedString("==========OUTBOUND=========="))
			fmt.Printf("%v", res.Protocol.DetailsStr())
			fmt.Println(color.RedString("============================"))

			instance, err := c.MakeInstance(res.Protocol)
			if err != nil {
				customlog.Printf(customlog.Failure, "Error making core instance with '%s': %v\n", res.ConfigLink, err)
				continue
			}
			if err := instance.Start(); err != nil {
				instance.Close()
				customlog.Printf(customlog.Failure, "Error starting core instance with '%s': %v\n", res.ConfigLink, err)
				continue
			}
			return instance, res.ConfigLink, nil
		}
	}
	return nil, "", errors.New("failed to find any new working outbound configuration in this batch")
}

func manageActiveProxyPeriod(ctx context.Context, rotationInterval uint32, forceRotate <-chan struct{}) string {
	customlog.Printf(customlog.Success, "Instance active. Interval: %ds. Press Enter to switch.\n", rotationInterval)

	timer := time.NewTimer(time.Duration(rotationInterval) * time.Second)
	defer timer.Stop()

	displayTicker := time.NewTicker(time.Second)
	defer displayTicker.Stop()
	endTime := time.Now().Add(time.Duration(rotationInterval) * time.Second)

	updateDisplay := func() {
		remaining := endTime.Sub(time.Now())
		if remaining < 0 {
			remaining = 0
		}
		fmt.Printf("\r%s\033[K", color.YellowString("[>] Enter to load the next config [Reloading in %v] >>> ", remaining.Round(time.Second)))
	}
	updateDisplay()

	for {
		select {
		case <-ctx.Done():
			fmt.Println()
			return "context cancelled"
		case <-forceRotate:
			fmt.Println()
			return "user requested switch"
		case <-timer.C:
			fmt.Println()
			return "interval timer expired"
		case <-displayTicker.C:
			updateDisplay()
		}
	}
}

func createXrayInbound(cfg Config, uuid string) (protocol.Protocol, error) {
	switch cfg.InboundProtocol {
	case "socks":
		user, _ := utils.GeneratePassword(4)
		pass, _ := utils.GeneratePassword(4)
		return &pkgxray.Socks{
			Remark: "Listener", Address: cfg.ListenAddr, Port: cfg.ListenPort,
			Username: user, Password: pass,
		}, nil
	case "vmess":
		switch cfg.InboundTransport {
		case "xhttp":
			return &pkgxray.Vmess{
				Remark: "Listener", Address: cfg.ListenAddr, Port: cfg.ListenPort,
				Network: "xhttp", Host: "snapp.ir", Path: "/", Security: "none", ID: uuid,
			}, nil
		case "tcp":
			return &pkgxray.Vmess{
				Remark: "Listener", Address: cfg.ListenAddr, Port: cfg.ListenPort,
				Type: "tcp", ID: uuid,
			}, nil
		}
	case "vless":
		switch cfg.InboundTransport {
		case "xhttp":
			return &pkgxray.Vless{
				Remark: "Listener", Address: cfg.ListenAddr, Port: cfg.ListenPort,
				Type: "xhttp", Host: "snapp.ir", Path: "/", Security: "none", ID: uuid, Mode: "auto",
			}, nil
		case "tcp":
			return &pkgxray.Vless{
				Remark: "Listener", Address: cfg.ListenAddr, Port: cfg.ListenPort,
				Type: "tcp", ID: uuid,
			}, nil
		}
	}
	return nil, fmt.Errorf("unsupported xray inbound protocol/transport: %s/%s", cfg.InboundProtocol, cfg.InboundTransport)
}

func createSingboxInbound(cfg Config) (protocol.Protocol, error) {
	// Currently, only SOCKS is implemented for Singbox inbound in this logic
	if cfg.InboundProtocol == "socks" {
		user, _ := utils.GeneratePassword(4)
		pass, _ := utils.GeneratePassword(4)
		return &pkgsingbox.Socks{
			Remark: "Listener", Address: cfg.ListenAddr, Port: cfg.ListenPort,
			Username: user, Password: pass,
		}, nil
	}
	return nil, fmt.Errorf("unsupported sing-box inbound protocol: %s", cfg.InboundProtocol)
}
