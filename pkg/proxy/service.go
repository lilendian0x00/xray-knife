package proxy

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"math/rand"
	"os"
	"sort"
	"strings"
	"sync"
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
	logger *log.Logger
}

// New creates a new proxy Service.
func New(config Config, logger *log.Logger) (*Service, error) {
	s := &Service{config: config, logger: logger}

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

	s.logf(customlog.Info, "==========INBOUND==========")
	if s.logger != nil {
		// Log simple, uncolored details for the Web UI
		g := inbound.ConvertToGeneralConfig()
		s.logger.Printf("Protocol: %s\nListen: %s:%s\nLink: %s\n", g.Protocol, g.Address, g.Port, g.OrigLink)
	} else {
		// Log rich, colored details for the CLI
		fmt.Printf("\n%v%s: %v\n", inbound.DetailsStr(), color.RedString("Link"), inbound.GetLink())
	}
	s.logf(customlog.Info, "============================\n\n")

	return s, nil
}

// logf is a helper to direct logs to either the web logger or the CLI customlog.
func (s *Service) logf(logType customlog.Type, format string, v ...interface{}) {
	if s.logger != nil {
		s.logger.Printf(format, v...)
	} else {
		customlog.Printf(logType, format, v...)
	}
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

	s.logf(customlog.Info, "==========OUTBOUND==========")
	if s.logger != nil {
		g := outbound.ConvertToGeneralConfig()
		s.logger.Printf("Protocol: %s\nRemark: %s\nAddr: %s:%s\nLink: %s\n", g.Protocol, g.Remark, g.Address, g.Port, g.OrigLink)
	} else {
		fmt.Printf("\n%v%s: %v\n", outbound.DetailsStr(), color.RedString("Link"), outbound.GetLink())
	}
	s.logf(customlog.Info, "============================\n")

	instance, err := s.core.MakeInstance(outbound)
	if err != nil {
		return fmt.Errorf("error making instance: %w", err)
	}
	defer instance.Close()

	if err := instance.Start(); err != nil {
		return fmt.Errorf("error starting instance: %w", err)
	}
	s.logf(customlog.Success, "Started listening for new connections...\n")

	<-ctx.Done() // Wait for shutdown signal
	s.logf(customlog.Processing, "Shutting down proxy...\n")
	return nil
}

func (s *Service) runRotationMode(ctx context.Context, forceRotate <-chan struct{}) error {
	examiner, err := s.createExaminer()
	if err != nil {
		return err
	}

	r := rand.New(rand.NewSource(time.Now().Unix()))
	var currentInstance protocol.Instance
	var currentLink string

	for {
		select {
		case <-ctx.Done():
			s.logf(customlog.Processing, "Main proxy loop exiting.\n")
			if currentInstance != nil {
				s.logf(customlog.Processing, "Closing final active instance...\n")
				_ = currentInstance.Close()
			}
			return nil
		default:
		}

		if currentInstance != nil {
			_ = currentInstance.Close()
			currentInstance = nil
		}

		newInstance, newLink, err := s.findAndStartWorkingConfig(examiner, r, currentLink)
		if err != nil {
			s.logf(customlog.Failure, "Error finding new config: %v. Retrying after delay...\n", err)
			select {
			case <-time.After(10 * time.Second):
			case <-ctx.Done():
				return nil
			}
			continue
		}

		currentInstance = newInstance
		currentLink = newLink
		s.logf(customlog.Success, "Successfully started new instance.\n")

		reason := s.manageActiveProxyPeriod(ctx, forceRotate)
		s.logf(customlog.Processing, "Switching config. Reason: %s\n", reason)
	}
}

func (s *Service) findAndStartWorkingConfig(
	examiner *pkghttp.Examiner,
	r *rand.Rand,
	lastUsedLink string,
) (protocol.Instance, string, error) {
	const BatchAmount = 50
	availableLinks := make([]string, len(s.config.ConfigLinks))
	copy(availableLinks, s.config.ConfigLinks)
	r.Shuffle(len(availableLinks), func(i, j int) { availableLinks[i], availableLinks[j] = availableLinks[j], availableLinks[i] })

	testCount := BatchAmount
	if len(availableLinks) < testCount {
		testCount = len(availableLinks)
	}
	linksToTest := availableLinks[:testCount]
	s.logf(customlog.Processing, "Testing a batch of %d configs...\n", len(linksToTest))

	testManager := pkghttp.NewTestManager(examiner, 50, false, s.logger)
	resultsChan := make(chan *pkghttp.Result, len(linksToTest))
	var results pkghttp.ConfigResults
	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		for res := range resultsChan {
			results = append(results, res)
		}
	}()

	testManager.RunTests(linksToTest, resultsChan)
	close(resultsChan)
	wg.Wait()

	sort.Sort(results)

	for _, res := range results {
		if res.Status == "passed" && res.Protocol != nil && res.ConfigLink != lastUsedLink {
			s.logf(customlog.Success, "Found working config: %s (Delay: %dms)\n", res.ConfigLink, res.Delay)
			s.logf(customlog.Info, "==========OUTBOUND==========")
			if s.logger != nil {
				g := res.Protocol.ConvertToGeneralConfig()
				s.logger.Printf("Protocol: %s\nRemark: %s\nAddr: %s:%s\nLink: %s\n", g.Protocol, g.Remark, g.Address, g.Port, g.OrigLink)
			} else {
				fmt.Printf("%v", res.Protocol.DetailsStr())
			}
			s.logf(customlog.Info, "============================\n")

			instance, err := s.core.MakeInstance(res.Protocol)
			if err != nil {
				s.logf(customlog.Failure, "Error making core instance with '%s': %v\n", res.ConfigLink, err)
				continue
			}
			if err := instance.Start(); err != nil {
				instance.Close()
				s.logf(customlog.Failure, "Error starting core instance with '%s': %v\n", res.ConfigLink, err)
				continue
			}
			return instance, res.ConfigLink, nil
		}
	}
	return nil, "", errors.New("failed to find any new working outbound configuration in this batch")
}

func (s *Service) manageActiveProxyPeriod(ctx context.Context, forceRotate <-chan struct{}) (reason string) {
	s.logf(customlog.Success, "Instance active. Interval: %ds. Press Enter to switch.\n", s.config.RotationInterval)

	timer := time.NewTimer(time.Duration(s.config.RotationInterval) * time.Second)
	defer timer.Stop()

	// The interactive countdown is a CLI-only feature.
	if s.logger == nil {
		displayTicker := time.NewTicker(time.Second)
		defer displayTicker.Stop()
		endTime := time.Now().Add(time.Duration(s.config.RotationInterval) * time.Second)

		updateDisplay := func() {
			if remaining := time.Until(endTime); remaining > 0 {
				fmt.Printf("\r%s\033[K", color.YellowString("[>] Enter to load the next config [Reloading in %v] >>> ", remaining.Round(time.Second)))
			} else {
				fmt.Printf("\r%s\033[K", color.YellowString("[>] Enter to load the next config [Reloading in 0s] >>> "))
			}
		}
		updateDisplay()

		for {
			select {
			case <-ctx.Done():
				fmt.Println() // Newline to clean up the progress bar line
				return "context cancelled"
			case <-forceRotate:
				fmt.Println() // Newline to clean up the progress bar line
				return "user requested switch"
			case <-timer.C:
				fmt.Println() // Newline to clean up the progress bar line
				return "interval timer expired"
			case <-displayTicker.C:
				if time.Now().Before(endTime) {
					updateDisplay()
				}
			}
		}
	}

	// Non-interactive wait for Web UI
	select {
	case <-ctx.Done():
		return "context cancelled"
	case <-forceRotate:
		return "user requested switch"
	case <-timer.C:
		return "interval timer expired"
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
		Core:                   s.config.CoreType,
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
