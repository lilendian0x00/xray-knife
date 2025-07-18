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
	CoreType            string `json:"coreType"`
	InboundProtocol     string `json:"inboundProtocol"`
	InboundTransport    string `json:"inboundTransport"`
	InboundUUID         string `json:"inboundUUID"`
	ListenAddr          string `json:"listenAddr"`
	ListenPort          string `json:"listenPort"`
	InboundConfigLink   string `json:"inboundConfigLink"`
	Mode                string `json:"mode"`
	Verbose             bool   `json:"verbose"`
	InsecureTLS         bool   `json:"insecureTLS"`
	EnableTLS           bool   `json:"enableTls"`
	TLSSNI              string `json:"tlsSni"`
	TLSALPN             string `json:"tlsAlpn"`
	TLSCertFile         string `json:"tlsCertPath"`
	TLSKeyFile          string `json:"tlsKeyPath"`
	WSPath              string `json:"wsPath"`
	WSHost              string `json:"wsHost"`
	GRPCServiceName     string `json:"grpcServiceName"`
	GRPCAuthority       string `json:"grpcAuthority"`
	XHTTPMode           string `json:"xhttpMode"`
	XHTTPHost           string `json:"xhttpHost"`
	XHTTPPath           string `json:"xhttpPath"`
	RotationInterval    uint32 `json:"rotationInterval"`
	MaximumAllowedDelay uint16 `json:"maximumAllowedDelay"`
	ConfigLinks         []string
}

// Details represents the current state of a running proxy service.
type Details struct {
	Inbound          protocol.GeneralConfig `json:"inbound"`
	ActiveOutbound   *pkghttp.Result        `json:"activeOutbound,omitempty"`
	RotationStatus   string                 `json:"rotationStatus"` // idle, testing, switching, stalled
	NextRotationTime time.Time              `json:"nextRotationTime"`
	RotationInterval uint32                 `json:"rotationInterval"`
	TotalConfigs     int                    `json:"totalConfigs"`
}

// Service is the main proxy service engine.
type Service struct {
	config           Config
	core             core.Core
	logger           *log.Logger
	inbound          protocol.Protocol
	activeOutbound   *pkghttp.Result
	mu               sync.RWMutex
	rotationStatus   string
	nextRotationTime time.Time
}

// New creates a new proxy Service.
func New(config Config, logger *log.Logger) (*Service, error) {
	s := &Service{
		config:         config,
		logger:         logger,
		rotationStatus: "idle",
	}

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
	s.inbound = inbound // Store inbound

	if err := s.core.SetInbound(inbound); err != nil {
		return nil, fmt.Errorf("failed to set inbound: %w", err)
	}

	s.logf(customlog.Info, "==========INBOUND==========")
	if s.logger != nil {
		g := inbound.ConvertToGeneralConfig()
		s.logger.Printf("Protocol: %s\nListen: %s:%s\nLink: %s\n", g.Protocol, g.Address, g.Port, g.OrigLink)
	} else {
		fmt.Printf("\n%v%s: %v\n", inbound.DetailsStr(), color.RedString("Link"), inbound.GetLink())
	}
	s.logf(customlog.Info, "============================\n\n")

	return s, nil
}

func (s *Service) setRotationStatus(status string) {
	s.mu.Lock()
	s.rotationStatus = status
	s.mu.Unlock()
}

// GetCurrentDetails safely returns the details of the running service.
func (s *Service) GetCurrentDetails() *Details {
	s.mu.RLock()
	defer s.mu.RUnlock()

	details := &Details{
		Inbound:          s.inbound.ConvertToGeneralConfig(),
		ActiveOutbound:   s.activeOutbound,
		RotationStatus:   s.rotationStatus,
		NextRotationTime: s.nextRotationTime,
		RotationInterval: s.config.RotationInterval,
		TotalConfigs:     len(s.config.ConfigLinks),
	}
	return details
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

	s.mu.Lock()
	s.activeOutbound = &pkghttp.Result{ConfigLink: link, Protocol: outbound}
	s.mu.Unlock()

	s.logf(customlog.Info, "==========OUTBOUND==========")
	if s.logger != nil {
		g := outbound.ConvertToGeneralConfig()
		s.logger.Printf("Protocol: %s\nRemark: %s\nAddr: %s:%s\nLink: %s\n", g.Protocol, g.Remark, g.Address, g.Port, g.OrigLink)
	} else {
		fmt.Printf("\n%v%s: %v\n", outbound.DetailsStr(), color.RedString("Link"), outbound.GetLink())
	}
	s.logf(customlog.Info, "============================\n")

	instance, err := s.core.MakeInstance(context.Background(), outbound)
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

	var currentInstance protocol.Instance
	defer func() {
		if currentInstance != nil {
			currentInstance.Close()
		}
	}()

	r := rand.New(rand.NewSource(time.Now().Unix()))
	var lastUsedLink string

	// Initial setup
	s.setRotationStatus("testing")
	instance, result, err := s.findAndStartWorkingConfig(examiner, r, "")
	if err != nil {
		s.logf(customlog.Failure, "Could not find any working config on initial startup. Exiting.")
		return err
	}
	currentInstance = instance
	lastUsedLink = result.ConfigLink
	s.setRotationStatus("idle")

	for {
		rotationDuration := time.Duration(s.config.RotationInterval) * time.Second
		if s.rotationStatus == "stalled" {
			rotationDuration = 30 * time.Second // Shorter retry interval if stalled
		}

		s.mu.Lock()
		s.nextRotationTime = time.Now().Add(rotationDuration)
		s.mu.Unlock()

		s.logf(customlog.Info, "Next rotation in %v. Current outbound: %s", rotationDuration, lastUsedLink)

		timer := time.NewTimer(rotationDuration)

		select {
		case <-ctx.Done():
			timer.Stop()
			return nil
		case <-forceRotate:
			s.logf(customlog.Processing, "Manual rotation triggered.")
			if !timer.Stop() {
				<-timer.C // Drain the timer if it already fired
			}
		case <-timer.C:
			s.logf(customlog.Processing, "Rotation interval elapsed.")
		}

		s.setRotationStatus("testing")
		instance, result, err := s.findAndStartWorkingConfig(examiner, r, lastUsedLink)
		if err != nil {
			s.logf(customlog.Warning, "Rotation failed to find a new working config. Keeping the current one. Retrying in 30s...")
			s.setRotationStatus("stalled")
			continue // Keep the old instance running and retry sooner
		}

		s.setRotationStatus("switching")
		s.logf(customlog.Success, "Switching to new outbound: %s", result.ConfigLink)

		if currentInstance != nil {
			currentInstance.Close()
		}
		currentInstance = instance
		lastUsedLink = result.ConfigLink
		s.setRotationStatus("idle")
	}
}

func (s *Service) findAndStartWorkingConfig(
	examiner *pkghttp.Examiner,
	r *rand.Rand,
	lastUsedLink string,
) (protocol.Instance, *pkghttp.Result, error) {
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

	testManager.RunTests(context.Background(), linksToTest, resultsChan, func() {

	})
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

			instance, err := s.core.MakeInstance(context.Background(), res.Protocol)
			if err != nil {
				s.logf(customlog.Failure, "Error making core instance with '%s': %v\n", res.ConfigLink, err)
				continue
			}
			if err := instance.Start(); err != nil {
				instance.Close()
				s.logf(customlog.Failure, "Error starting core instance with '%s': %v\n", res.ConfigLink, err)
				continue
			}
			s.mu.Lock()
			res.Protocol = res.Protocol // Ensure protocol field is set.
			s.activeOutbound = res
			s.mu.Unlock()
			return instance, res, nil
		}
	}
	return nil, nil, errors.New("failed to find any new working outbound configuration in this batch")
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
		DoIPInfo:               true,
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
	if uuidV4 == "random" || uuidV4 == "" {
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
		vmess := &pkgxray.Vmess{
			Remark:  "Listener",
			Address: cfg.ListenAddr,
			Port:    cfg.ListenPort,
			ID:      uuid,
		}
		switch cfg.InboundTransport {
		case "tcp":
			vmess.Network = "tcp"
		case "ws":
			vmess.Network = "ws"
			vmess.Path = cfg.WSPath
			vmess.Host = cfg.WSHost
		case "grpc":
			vmess.Network = "grpc"
			vmess.Path = cfg.GRPCServiceName // For VMESS, Path is used for ServiceName
			vmess.Host = cfg.GRPCAuthority
		case "xhttp":
			vmess.Network = "xhttp"
			vmess.Type = cfg.XHTTPMode
			vmess.Host = cfg.XHTTPHost
			vmess.Path = cfg.XHTTPPath
			vmess.Security = "none"
		default:
			return nil, fmt.Errorf("unsupported vmess transport: %s", cfg.InboundTransport)
		}

		if cfg.EnableTLS {
			vmess.TLS = "tls"
			vmess.CertFile = cfg.TLSCertFile
			vmess.KeyFile = cfg.TLSKeyFile
			vmess.SNI = cfg.TLSSNI
			vmess.ALPN = cfg.TLSALPN
		}

		return vmess, nil
	case "vless":
		vless := &pkgxray.Vless{
			Remark:  "Listener",
			Address: cfg.ListenAddr,
			Port:    cfg.ListenPort,
			ID:      uuid,
		}
		switch cfg.InboundTransport {
		case "tcp":
			vless.Type = "tcp"
		case "ws":
			vless.Type = "ws"
			vless.Path = cfg.WSPath
			vless.Host = cfg.WSHost
		case "grpc":
			vless.Type = "grpc"
			vless.ServiceName = cfg.GRPCServiceName
			vless.Authority = cfg.GRPCAuthority
		case "xhttp":
			vless.Type = "xhttp"
			vless.Host = cfg.XHTTPHost
			vless.Path = cfg.XHTTPPath
			vless.Security = "none"
			vless.Mode = cfg.XHTTPMode
		default:
			return nil, fmt.Errorf("unsupported vless transport: %s", cfg.InboundTransport)
		}

		if cfg.EnableTLS {
			vless.Security = "tls"
			vless.CertFile = cfg.TLSCertFile
			vless.KeyFile = cfg.TLSKeyFile
			vless.SNI = cfg.TLSSNI
			vless.ALPN = cfg.TLSALPN
		}
		return vless, nil
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
