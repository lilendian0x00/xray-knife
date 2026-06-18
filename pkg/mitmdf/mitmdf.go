package mitmdf

import (
	"context"
	"fmt"
	"log"
	"os"
	"sync"

	"github.com/xtls/xray-core/core"
	// Import necessary xray-core modules to register handlers
	_ "github.com/xtls/xray-core/app/dispatcher"
	_ "github.com/xtls/xray-core/app/proxyman/inbound"
	_ "github.com/xtls/xray-core/app/proxyman/outbound"
	commlog "github.com/xtls/xray-core/common/log"
)

type Service struct {
	mu       sync.Mutex
	instance *core.Instance
	cfg      *Config
	logger   *log.Logger
}

func NewService(cfg *Config, logger *log.Logger) *Service {
	return &Service{
		cfg:    cfg,
		logger: logger,
	}
}

func (s *Service) Start(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.instance != nil {
		return fmt.Errorf("MITM-DF service is already running")
	}

	// Set XRAY_LOCATION_ASSET so geosite.dat/geoip.dat can be found
	assetsDir, err := AssetsDir()
	if err != nil {
		return fmt.Errorf("failed to get assets dir: %w", err)
	}
	if err := os.Setenv("XRAY_LOCATION_ASSET", assetsDir); err != nil {
		return fmt.Errorf("failed to set XRAY_LOCATION_ASSET: %w", err)
	}

	// Suppress xray-core's default console logger
	commlog.RegisterHandler(commlog.NewLogger(commlog.CreateStderrLogWriter()))

	coreCfg, err := GenerateXrayConfig(s.cfg)
	if err != nil {
		return fmt.Errorf("failed to generate xray config: %w", err)
	}

	inst, err := core.New(coreCfg)
	if err != nil {
		return fmt.Errorf("failed to create xray instance: %w", err)
	}

	if err := inst.Start(); err != nil {
		return fmt.Errorf("failed to start xray instance: %w", err)
	}

	s.instance = inst
	s.logger.Printf("[MITM-DF] Service started successfully on SOCKS5 port %d", s.cfg.SOCKS5Port)

	// Wait for context cancellation to stop the service
	go func() {
		<-ctx.Done()
		s.logger.Printf("[MITM-DF] Context cancelled, stopping service...")
		if stopErr := s.Stop(); stopErr != nil {
			s.logger.Printf("[MITM-DF] Error during stop: %v", stopErr)
		}
	}()

	return nil
}

func (s *Service) Stop() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.instance == nil {
		return fmt.Errorf("MITM-DF service is not running")
	}

	if err := s.instance.Close(); err != nil {
		return fmt.Errorf("error closing xray instance: %w", err)
	}

	s.instance = nil
	s.logger.Printf("[MITM-DF] Service stopped.")
	return nil
}

func (s *Service) IsRunning() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.instance != nil
}
