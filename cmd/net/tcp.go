package net

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net"
	"os"
	"strings"
	"time"

	"github.com/lilendian0x00/xray-knife/v11/pkg/core"
	"github.com/lilendian0x00/xray-knife/v11/utils/customlog"
	"github.com/lilendian0x00/xray-knife/v11/utils/exitcode"

	"github.com/spf13/cobra"
)

// Define a struct to hold the configuration for the TCP command
type tcpCmdConfig struct {
	configLink string
	timeout    time.Duration
	count      int
	interval   time.Duration
	json       bool
}

// tcpSummary is the --json output.
type tcpSummary struct {
	Target   string    `json:"target"`
	Sent     int       `json:"sent"`
	Received int       `json:"received"`
	LossPct  float64   `json:"lossPercent"`
	MinMs    float64   `json:"minMs,omitempty"`
	AvgMs    float64   `json:"avgMs,omitempty"`
	MaxMs    float64   `json:"maxMs,omitempty"`
	RTTsMs   []float64 `json:"rttsMs"`
	Errors   []string  `json:"errors,omitempty"`
}

// TcpCmd is the tcp subcommand.
var TcpCmd = newTcpCommand()

// dialFunc is swapped in tests.
var dialFunc = func(ctx context.Context, timeout time.Duration, addr string) (net.Conn, error) {
	d := net.Dialer{Timeout: timeout}
	return d.DialContext(ctx, "tcp", addr)
}

// targetOf returns host:port of a config link's server.
func targetOf(link string) (string, error) {
	c := core.NewAutomaticCore(false, false)
	parsed, err := c.CreateProtocol(link)
	if err != nil {
		return "", fmt.Errorf("couldn't parse the config: %w", err)
	}
	if err := parsed.Parse(); err != nil {
		return "", fmt.Errorf("couldn't parse the config: %w", err)
	}
	g := parsed.ConvertToGeneralConfig()
	// Some protocols report IPv6 literals already bracketed; JoinHostPort
	// adds its own.
	host := strings.TrimSuffix(strings.TrimPrefix(g.Address, "["), "]")
	if host == "" || g.Port == "" {
		return "", fmt.Errorf("parsed config does not yield a valid address or port")
	}
	return net.JoinHostPort(host, g.Port), nil
}

// probe dials target count times and collects the connect times.
func probe(ctx context.Context, cfg *tcpCmdConfig, target string, report func(i int, rtt time.Duration, err error)) tcpSummary {
	sum := tcpSummary{Target: target, RTTsMs: []float64{}}
	var total float64
	sum.MinMs = math.MaxFloat64
	for i := 0; i < cfg.count; i++ {
		if i > 0 {
			select {
			case <-ctx.Done():
			case <-time.After(cfg.interval):
			}
		}
		if ctx.Err() != nil {
			break
		}
		sum.Sent++
		start := time.Now()
		conn, err := dialFunc(ctx, cfg.timeout, target)
		rtt := time.Since(start)
		if err != nil {
			if ctx.Err() != nil {
				sum.Sent--
				break
			}
			sum.Errors = append(sum.Errors, err.Error())
			report(i, 0, err)
			continue
		}
		_ = conn.Close()
		ms := float64(rtt.Microseconds()) / 1000
		sum.Received++
		sum.RTTsMs = append(sum.RTTsMs, ms)
		total += ms
		sum.MinMs = math.Min(sum.MinMs, ms)
		sum.MaxMs = math.Max(sum.MaxMs, ms)
		report(i, rtt, nil)
	}
	if sum.Received > 0 {
		sum.AvgMs = total / float64(sum.Received)
	} else {
		sum.MinMs = 0
	}
	if sum.Sent > 0 {
		sum.LossPct = 100 * float64(sum.Sent-sum.Received) / float64(sum.Sent)
	}
	return sum
}

func newTcpCommand() *cobra.Command {
	// cfg holds the configuration for this command, populated by flags
	cfg := &tcpCmdConfig{}

	cmd := &cobra.Command{
		Use:   "tcp [link]",
		Short: "Examine TCP Connection delay to config's host",
		Long: `Measures how long a plain TCP connection to a config's server takes (no
proxy handshake). Useful to tell an unreachable server from a broken config.

Examples:
  xray-knife net tcp -c "vless://..."
  xray-knife net tcp "vless://..." -n 5 --interval 500ms
  xray-knife net tcp -c "tg://proxy?server=..." --json`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 1 {
				if cfg.configLink != "" {
					return exitcode.New(exitcode.Usage, errors.New("pass the link either as an argument or with -c, not both"))
				}
				cfg.configLink = args[0]
			}
			if cfg.configLink == "" {
				return exitcode.New(exitcode.Usage, errors.New("config link is required for the tcp command. Use -c or --config"))
			}
			if cfg.count < 1 {
				return exitcode.New(exitcode.Usage, errors.New("--count must be at least 1"))
			}
			if cfg.timeout <= 0 {
				return exitcode.New(exitcode.Usage, errors.New("--timeout must be positive"))
			}
			if cfg.interval < 0 {
				return exitcode.New(exitcode.Usage, errors.New("--interval must not be negative"))
			}

			target, err := targetOf(cfg.configLink)
			if err != nil {
				return err
			}

			report := func(i int, rtt time.Duration, err error) {
				if cfg.json {
					return
				}
				if err != nil {
					customlog.Printf(customlog.Failure, "[%d] couldn't establish tcp conn to %s: %v\n", i+1, target, err)
					return
				}
				customlog.Printf(customlog.Success, "[%d] Established TCP connection to %s in %dms\n", i+1, target, rtt.Milliseconds())
			}
			sum := probe(cmd.Context(), cfg, target, report)

			if cfg.json {
				enc := json.NewEncoder(os.Stdout)
				enc.SetIndent("", "  ")
				if err := enc.Encode(sum); err != nil {
					return err
				}
			} else if cfg.count > 1 && sum.Sent > 0 {
				fmt.Printf("--- %s ---\n%d probes, %d connected, %.0f%% loss", target, sum.Sent, sum.Received, sum.LossPct)
				if sum.Received > 0 {
					fmt.Printf(", min/avg/max = %.1f/%.1f/%.1f ms", sum.MinMs, sum.AvgMs, sum.MaxMs)
				}
				fmt.Println()
			}

			if err := cmd.Context().Err(); err != nil {
				return err
			}
			if sum.Received == 0 {
				msg := fmt.Sprintf("couldn't establish a tcp conn to %s", target)
				if len(sum.Errors) > 0 {
					msg += ": " + sum.Errors[len(sum.Errors)-1]
				}
				if cfg.json {
					return exitcode.Silent(exitcode.Error)
				}
				return errors.New(msg)
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&cfg.configLink, "config", "c", "", "The config link (any supported protocol, including tg://proxy)")
	cmd.Flags().DurationVar(&cfg.timeout, "timeout", 5*time.Second, "Timeout for each connection attempt")
	cmd.Flags().IntVarP(&cfg.count, "count", "n", 1, "Number of connection attempts")
	cmd.Flags().DurationVar(&cfg.interval, "interval", time.Second, "Pause between attempts")
	cmd.Flags().BoolVarP(&cfg.json, "json", "j", false, "Print a JSON summary instead of log lines")
	return cmd
}
