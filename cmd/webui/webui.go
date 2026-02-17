package webui

import (
	"bufio"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"github.com/lilendian0x00/xray-knife/v7/utils"
	"github.com/lilendian0x00/xray-knife/v7/utils/customlog"
	"os"
	"path/filepath"
	"strings"

	"github.com/lilendian0x00/xray-knife/v7/web"
	"github.com/spf13/cobra"
)

const (
	webuiConfigFilename = "webui.conf"
	defaultAuthUser     = "root"
)

// webuiCmdConfig holds the configuration for the webui command
type webuiCmdConfig struct {
	ListenAddress string
	Port          uint16
	AuthUser      string
	AuthPassword  string
	AuthSecret    string
}

// WebUICmd is the webui subcommand.
var WebUICmd = newWebUICommand()

// generateJWTSecret makes a random base64 string for use as a JWT secret.
func generateJWTSecret(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(bytes), nil
}

// loadWebUIConfig loads credentials from the webui.conf file.
func loadWebUIConfig(path string) (map[string]string, error) {
	config := make(map[string]string)
	file, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return config, nil // File not existing is not an error here
		}
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) == 2 {
			config[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}
	}
	return config, scanner.Err()
}

// saveWebUIConfig saves credentials to the webui.conf file with secure permissions.
func saveWebUIConfig(path string, config map[string]string) error {
	var builder strings.Builder
	builder.WriteString("# xray-knife Web UI Credentials\n")
	builder.WriteString(fmt.Sprintf("username=%s\n", config["username"]))
	builder.WriteString(fmt.Sprintf("password=%s\n", config["password"]))
	builder.WriteString(fmt.Sprintf("secret=%s\n", config["secret"]))

	return os.WriteFile(path, []byte(builder.String()), 0600) // 0600: read/write for owner only
}

func newWebUICommand() *cobra.Command {
	cfg := &webuiCmdConfig{}

	cmd := &cobra.Command{
		Use:   "webui",
		Short: "Starts a web-based user interface for managing xray-knife.",
		Long: `Launches a local web server to provide a graphical user interface
for all of xray-knife's core functionalities, including proxy management,
configuration testing, and scanning.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			// Find home directory to locate the config file
			home, err := os.UserHomeDir()
			if err != nil {
				return fmt.Errorf("could not find user home directory: %w", err)
			}
			configDir := filepath.Join(home, ".xray-knife")
			configFilePath := filepath.Join(configDir, webuiConfigFilename)

			// Determine final credentials based on priority: flags > env > file > generate
			finalUser := defaultAuthUser
			finalPass := ""
			finalSecret := ""
			//generated := false

			// Flags (highest priority)
			if cmd.Flag("auth.user").Changed {
				finalUser = cfg.AuthUser
			}
			if cmd.Flag("auth.password").Changed {
				finalPass = cfg.AuthPassword
			}
			if cmd.Flag("auth.secret").Changed {
				finalSecret = cfg.AuthSecret
			}

			// Environment variables (if flags not set)
			if !cmd.Flag("auth.user").Changed && os.Getenv("XRAY_KNIFE_WEBUI_USER") != "" {
				finalUser = os.Getenv("XRAY_KNIFE_WEBUI_USER")
			}
			if !cmd.Flag("auth.password").Changed && os.Getenv("XRAY_KNIFE_WEBUI_PASS") != "" {
				finalPass = os.Getenv("XRAY_KNIFE_WEBUI_PASS")
			}
			if !cmd.Flag("auth.secret").Changed && os.Getenv("XRAY_KNIFE_WEBUI_SECRET") != "" {
				finalSecret = os.Getenv("XRAY_KNIFE_WEBUI_SECRET")
			}

			// Config file (if flags and env not set)
			if finalPass == "" && finalSecret == "" {
				fileConfig, err := loadWebUIConfig(configFilePath)
				if err != nil {
					customlog.Printf(customlog.Warning, "Could not read config file at %s: %v\n", configFilePath, err)
				}
				if val, ok := fileConfig["username"]; ok {
					finalUser = val
				}
				if val, ok := fileConfig["password"]; ok {
					finalPass = val
				}
				if val, ok := fileConfig["secret"]; ok {
					finalSecret = val
				}
			}

			// Generate if still missing
			if finalPass == "" || finalSecret == "" {
				customlog.Printf(customlog.Info, "Generating new credentials for Web UI...\n")
				//generated = true

				newPass, err := utils.GeneratePassword(16)
				if err != nil {
					return fmt.Errorf("failed to generate random password: %w", err)
				}
				finalPass = newPass

				newSecret, err := generateJWTSecret(32) // 32 bytes = 256 bits
				if err != nil {
					return fmt.Errorf("failed to generate JWT secret: %w", err)
				}
				finalSecret = newSecret

				configToSave := map[string]string{
					"username": finalUser,
					"password": finalPass,
					"secret":   finalSecret,
				}
				if err := saveWebUIConfig(configFilePath, configToSave); err != nil {
					customlog.Printf(customlog.Failure, "Failed to save new credentials to %s: %v\n", configFilePath, err)
				} else {
					customlog.Printf(customlog.Success, "Credentials saved to %s\n", configFilePath)
				}
			}

			// Use fmt to print to console before customlog is redirected by the server
			fmt.Printf("%s Starting Web UI server on http://%s:%d\n", customlog.GetColor(customlog.Success, "[+]"), cfg.ListenAddress, cfg.Port)

			// Show credentials
			fmt.Println(customlog.GetColor(customlog.Warning, "\n--- Please use the following credentials to log in ---"))
			fmt.Printf("Username: %s\n", customlog.GetColor(customlog.Success, finalUser))
			fmt.Printf("Password: %s\n", customlog.GetColor(customlog.Success, finalPass))
			fmt.Println(customlog.GetColor(customlog.Warning, "-----------------------------------------------------\n"))

			fmt.Printf("%s Press CTRL+C to stop the server.\n", customlog.GetColor(customlog.Info, "[i]"))

			addr := fmt.Sprintf("%s:%d", cfg.ListenAddress, cfg.Port)

			// Use the final resolved credentials to start the server
			server, err := web.NewServer(addr, finalUser, finalPass, finalSecret)
			if err != nil {
				return fmt.Errorf("could not create web server: %w", err)
			}

			return server.Run()
		},
	}

	cmd.Flags().StringVarP(&cfg.ListenAddress, "addr", "a", "127.0.0.1", "The IP address for the web server to listen on.")
	cmd.Flags().Uint16VarP(&cfg.Port, "port", "p", 8080, "The port for the web server to listen on.")
	cmd.Flags().StringVar(&cfg.AuthUser, "auth.user", "", "Username for web UI authentication (default: root, env: XRAY_KNIFE_WEBUI_USER)")
	cmd.Flags().StringVar(&cfg.AuthPassword, "auth.password", "", "Password for web UI authentication (env: XRAY_KNIFE_WEBUI_PASS)")
	cmd.Flags().StringVar(&cfg.AuthSecret, "auth.secret", "", "Secret key for signing JWTs (env: XRAY_KNIFE_WEBUI_SECRET)")

	return cmd
}
