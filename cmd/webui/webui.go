package webui

import (
	"bufio"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/lilendian0x00/xray-knife/v11/utils"
	"github.com/lilendian0x00/xray-knife/v11/utils/customlog"

	"github.com/lilendian0x00/xray-knife/v11/web"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/bcrypt"

	"github.com/lilendian0x00/xray-knife/v11/utils/xkhome"
)

const (
	webuiConfigFilename = "webui.conf"
	defaultAuthUser     = "root"
)

// webuiCmdConfig holds the configuration for the webui command
type webuiCmdConfig struct {
	ListenAddress  string
	Port           uint16
	AuthUser       string
	AuthPassword   string
	AuthSecret     string
	TLSCert        string
	TLSKey         string
	AllowHosts     []string
	AllowHostModes bool
	// TrustProxyHeaders reads the client address from X-Real-IP /
	// X-Forwarded-For (only behind a reverse proxy you control).
	TrustProxyHeaders bool
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
// The password is stored only as a bcrypt hash.
func saveWebUIConfig(path string, config map[string]string) error {
	var builder strings.Builder
	builder.WriteString("# xray-knife Web UI credentials. The password is stored as a bcrypt hash;\n")
	builder.WriteString("# delete this file (or pass --auth.password) to set a new one.\n")
	fmt.Fprintf(&builder, "username=%s\n", config["username"])
	fmt.Fprintf(&builder, "password_hash=%s\n", config["password_hash"])
	fmt.Fprintf(&builder, "secret=%s\n", config["secret"])
	// Session bookkeeping: the epoch is mixed into the token signing key and
	// bumped when the password changes; the check detects that change.
	fmt.Fprintf(&builder, "session_epoch=%s\n", config["session_epoch"])
	fmt.Fprintf(&builder, "session_check=%s\n", config["session_check"])

	// Write-then-rename so a crash never leaves a truncated file.
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(builder.String()), 0600); err != nil { // 0600: read/write for owner only
		return err
	}
	return os.Rename(tmp, path)
}

// credentialInputs are the raw sources for each credential, in priority
// order flag > environment > webui.conf > generated.
type credentialInputs struct {
	FlagUser, FlagPass, FlagSecret string
	FlagUserSet                    bool
	FlagPassSet                    bool
	FlagSecretSet                  bool
	Env                            func(string) string
	File                           map[string]string
}

// resolvedCredentials is what the server starts with, plus what (if
// anything) must be written back to webui.conf.
type resolvedCredentials struct {
	User         string
	Password     string // plaintext, only when given or generated this run
	PasswordHash string // bcrypt, when the password came from the file
	Secret       string

	UserSource, PasswordSource, SecretSource string // flag, env, file, generated, default

	// SessionEpoch is mixed into the JWT key; it moves when the password
	// changes, which ends every session issued with the old one.
	SessionEpoch uint64
	// SessionsReset is set when this run bumped the epoch.
	SessionsReset bool

	// Save is the full file content to persist, or nil when unchanged.
	Save map[string]string
	// MigratedPlaintext is set when a legacy plaintext password was hashed.
	MigratedPlaintext bool
}

// resolveCredentials decides every credential independently: a flag or
// environment value never causes the others to be regenerated, and only
// generated (or migrated) values are persisted. Flag/env passwords are
// never written to disk.
func resolveCredentials(in credentialInputs, genPassword, genSecret func() (string, error), hash func(string) (string, error)) (*resolvedCredentials, error) {
	env := in.Env
	if env == nil {
		env = func(string) string { return "" }
	}
	file := in.File
	if file == nil {
		file = map[string]string{}
	}
	rc := &resolvedCredentials{}
	save := map[string]string{
		"username":      file["username"],
		"password_hash": file["password_hash"],
		"secret":        file["secret"],
		"session_epoch": file["session_epoch"],
		"session_check": file["session_check"],
	}
	changed := false

	// A legacy plaintext password never stays on disk, whatever this run
	// uses: it moves into password_hash (unless one exists) and is dropped.
	if file["password"] != "" {
		if !web.IsPasswordHash(file["password_hash"]) {
			h, err := hash(file["password"])
			if err != nil {
				return nil, err
			}
			save["password_hash"] = h
		}
		rc.MigratedPlaintext = true
		changed = true
	}

	switch {
	case in.FlagUserSet && in.FlagUser != "":
		rc.User, rc.UserSource = in.FlagUser, "flag"
	case env("XRAY_KNIFE_WEBUI_USER") != "":
		rc.User, rc.UserSource = env("XRAY_KNIFE_WEBUI_USER"), "env"
	case file["username"] != "":
		rc.User, rc.UserSource = file["username"], "file"
	default:
		rc.User, rc.UserSource = defaultAuthUser, "default"
	}

	switch {
	case in.FlagPassSet && in.FlagPass != "":
		rc.Password, rc.PasswordSource = in.FlagPass, "flag"
	case env("XRAY_KNIFE_WEBUI_PASS") != "":
		rc.Password, rc.PasswordSource = env("XRAY_KNIFE_WEBUI_PASS"), "env"
	case web.IsPasswordHash(save["password_hash"]):
		rc.PasswordHash, rc.PasswordSource = save["password_hash"], "file"
	default:
		p, err := genPassword()
		if err != nil {
			return nil, fmt.Errorf("failed to generate random password: %w", err)
		}
		h, err := hash(p)
		if err != nil {
			return nil, err
		}
		rc.Password, rc.PasswordSource = p, "generated"
		save["password_hash"] = h
		// Pair the stored hash with the user it was generated for.
		save["username"] = rc.User
		changed = true
	}

	switch {
	case in.FlagSecretSet && in.FlagSecret != "":
		rc.Secret, rc.SecretSource = in.FlagSecret, "flag"
	case env("XRAY_KNIFE_WEBUI_SECRET") != "":
		rc.Secret, rc.SecretSource = env("XRAY_KNIFE_WEBUI_SECRET"), "env"
	case file["secret"] != "":
		rc.Secret, rc.SecretSource = file["secret"], "file"
	default:
		s, err := genSecret()
		if err != nil {
			return nil, fmt.Errorf("failed to generate JWT secret: %w", err)
		}
		rc.Secret, rc.SecretSource = s, "generated"
		save["secret"] = s
		changed = true
	}

	// Session epoch: sessions survive restarts with the same password, and
	// end when it changes. session_check is a bcrypt hash of the password
	// in use (or the stored password_hash itself), never the password.
	epoch, _ := strconv.ParseUint(save["session_epoch"], 10, 64)
	check := save["session_check"]
	samePassword := func() bool {
		if rc.Password != "" {
			return bcrypt.CompareHashAndPassword([]byte(check), []byte(rc.Password)) == nil
		}
		return check == rc.PasswordHash
	}
	if check == "" || !samePassword() {
		if check != "" {
			epoch++
			rc.SessionsReset = true
		}
		newCheck := rc.PasswordHash
		if rc.Password != "" {
			if rc.PasswordSource == "generated" {
				newCheck = save["password_hash"]
			} else {
				h, err := hash(rc.Password)
				if err != nil {
					return nil, err
				}
				newCheck = h
			}
		}
		save["session_check"] = newCheck
		save["session_epoch"] = strconv.FormatUint(epoch, 10)
		changed = true
	}
	rc.SessionEpoch = epoch

	if changed {
		if save["username"] == "" {
			save["username"] = rc.User
		}
		rc.Save = save
	}
	return rc, nil
}

func hashPassword(p string) (string, error) {
	h, err := web.HashPassword(p)
	if err != nil {
		return "", fmt.Errorf("failed to hash password: %w", err)
	}
	return string(h), nil
}

func isLoopbackAddr(host string) bool {
	host = strings.Trim(host, "[]")
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func newWebUICommand() *cobra.Command {
	cfg := &webuiCmdConfig{}

	cmd := &cobra.Command{
		Use:   "webui",
		Short: "Starts a web-based user interface for managing xray-knife.",
		Long: `Launches a local web server to provide a graphical user interface
for all of xray-knife's core functionalities, including proxy management,
configuration testing, and scanning.

Credentials are resolved per field, in this order:
  1. --auth.user / --auth.password / --auth.secret
  2. XRAY_KNIFE_WEBUI_USER / XRAY_KNIFE_WEBUI_PASS / XRAY_KNIFE_WEBUI_SECRET
  3. webui.conf in the xray-knife directory (password stored as a bcrypt hash)
  4. generated (default user "root"; the password is printed once and saved hashed)
Passwords given by flag or environment are never written to disk.`,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if (cfg.TLSCert == "") != (cfg.TLSKey == "") {
				return fmt.Errorf("--tls-cert and --tls-key must be given together")
			}

			// Locate the config file inside the xray-knife state directory
			configDir, err := xkhome.Dir()
			if err != nil {
				return fmt.Errorf("could not resolve the xray-knife directory: %w", err)
			}
			configFilePath := filepath.Join(configDir, webuiConfigFilename)

			fileConfig, err := loadWebUIConfig(configFilePath)
			if err != nil {
				customlog.Printf(customlog.Warning, "Could not read config file at %s: %v\n", configFilePath, err)
				fileConfig = map[string]string{}
			}

			creds, err := resolveCredentials(credentialInputs{
				FlagUser:      cfg.AuthUser,
				FlagPass:      cfg.AuthPassword,
				FlagSecret:    cfg.AuthSecret,
				FlagUserSet:   cmd.Flag("auth.user").Changed,
				FlagPassSet:   cmd.Flag("auth.password").Changed,
				FlagSecretSet: cmd.Flag("auth.secret").Changed,
				Env:           os.Getenv,
				File:          fileConfig,
			}, func() (string, error) { return utils.GeneratePassword(16) },
				func() (string, error) { return generateJWTSecret(32) }, // 32 bytes = 256 bits
				hashPassword)
			if err != nil {
				return err
			}
			if creds.Save != nil {
				if err := saveWebUIConfig(configFilePath, creds.Save); err != nil {
					customlog.Printf(customlog.Failure, "Failed to save credentials to %s: %v\n", configFilePath, err)
				} else if creds.SessionsReset {
					customlog.Printf(customlog.Info, "The password changed: existing Web UI sessions were signed out.\n")
				} else if creds.MigratedPlaintext {
					customlog.Printf(customlog.Info, "Moved the plaintext password in %s to a bcrypt hash.\n", configFilePath)
				} else {
					customlog.Printf(customlog.Success, "Credentials saved to %s\n", configFilePath)
				}
			}
			if creds.PasswordSource == "flag" {
				customlog.Printf(customlog.Warning, "--auth.password is visible to other users in the process list; prefer XRAY_KNIFE_WEBUI_PASS.\n")
			}

			addr := net.JoinHostPort(strings.Trim(cfg.ListenAddress, "[]"), strconv.Itoa(int(cfg.Port)))
			scheme := "http"
			if cfg.TLSCert != "" {
				scheme = "https"
			}
			if !isLoopbackAddr(cfg.ListenAddress) && cfg.TLSCert == "" {
				customlog.Printf(customlog.Warning, "Listening on %s without TLS: the login and every API call cross the network in plaintext. Use --tls-cert/--tls-key, an SSH tunnel, or bind 127.0.0.1.\n", cfg.ListenAddress)
			}

			// Use fmt to print to console before customlog is redirected by the server
			fmt.Printf("%s Starting Web UI server on %s://%s\n", customlog.GetColor(customlog.Success, "[+]"), scheme, addr)

			// Show credentials
			fmt.Println(customlog.GetColor(customlog.Warning, "\n--- Please use the following credentials to log in ---"))
			fmt.Printf("Username: %s\n", customlog.GetColor(customlog.Success, creds.User))
			switch creds.PasswordSource {
			case "generated":
				fmt.Printf("Password: %s  (generated; shown only now, stored hashed)\n", customlog.GetColor(customlog.Success, creds.Password))
			case "file":
				fmt.Printf("Password: (unchanged, stored hashed in %s)\n", configFilePath)
			default:
				fmt.Printf("Password: (from %s)\n", map[string]string{"flag": "--auth.password", "env": "XRAY_KNIFE_WEBUI_PASS"}[creds.PasswordSource])
			}
			fmt.Println(customlog.GetColor(customlog.Warning, "-----------------------------------------------------\n"))

			fmt.Printf("%s Press CTRL+C to stop the server.\n", customlog.GetColor(customlog.Info, "[i]"))

			// Use the final resolved credentials to start the server
			server, err := web.NewServerWithOptions(web.Options{
				ListenAddr:     addr,
				Username:       creds.User,
				Password:       creds.Password,
				PasswordHash:   creds.PasswordHash,
				Secret:         creds.Secret,
				TLSCertFile:    cfg.TLSCert,
				TLSKeyFile:     cfg.TLSKey,
				AllowedHosts:   cfg.AllowHosts,
				AllowHostModes: cfg.AllowHostModes,
				Version:        cmd.Root().Version,
				LogToStderr:    true,
				SessionEpoch:   creds.SessionEpoch,

				TrustProxyHeaders: cfg.TrustProxyHeaders,
			})
			if err != nil {
				return fmt.Errorf("could not create web server: %w", err)
			}

			return server.Run()
		},
	}

	cmd.Flags().StringVarP(&cfg.ListenAddress, "addr", "a", "127.0.0.1", "The IP address for the web server to listen on.")
	cmd.Flags().Uint16VarP(&cfg.Port, "port", "p", 8080, "The port for the web server to listen on.")
	cmd.Flags().StringVar(&cfg.AuthUser, "auth.user", "", "Username for web UI authentication (default: root, env: XRAY_KNIFE_WEBUI_USER)")
	cmd.Flags().StringVar(&cfg.AuthPassword, "auth.password", "", "Password for web UI authentication (env: XRAY_KNIFE_WEBUI_PASS; the env var keeps it out of the process list)")
	cmd.Flags().StringVar(&cfg.AuthSecret, "auth.secret", "", "Secret key for signing JWTs (env: XRAY_KNIFE_WEBUI_SECRET)")
	cmd.Flags().StringVar(&cfg.TLSCert, "tls-cert", "", "Serve HTTPS with this certificate file (PEM); needs --tls-key")
	cmd.Flags().StringVar(&cfg.TLSKey, "tls-key", "", "Private key file (PEM) for --tls-cert")
	cmd.Flags().StringSliceVar(&cfg.AllowHosts, "allow-host", nil, "Extra Host header value to accept (repeatable), e.g. a hostname that points at this machine")
	cmd.Flags().BoolVar(&cfg.AllowHostModes, "allow-host-modes", false, "Allow the web UI to start the proxy in app/tun mode (reconfigures host networking; needs root)")
	cmd.Flags().BoolVar(&cfg.TrustProxyHeaders, "trust-proxy-headers", false, "Take the client address from X-Real-IP / X-Forwarded-For for rate limiting (only behind a reverse proxy you control)")

	return cmd
}
