package mitmdf

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"
)

func GenerateCertificate(certPath, keyPath string, force bool) error {
	if !force {
		if _, err := os.Stat(certPath); err == nil {
			if _, err := os.Stat(keyPath); err == nil {
				return nil
			}
		}
	}

	dir := filepath.Dir(certPath)
	if dir != "" {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("failed to create cert directory: %w", err)
		}
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("failed to generate RSA key: %w", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return fmt.Errorf("failed to generate serial: %w", err)
	}

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   "MITM-DomainFronting Root CA",
			Organization: []string{"MITM-DomainFronting"},
		},
		NotBefore:             time.Now().Add(-24 * time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
		DNSNames:              []string{"localhost", "fromMitM"},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return fmt.Errorf("failed to create certificate: %w", err)
	}

	certFile, err := os.Create(certPath)
	if err != nil {
		return fmt.Errorf("failed to create cert file: %w", err)
	}
	defer certFile.Close()

	if err := pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: certDER}); err != nil {
		return fmt.Errorf("failed to write cert PEM: %w", err)
	}

	keyFile, err := os.Create(keyPath)
	if err != nil {
		return fmt.Errorf("failed to create key file: %w", err)
	}
	defer keyFile.Close()

	keyPEM := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}
	if err := pem.Encode(keyFile, keyPEM); err != nil {
		return fmt.Errorf("failed to write key PEM: %w", err)
	}

	return nil
}

func CheckCertificate(certPath, keyPath string) bool {
	if _, err := os.Stat(certPath); os.IsNotExist(err) {
		return false
	}
	if _, err := os.Stat(keyPath); os.IsNotExist(err) {
		return false
	}
	if data, err := os.ReadFile(certPath); err == nil {
		block, _ := pem.Decode(data)
		if block != nil && block.Type == "CERTIFICATE" {
			if _, err := x509.ParseCertificate(block.Bytes); err == nil {
				return true
			}
		}
	}
	return false
}

type InstallResult struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
	Command string `json:"command,omitempty"`
}

func InstallCert(certPath string) InstallResult {
	if runtime.GOOS != "linux" {
		return InstallResult{
			Message: fmt.Sprintf("Auto-install only supported on Linux. Copy %s to your system trust store manually.", certPath),
			Command: fmt.Sprintf("cp %s /usr/local/share/ca-certificates/mitmdf-root-ca.crt && sudo update-ca-certificates", certPath),
		}
	}

	data, err := os.ReadFile(certPath)
	if err != nil {
		return InstallResult{Message: fmt.Sprintf("Cannot read cert file: %v", err)}
	}

	// Determine system ca store layout
	type caLayout struct {
		Dir     string
		Ext     string
		Cmd     string
		CmdArgs []string
	}

	var layouts []caLayout

	// Detect distro via available commands
	if _, err := exec.LookPath("update-ca-certificates"); err == nil {
		layouts = append(layouts, caLayout{
			Dir: "/usr/local/share/ca-certificates",
			Ext: ".crt",
			Cmd: "update-ca-certificates",
		})
		layouts = append(layouts, caLayout{
			Dir: "/usr/share/ca-certificates",
			Ext: ".crt",
			Cmd: "update-ca-certificates",
		})
	}
	if _, err := exec.LookPath("update-ca-trust"); err == nil {
		layouts = append(layouts, caLayout{
			Dir:     "/etc/pki/ca-trust/source/anchors",
			Ext:     ".pem",
			Cmd:     "update-ca-trust",
			CmdArgs: []string{"extract"},
		})
	}
	if _, err := exec.LookPath("trust"); err == nil {
		layouts = append(layouts, caLayout{
			Dir:     "/etc/ca-certificates/trust-source/anchors",
			Ext:     ".pem",
			Cmd:     "trust",
			CmdArgs: []string{"extract-compat"},
		})
	}

	if len(layouts) == 0 {
		return InstallResult{
			Message: "No supported CA trust update command found. Install the cert manually.",
			Command: fmt.Sprintf("cp %s /usr/local/share/ca-certificates/mitmdf-root-ca.crt && sudo update-ca-certificates", certPath),
		}
	}

	firstErr := ""
	for _, l := range layouts {
		destName := "mitmdf-root-ca" + l.Ext
		dest := filepath.Join(l.Dir, destName)

		// Try to write directly
		if err := os.MkdirAll(l.Dir, 0755); err != nil {
			if firstErr == "" {
				firstErr = fmt.Sprintf("write %s: %v", dest, err)
			}
			continue
		}
		if err := os.WriteFile(dest, data, 0644); err != nil {
			if firstErr == "" {
				firstErr = fmt.Sprintf("write %s: %v", dest, err)
			}
			continue
		}

		cmd := exec.Command(l.Cmd, l.CmdArgs...)
		if out, err := cmd.CombinedOutput(); err != nil {
			// Command failed but cert file is in place
			return InstallResult{
				Success: true,
				Message: fmt.Sprintf("Copied cert to %s but trust update command failed: %s", dest, string(out)),
				Command: fmt.Sprintf("sudo %s %s", l.Cmd, joinArgs(l.CmdArgs)),
			}
		}

		return InstallResult{
			Success: true,
			Message: fmt.Sprintf("Certificate installed to %s and trust store updated.", dest),
		}
	}

	return InstallResult{
		Message: fmt.Sprintf("Could not install cert system-wide (%s). Install manually.", firstErr),
		Command: fmt.Sprintf("sudo cp %s /usr/local/share/ca-certificates/mitmdf-root-ca.crt && sudo update-ca-certificates", certPath),
	}
}

func joinArgs(args []string) string {
	s := ""
	for i, a := range args {
		if i > 0 {
			s += " "
		}
		s += a
	}
	return s
}
