package utils

import (
	"bufio"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/lilendian0x00/xray-knife/v11/utils/customlog"
)

// Base64Decode decodes standard or URL-safe base64, padded or not.
// Share links in the wild use all four variants (v2rayN emits padded
// standard, SIP002 mandates unpadded URL-safe), so try each in turn.
func Base64Decode(b64 string) ([]byte, error) {
	b64 = strings.TrimSpace(b64)
	raw := strings.TrimRight(b64, "=")

	b, err := base64.RawStdEncoding.DecodeString(raw)
	if err == nil {
		return b, nil
	}
	if b, urlErr := base64.RawURLEncoding.DecodeString(raw); urlErr == nil {
		return b, nil
	}
	return nil, err
}

// ReadLinks reads one entry per line from path ("-" reads stdin). It
// strips a UTF-8 BOM, trims whitespace, and skips blank lines and lines
// starting with "#" or "//". Unlike ParseFileByNewline it reports a
// missing or unreadable file, and it returns an error when the file has
// no entries, so callers never silently fall back to another source.
func ReadLinks(path string) ([]string, error) {
	var r io.Reader
	if path == "-" {
		r = os.Stdin
	} else {
		f, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		r = f
	}
	lines, err := ReadLinksFrom(r)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	if len(lines) == 0 {
		return nil, fmt.Errorf("%s: no entries found", path)
	}
	return lines, nil
}

// ReadLinksFrom applies ReadLinks' line cleaning to an arbitrary reader.
// An empty input yields an empty slice and no error.
func ReadLinksFrom(r io.Reader) ([]string, error) {
	scanner := bufio.NewScanner(r)
	// Allow very long lines (e.g. vmess base64 blobs).
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	var lines []string
	first := true
	for scanner.Scan() {
		line := scanner.Text()
		if first {
			line = strings.TrimPrefix(line, "\uFEFF")
			first = false
		}
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
			continue
		}
		lines = append(lines, line)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return lines, nil
}

// ParseFileByNewline reads non-empty lines from fileName, logging (not
// returning) errors.
//
// Deprecated: use ReadLinks, which reports missing and empty files.
func ParseFileByNewline(fileName string) []string {
	file, err := os.Open(fileName)
	if err != nil {
		customlog.Printf(customlog.Failure, "Error in reading file: %v\n", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	// Increase buffer to 1MB to handle very long config lines (e.g. vmess base64 blobs)
	scanner.Buffer(make([]byte, 0, 1024*1024), 1024*1024)

	// Set the Scanner to split on newline characters
	scanner.Split(bufio.ScanLines)

	var lines []string
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}
		lines = append(lines, strings.TrimSpace(line))
	}

	if scanner.Err() != nil {
		customlog.Printf(customlog.Failure, "Error in parsing file: %v\n", scanner.Err())
	}
	return lines
}

func WriteIntoFile(fileName string, data []byte) error {
	var err error
	switch fileName {
	case "-":
		_, err = os.Stdout.Write(data)
	default:
		err = os.WriteFile(fileName, data, 0644)
	}
	if err != nil {
		return err
	}
	return nil
}

const (
	charSet = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	// Storing the length of the character set avoids recalculating it.
	charSetLength = len(charSet)
)

func GeneratePassword(length int) (string, error) {
	// Validate the input length. A password cannot have a zero or negative length.
	if length <= 0 {
		return "", fmt.Errorf("password length must be greater than 0")
	}

	password := make([]byte, length)

	randomBytes := make([]byte, length)

	if _, err := io.ReadFull(rand.Reader, randomBytes); err != nil {
		return "", fmt.Errorf("failed to read random bytes: %w", err)
	}

	for i := 0; i < length; i++ {
		randomByte := randomBytes[i]
		charIndex := int(randomByte) % charSetLength
		password[i] = charSet[charIndex]
	}

	return string(password), nil
}
