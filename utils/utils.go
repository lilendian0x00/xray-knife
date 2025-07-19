package utils

import (
	"bufio"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/lilendian0x00/xray-knife/v6/utils/customlog"
)

func Base64Decode(b64 string) ([]byte, error) {
	b64 = strings.TrimSpace(b64)
	stdb64 := b64
	if pad := len(b64) % 4; pad != 0 {
		stdb64 += strings.Repeat("=", 4-pad)
	}

	b, err := base64.StdEncoding.DecodeString(stdb64)
	if err != nil {
		return base64.URLEncoding.DecodeString(b64)
	}
	return b, nil
}

func ParseFileByNewline(fileName string) []string {
	file, err := os.Open(fileName)
	if err != nil {
		customlog.Printf(customlog.Failure, "Error in reading file: %v\n", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)

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
