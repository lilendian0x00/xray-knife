package utils

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"xray-knife/utils/customlog"
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
	err := os.WriteFile(fileName, data, 0644)
	if err != nil {
		return err
	}
	return nil
}

func ClearTerminal() {
	var cmd *exec.Cmd

	switch runtime.GOOS {
	case "linux", "darwin":
		cmd = exec.Command("clear")
	case "windows":
		cmd = exec.Command("cmd", "/c", "cls")
	default:
		fmt.Println("Unsupported operating system")
		return
	}

	cmd.Stdout = os.Stdout
	cmd.Run()
}
