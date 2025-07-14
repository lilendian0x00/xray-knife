package customlog

import (
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	"github.com/fatih/color"
)

// Type defines the level or category of the log message.
type Type uint8

// Defines the available log types.
var (
	Success    Type = 0x00
	Failure    Type = 0x01
	Processing Type = 0x02
	Finished   Type = 0x03
	Info       Type = 0x04
	Warning    Type = 0x05
	// None is for un-styled text, providing a neutral default.
	None Type = 0x06
)

// TypesDetails holds the visual properties for each log type.
type TypesDetails struct {
	symbol string
	color  *color.Color
}

// logTypeMap maps a log Type to its visual details (symbol and color).
var logTypeMap = map[Type]TypesDetails{
	Success:    {symbol: "[+]", color: color.New(color.Bold, color.FgGreen)},
	Failure:    {symbol: "[-]", color: color.New(color.Bold, color.FgRed)},
	Processing: {symbol: "[/]", color: color.New(color.Bold, color.FgBlue)},
	Finished:   {symbol: "[$]", color: color.New(color.BgGreen, color.FgBlack)},
	Info:       {symbol: "[i]", color: color.New(color.Bold, color.FgCyan)},
	Warning:    {symbol: "[!]", color: color.New(color.Bold, color.FgYellow)},
	None:       {symbol: "", color: color.New()}, // No symbol, default color
}

var (
	// Default output is os.Stderr
	output io.Writer = os.Stderr
	mu     sync.Mutex
)

// SetOutput sets the output destination for the custom logger.
// This is useful for redirecting logs to a file or a web socket.
func SetOutput(w io.Writer) {
	mu.Lock()
	defer mu.Unlock()
	output = w
}

// GetOutput returns the current output writer.
func GetOutput() io.Writer {
	mu.Lock()
	defer mu.Unlock()
	return output
}

// Printf prints a formatted, timestamped, and colored log message.
// It prepends the corresponding symbol and current time to the message.
func Printf(logType Type, format string, v ...interface{}) {
	mu.Lock()
	defer mu.Unlock()

	// Check if the current output is a terminal device.
	// This check is a bit tricky as the `output` can be anything.
	// We'll assume color is enabled unless we're sure it's not a tty.
	if f, ok := output.(*os.File); ok {
		stat, _ := f.Stat()
		color.NoColor = (stat.Mode() & os.ModeCharDevice) != os.ModeCharDevice
	} else {
		// For non-file writers (like web sockets), we typically want to send the raw string without ANSI color codes.
		// However, fatih/color handles this by checking the NO_COLOR env var. We can also force it.
		// For now, let's assume the receiver can handle it or we strip it elsewhere if needed.
		color.NoColor = false
	}

	t, ok := logTypeMap[logType]
	if !ok {
		// Fallback for an undefined type to prevent a panic.
		t = logTypeMap[None]
	}

	// Prepare the prefix with a symbol (if it exists) and a timestamp.
	prefix := ""
	if t.symbol != "" {
		prefix = t.symbol + " "
	}
	currentTime := time.Now()
	fullFormat := prefix + currentTime.Format("15:04:05") + " " + format

	// Use Fprintf to write to the designated output.
	t.color.Fprintf(output, fullFormat, v...)
}

// Println prints the given arguments to the designated output, followed by a newline.
func Println(v ...interface{}) {
	mu.Lock()
	defer mu.Unlock()
	fmt.Fprintln(output, v...)
}

// GetColor returns a string colored according to the specified log type.
func GetColor(logType Type, text string) string {
	t, ok := logTypeMap[logType]
	if !ok {
		t = logTypeMap[None]
	}
	return t.color.Sprint(text)
}
