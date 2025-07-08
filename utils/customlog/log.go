package customlog

import (
	"fmt"
	"os"
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

// Printf prints a formatted, timestamped, and colored log message to the console.
// It prepends the corresponding symbol and current time to the message.
func Printf(logType Type, format string, v ...interface{}) {
	stat, _ := os.Stderr.Stat()
	color.NoColor = stat.Mode() & os.ModeCharDevice != os.ModeCharDevice

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

	t.color.Fprintf(os.Stderr, fullFormat, v...)
}

// Println prints the given arguments to the console, followed by a newline.
// It acts as a simple wrapper around fmt.Println and is useful for printing
// raw text or strings that have already been colored by GetColor.
func Println(v ...interface{}) {
	fmt.Fprintln(os.Stderr, v...)
}

// GetColor returns a string colored according to the specified log type.
// It does not add any symbols or timestamps. This is useful for coloring
// parts of a string before printing.
func GetColor(logType Type, text string) string {
	t, ok := logTypeMap[logType]
	if !ok {
		t = logTypeMap[None]
	}
	return t.color.Sprint(text)
}
