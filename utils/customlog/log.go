package customlog

import (
	"github.com/fatih/color"
	"time"
)

type Type uint8

var (
	Success    Type = 0x00
	Failure    Type = 0x01
	Processing Type = 0x02
)

type TypesDetails struct {
	symbol string
	color  *color.Color
}

var logTypeMap = map[Type]TypesDetails{
	Success:    {symbol: "[+]", color: color.New(color.Bold, color.FgGreen)},
	Failure:    {symbol: "[-]", color: color.New(color.Bold, color.FgRed)},
	Processing: {symbol: "[/]", color: color.New(color.Bold, color.FgBlue)},
}

func Printf(logType Type, format string, v ...interface{}) {
	t := logTypeMap[logType]
	currentTime := time.Now()
	t.color.Printf(t.symbol+" "+currentTime.Format("2006-01-02 15:04:05")+" "+format, v...)
}
