package logging

import (
	"fmt"
	"os"

	"github.com/fatih/color"
)

var (
	OkSym    = "✔"
	ErrSym   = "✘"
	WarnSym  = "‼"
	UnkwnSym = "⁇"
)
var (
	OkSymText    = "[+]"
	ErrSymText   = "[-]"
	WarnSymText  = "[!]"
	UnkwnSymText = "[?]"
)

var (
	ok    string
	err   string
	warn  string
	unkwn string
)

var (
	on bool
)

func PrintOn() {
	on = true
}

func PrintOff() {
	on = false
}

func PrintWithFile(f *os.File, msg string, a ...interface{}) {
	if on {
		fmt.Fprintf(f, msg, a...)
	}
}

func Print(msg string, a ...interface{}) {
	PrintWithFile(os.Stdout, msg, a...)
}

// Print ok string to stdout
func Ok(m string, a ...interface{}) {
	Print(fmt.Sprintf("%s %s\n", ok, fmt.Sprintf(m, a...)))
}

func Error(m string, a ...interface{}) {
	Print(fmt.Sprintf("%s %s\n", err, fmt.Sprintf(m, a...)))
}

func Unknown(m string, a ...interface{}) {
	Print(fmt.Sprintf("%s %s\n", unkwn, fmt.Sprintf(m, a...)))
}

func Warn(m string, a ...interface{}) {
	Print(fmt.Sprintf("%s %s\n", warn, fmt.Sprintf(m, a...)))
}

func Fatal(err error) {
	m := color.New(color.FgRed, color.Bold).Sprintf("%s %s", UnkwnSym, err.Error())
	PrintWithFile(os.Stderr, m)
}

func init() {
	if ok := os.Getenv("EFIBOOTCTL_UNICODE"); ok == "0" {
		OkSym = OkSymText
		ErrSym = ErrSymText
		WarnSym = WarnSymText
		UnkwnSym = UnkwnSymText
	}

	ok = color.New(color.FgGreen, color.Bold).Sprintf(OkSym)
	err = color.New(color.FgRed, color.Bold).Sprintf(ErrSym)
	warn = color.New(color.FgYellow, color.Bold).Sprintf(WarnSym)
	unkwn = color.New(color.FgRed, color.Bold).Sprintf(UnkwnSym)
	PrintOn()
}
