package logging

import (
	"fmt"
	"io"
	"os"

	"github.com/fatih/color"
)

var (
	OkSym    = "✓"
	NotOkSym = "✗"
	WarnSym  = "‼"
	UnkwnSym = "⁇"
)
var (
	OkSymText    = "[+]"
	NotOkSymText = "[-]"
	WarnSymText  = "[!]"
	UnkwnSymText = "[?]"
)

var (
	ok    string
	notok string
	warn  string
	unkwn string
)

var (
	on          bool
	DisableInfo bool      = false
	output      io.Writer = os.Stdout
)

func PrintOn() {
	on = true
}

func PrintOff() {
	on = false
}

func SetOutput(w io.Writer) {
	output = w
}

func PrintWithFile(f io.Writer, msg string, a ...interface{}) {
	if on {
		fmt.Fprintf(f, msg, a...)
	}
}

func Print(msg string, a ...interface{}) {
	if DisableInfo && output == os.Stdout {
		return
	}
	PrintWithFile(output, msg, a...)
}

func Println(msg string) {
	if DisableInfo && output == os.Stdout {
		return
	}
	PrintWithFile(output, msg+"\n")
}

func Okf(m string, a ...interface{}) string {
	return fmt.Sprintf("%s %s\n", ok, fmt.Sprintf(m, a...))
}

// Print ok string to stdout
func Ok(m string, a ...interface{}) {
	Print(Okf(m, a...))
}

func NotOkf(m string, a ...interface{}) string {
	return fmt.Sprintf("%s %s\n", notok, fmt.Sprintf(m, a...))
}

// Print ok string to stdout
func NotOk(m string, a ...interface{}) {
	Print(NotOkf(m, a...))
}

func Unknownf(m string, a ...interface{}) string {
	return fmt.Sprintf("%s %s\n", unkwn, fmt.Sprintf(m, a...))
}

func Unknown(m string, a ...interface{}) {
	Print(Unknownf(m, a...))
}

func Warnf(m string, a ...interface{}) string {
	return fmt.Sprintf("%s %s\n", warn, fmt.Sprintf(m, a...))
}
func Warn(m string, a ...interface{}) {
	PrintWithFile(os.Stderr, Warnf(m, a...))
}

func Fatalf(m string, a ...interface{}) string {
	return color.New(color.FgRed, color.Bold).Sprintf("%s %s\n", UnkwnSym, fmt.Sprintf(m, a...))
}

func Fatal(err error) {
	PrintWithFile(os.Stderr, Fatalf(err.Error()))
}

func Errorf(m string, a ...interface{}) string {
	return color.New(color.FgRed, color.Bold).Sprintf("%s\n", fmt.Sprintf(m, a...))
}

func Error(err error) {
	PrintWithFile(os.Stderr, Errorf(err.Error()))
}

func init() {
	if ok := os.Getenv("SBCTL_UNICODE"); ok == "0" {
		OkSym = OkSymText
		NotOkSym = NotOkSymText
		WarnSym = WarnSymText
		UnkwnSym = UnkwnSymText
	}

	ok = color.New(color.FgGreen, color.Bold).Sprintf(OkSym)
	notok = color.New(color.FgRed, color.Bold).Sprintf(NotOkSym)
	warn = color.New(color.FgYellow, color.Bold).Sprintf(WarnSym)
	unkwn = color.New(color.FgRed, color.Bold).Sprintf(UnkwnSym)
	PrintOn()
}
