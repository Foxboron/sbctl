package sbctl

import (
	"bytes"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
)

var (
	plain    *log.Logger
	msg      *log.Logger
	msg2     *log.Logger
	warning  *log.Logger
	warning2 *log.Logger
	err      *log.Logger
	err2     *log.Logger
)

func GetColor(args string) string {
	out, _ := exec.Command("tput", strings.Split(args, " ")...).Output()
	return string(bytes.TrimSuffix(out, []byte("\n")))
}

func init() {
	var (
		red    = GetColor("setaf 1")
		green  = GetColor("setaf 2")
		yellow = GetColor("setaf 3")
		blue   = GetColor("setaf 4")
		bold   = GetColor("bold")
		off    = GetColor("sgr0")
		// I didn't bother figure out how we get this to the end of the log format
		// So we just clear the terminal stuff at the start of each log line
		prefix = fmt.Sprintf("%s", off)
	)
	plainfmt := fmt.Sprintf("%s%s ", prefix, bold)
	plain = log.New(os.Stdout, plainfmt, 0)

	msgfmt := fmt.Sprintf("%s%s%s==>%s%s ", prefix, bold, green, off, bold)
	msg = log.New(os.Stdout, msgfmt, 0)

	msg2fmt := fmt.Sprintf("%s%s%s  ->%s%s ", prefix, bold, blue, off, bold)
	msg2 = log.New(os.Stdout, msg2fmt, 0)

	warningfmt := fmt.Sprintf("%s%s%s==> WARNING:%s%s ", prefix, bold, yellow, off, bold)
	warning = log.New(os.Stderr, warningfmt, 0)

	warning2fmt := fmt.Sprintf("%s%s%s  -> WARNING:%s%s ", prefix, bold, yellow, off, bold)
	warning2 = log.New(os.Stderr, warning2fmt, 0)

	errfmt := fmt.Sprintf("%s%s%s==> ERROR:%s%s ", prefix, bold, red, off, bold)
	err = log.New(os.Stderr, errfmt, 0)

	err2fmt := fmt.Sprintf("%s%s%s  -> ERROR:%s%s ", prefix, bold, red, off, bold)
	err2 = log.New(os.Stderr, err2fmt, 0)
}
