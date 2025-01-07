package prompt

import (
	"fmt"
	"github.com/foxboron/sbctl/logging"
	"github.com/manifoldco/promptui"
	"golang.org/x/sys/unix"
	"os"
	"os/exec"
)

func SBCTLPrompt(validate func(string) error, label string, mask *rune) (string, error) {
	if IsTerminal(os.Stdout.Fd()) {
		return TTYPrompt(validate, label, mask)
	} else {
		logging.Warn("not running in a TTY -- prompting with systemd-ask-password")
		logging.Warn(fmt.Sprintf("(PROMPT) %s", label))
		logging.Print("Run \"systemd-tty-ask-password-agent --query\" in another terminal\n")
		cmd := exec.Command("/usr/bin/systemd-ask-password",
			"--emoji=no",
			"--timeout=0",
			"-n",
			"--echo=masked",
		)
		output, err := cmd.Output()
		if err != nil {
			return "", err
		}
		if err = validate(string(output)); err != nil {
			return "", err
		} else {
			return string(output), nil
		}
	}
}

func TTYPrompt(validate func(string) error, label string, mask *rune) (string, error) {
	prompt := promptui.Prompt{
		Label:    label,
		Validate: validate,
	}
	if mask != nil {
		prompt.Mask = *mask
	}

	result, err := prompt.Run()
	if err != nil {
		return "", err
	}
	return result, nil
}

// IsTerminal return true if the file descriptor is terminal.
func IsTerminal(fd uintptr) bool {
	_, err := unix.IoctlGetTermios(int(fd), unix.TCGETS)
	return err == nil
}
