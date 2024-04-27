package utils

import (
	"os"
	"os/exec"
	"strings"
)

func Exec(c string) error {
	args := strings.Split(c, " ")
	cmd := exec.Command(args[0], args[1:]...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return err
	}
	return nil
}

func ExecWithOutput(c string) (string, error) {
	args := strings.Split(c, " ")
	cmd := exec.Command(args[0], args[1:]...)
	b, err := cmd.CombinedOutput()

	return string(b), err
}
