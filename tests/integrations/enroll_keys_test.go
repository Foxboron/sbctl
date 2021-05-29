// +build integrations

package main

import (
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/foxboron/go-uefi/efi"
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

func TestEnrollKeys(t *testing.T) {

	if !efi.GetSetupMode() {
		t.Fatal("not in setup mode")
	}

	if efi.GetSecureBoot() {
		t.Fatal("in secure boot mode")
	}

	Exec("/mnt/sbctl status")

	if !efi.GetSetupMode() {
		t.Fatal("not in setup mode")
	}

}
