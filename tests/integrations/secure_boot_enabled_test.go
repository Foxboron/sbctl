// +build integrations

package main

import (
	"testing"

	"github.com/foxboron/go-uefi/efi"
	"github.com/foxboron/sbctl/tests/utils"
)

func TestSecureBootEnabled(t *testing.T) {

	utils.Exec("/mnt/sbctl status")

	if !efi.GetSecureBoot() {
		t.Fatal("not in secure boot mode")
	}

	if efi.GetSetupMode() {
		t.Fatal("in setup mode")
	}
}
