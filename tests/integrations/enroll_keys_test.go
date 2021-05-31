// +build integrations

package main

import (
	"testing"

	"github.com/foxboron/go-uefi/efi"
	"github.com/foxboron/sbctl/tests/utils"
)

func TestEnrollKeys(t *testing.T) {

	if efi.GetSecureBoot() {
		t.Fatal("in secure boot mode")
	}

	if !efi.GetSetupMode() {
		t.Fatal("not in setup mode")
	}

	utils.Exec("rm -rf /usr/share/secureboot")
	utils.Exec("/mnt/sbctl status")
	utils.Exec("/mnt/sbctl create-keys")
	utils.Exec("/mnt/sbctl enroll-keys")

	if efi.GetSetupMode() {
		t.Fatal("in setup mode")
	}

}
