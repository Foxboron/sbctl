package main

import (
	"testing"

	"github.com/foxboron/go-uefi/efi/efitest"
	"github.com/spf13/cobra"
)

var (
	out Status
)

func TestStatusOff(t *testing.T) {
	SetFS(efitest.SecureBootOff())

	if err := captureJsonOutput(&out, func() error {
		return RunStatus(&cobra.Command{}, []string{})
	}); err != nil {
		t.Fatal(err)
	}

	if out.SecureBoot != false {
		t.Fatal("secure boot is not disabled")
	}
}

func TestStatusOn(t *testing.T) {
	SetFS(efitest.SecureBootOn())

	if err := captureJsonOutput(&out, func() error {
		return RunStatus(&cobra.Command{}, []string{})
	}); err != nil {
		t.Fatal(err)
	}

	if out.SecureBoot != true {
		t.Fatal("secure boot is not enabled")
	}
}
