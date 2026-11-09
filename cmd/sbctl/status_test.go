package main

import (
	"reflect"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/foxboron/go-uefi/efi/efitest"
	"github.com/foxboron/sbctl/logging"
	"github.com/foxboron/sbctl/quirks"
)

var (
	out Status
)

// TestStatusSecureBootMissingSetupMode covers firmware that exposes the
// standard SecureBoot variable but no standalone SetupMode variable. Secure Boot
// must be reported as enabled and Setup Mode as unknown, following the kernel's
// interpretation, rather than rejected as "not UEFI".
func TestStatusSecureBootMissingSetupMode(t *testing.T) {
	cmd := SetFS(efitest.SecureBootOn()) // SecureBoot=1, no SetupMode variable

	if err := captureJsonOutput(&out, func() error {
		return RunStatus(cmd, []string{})
	}); err != nil {
		t.Fatalf("SecureBoot present but SetupMode missing should not be rejected: %v", err)
	}

	if out.SecureBoot != SecureBootEnabled {
		t.Fatal("expected secure boot enabled (kernel-compatible: missing SetupMode defaults to 0)")
	}
	if out.SetupMode != SetupModeUnknown {
		t.Fatalf("expected SetupMode unknown, got %v", out.SetupMode)
	}
}

// TestStatusSecureBootInSetupMode covers SecureBoot=1 while the system is in
// Setup Mode (SetupMode=1). Per the kernel interpretation this is reported as
// secure boot disabled and Setup Mode enabled.
func TestStatusSecureBootInSetupMode(t *testing.T) {
	cmd := SetFS(
		efitest.SecureBootOn(),
		fstest.MapFS{
			"/sys/firmware/efi/efivars/SetupMode-8be4df61-93ca-11d2-aa0d-00e098032b8c": {
				Data: []byte{0x6, 0x0, 0x0, 0x0, 0x1},
			},
		},
	)

	if err := captureJsonOutput(&out, func() error {
		return RunStatus(cmd, []string{})
	}); err != nil {
		t.Fatal(err)
	}

	if out.SecureBoot != SecureBootDisabled {
		t.Fatal("expected secure boot disabled while in setup mode")
	}
	if out.SetupMode != SetupModeEnabled {
		t.Fatalf("expected SetupMode enabled, got %v", out.SetupMode)
	}
}

// TestStatusNotUEFIWithoutEFIVariables ensures the UEFI gate still rejects
// machines that expose no EFI Secure Boot variables at all.
func TestStatusNotUEFIWithoutEFIVariables(t *testing.T) {
	cmd := SetFS(fstest.MapFS{})

	err := RunStatus(cmd, []string{})
	if err == nil {
		t.Fatal("expected 'not booted with UEFI' error, got nil")
	}
}

// TestStatusSetupModeOnly covers a machine where SetupMode is accessible but
// SecureBoot is absent. The presence of SetupMode still proves UEFI boot (it
// must not be rejected), but the Secure Boot on/off state cannot be established
// and is reported as unknown.
func TestStatusSetupModeOnly(t *testing.T) {
	cmd := SetFS(efitest.SetUpModeOn())

	if err := captureJsonOutput(&out, func() error {
		return RunStatus(cmd, []string{})
	}); err != nil {
		t.Fatalf("SetupMode present must be detected as UEFI, got error: %v", err)
	}
	if out.SetupMode != SetupModeEnabled {
		t.Fatalf("expected SetupMode enabled, got %v", out.SetupMode)
	}
	if out.SecureBoot != SecureBootUnknown {
		t.Fatalf("expected secure boot unknown (no SecureBoot variable), got %v", out.SecureBoot)
	}
}

// TestStatusSecureBootMalformed covers a machine where the standard SecureBoot
// variable exists but its contents cannot be parsed (wrong EFI attributes, for
// example). Presence still proves UEFI boot, but the Secure Boot state cannot
// be established and is reported as unknown rather than rejected or guessed.
func TestStatusSecureBootMalformed(t *testing.T) {
	cmd := SetFS(fstest.MapFS{
		"/sys/firmware/efi/efivars/SecureBoot-" + efiStandardVariableGUID: {
			// Attributes 0x0 instead of the expected 0x6: present but unreadable.
			Data: []byte{0x0, 0x0, 0x0, 0x0, 0x1},
		},
	})

	if err := captureJsonOutput(&out, func() error {
		return RunStatus(cmd, []string{})
	}); err != nil {
		t.Fatalf("a present-but-malformed SecureBoot variable must still be detected as UEFI, got error: %v", err)
	}
	if out.SecureBoot != SecureBootUnknown {
		t.Fatalf("expected secure boot unknown (malformed SecureBoot variable), got %v", out.SecureBoot)
	}
}

// TestStatusSecureBootSetupModeMalformed covers SecureBoot=1 (valid) together
// with a SetupMode variable that exists but cannot be parsed. Because the
// SetupMode read fails for a reason other than absence (a genuine read error),
// the Secure Boot state cannot be reliably derived and is reported as unknown
// rather than being inferred as enabled.
func TestStatusSecureBootSetupModeMalformed(t *testing.T) {
	cmd := SetFS(
		fstest.MapFS{
			"/sys/firmware/efi/efivars/SecureBoot-" + efiStandardVariableGUID: {
				Data: []byte{0x6, 0x0, 0x0, 0x0, 0x1}, // attributes ok, value 1
			},
		},
		fstest.MapFS{
			"/sys/firmware/efi/efivars/SetupMode-" + efiStandardVariableGUID: {
				// Attributes 0x0 instead of the expected 0x6: present but unreadable.
				Data: []byte{0x0, 0x0, 0x0, 0x0, 0x1},
			},
		},
	)

	if err := captureJsonOutput(&out, func() error {
		return RunStatus(cmd, []string{})
	}); err != nil {
		t.Fatalf("expected UEFI detection, got error: %v", err)
	}
	if out.SetupMode != SetupModeUnknown {
		t.Fatalf("expected SetupMode unknown (malformed SetupMode variable), got %v", out.SetupMode)
	}
	if out.SecureBoot != SecureBootUnknown {
		t.Fatalf("expected secure boot unknown when SetupMode cannot be read, got %v", out.SecureBoot)
	}
}

// TestStatusSetupModeOnlyHumanReadable covers a machine where only SetupMode is
// exposed. The human-readable output must report Secure Boot as unknown without
// claiming a particular firmware interface, since that has not been
// established.
func TestStatusSetupModeOnlyHumanReadable(t *testing.T) {
	logging.PrintOn()
	defer logging.PrintOff()

	cmd := SetFS(efitest.SetUpModeOn())

	prev := cmdOptions.JsonOutput
	cmdOptions.JsonOutput = false
	defer func() { cmdOptions.JsonOutput = prev }()
	output, err := captureOutput(func() error {
		return RunStatus(cmd, []string{})
	})
	if err != nil {
		t.Fatal(err)
	}

	if !strings.Contains(string(output), "Unknown") {
		t.Fatalf("expected Secure Boot to print as Unknown, got:\n%s", output)
	}
}

// TestStatusSecureBootConfigFirmware covers firmware that reports Secure Boot
// state through the "SecureBootData" variable instead of the standalone
// SetupMode/SecureBoot variables. Such firmware has neither variable, so its
// absence must not be treated as "not UEFI", and its Secure Boot on/off state
// must be reported as unknown (derived at boot by the kernel) rather than as
// disabled.
func TestStatusSecureBootConfigFirmware(t *testing.T) {
	cmd := SetFS(
		fstest.MapFS{
			"/sys/firmware/efi/efivars/SecureBootData-" + secureBootConfigGUID: {
				Data: []byte{0x6, 0x0, 0x0, 0x0, 0x0},
			},
		},
	)

	if err := captureJsonOutput(&out, func() error {
		return RunStatus(cmd, []string{})
	}); err != nil {
		t.Fatalf("firmware using SecureBootData must be detected as UEFI: %v", err)
	}

	if out.SecureBoot != SecureBootUnknown {
		t.Fatalf("expected secure boot unknown, got %v", out.SecureBoot)
	}
	if out.SetupMode != SetupModeUnknown {
		t.Fatalf("expected setup mode unknown, got %v", out.SetupMode)
	}
}

// TestStatusSecureBootConfigNote ensures the human-readable status output
// reports the Secure Boot state as unknown when it cannot be established from
// the available EFI variables.
func TestStatusSecureBootConfigNote(t *testing.T) {
	logging.PrintOn()
	defer logging.PrintOff()

	cmd := SetFS(
		fstest.MapFS{
			"/sys/firmware/efi/efivars/SecureBootData-" + secureBootConfigGUID: {
				Data: []byte{0x6, 0x0, 0x0, 0x0, 0x0},
			},
		},
	)

	prev := cmdOptions.JsonOutput
	cmdOptions.JsonOutput = false
	defer func() { cmdOptions.JsonOutput = prev }()
	output, err := captureOutput(func() error {
		return RunStatus(cmd, []string{})
	})
	if err != nil {
		t.Fatal(err)
	}

	if !strings.Contains(string(output), "Unknown") {
		t.Fatalf("expected Secure Boot to print as Unknown, got:\n%s", output)
	}
}

func TestStatusOff(t *testing.T) {
	cmd := SetFS(
		efitest.SecureBootOff(),
		efitest.SetUpModeOn(),
	)

	if err := captureJsonOutput(&out, func() error {
		return RunStatus(cmd, []string{})
	}); err != nil {
		t.Fatal(err)
	}

	if out.SecureBoot != SecureBootDisabled {
		t.Fatal("secure boot is not disabled")
	}
}

func TestStatusOn(t *testing.T) {
	// NB: efitest.SetUpModeOff() is buggy (it writes SetupMode=1), so build the
	// "setup mode disabled" fixture with the correct value here.
	cmd := SetFS(
		efitest.SecureBootOn(),
		fstest.MapFS{
			"/sys/firmware/efi/efivars/SetupMode-8be4df61-93ca-11d2-aa0d-00e098032b8c": {
				Data: []byte{0x6, 0x0, 0x0, 0x0, 0x0},
			},
		},
	)

	if err := captureJsonOutput(&out, func() error {
		return RunStatus(cmd, []string{})
	}); err != nil {
		t.Fatal(err)
	}

	if out.SecureBoot != SecureBootEnabled {
		t.Fatal("secure boot is not enabled")
	}
	if out.SetupMode != SetupModeDisabled {
		t.Fatalf("expected SetupMode disabled, got %v", out.SetupMode)
	}
}

func TestFQ0001DateMethod(t *testing.T) {
	cmd := SetFS(
		fstest.MapFS{"/sys/devices/virtual/dmi/id/bios_date": {Data: []byte("01/06/2023\n")}},
		fstest.MapFS{"/sys/devices/virtual/dmi/id/bios_version": {Data: []byte("A.30\n")}},
		fstest.MapFS{"/sys/devices/virtual/dmi/id/board_name": {Data: []byte("PRO Z790-A WIFI (MS-7E07)\n")}},
		fstest.MapFS{"/sys/devices/virtual/dmi/id/board_vendor": {Data: []byte("Micro-Star International Co., Ltd.\n")}},
		fstest.MapFS{"/sys/devices/virtual/dmi/id/chassis_type": {Data: []byte("3\n")}},
		fstest.MapFS{"/sys/devices/virtual/dmi/id/product_name": {Data: []byte("MS-7E07\n")}},
		efitest.SecureBootOn(),
		efitest.SetUpModeOff(),
	)

	if err := captureJsonOutput(&out, func() error {
		return RunStatus(cmd, []string{})
	}); err != nil {
		t.Fatal(err)
	}

	fq0001 := quirks.Quirk{}
	for _, quirk := range out.FirmwareQuirks {
		if quirk.ID == "FQ0001" {
			fq0001 = quirk
		}
	}

	if reflect.ValueOf(fq0001).IsZero() {
		t.Fatal("quirk not detected")
	} else if fq0001.Method != "date" {
		t.Fatal("expected 'date' method, got '" + fq0001.Method + "'")
	}
}

func TestFQ0001DeviceMethod(t *testing.T) {
	cmd := SetFS(
		fstest.MapFS{"/sys/devices/virtual/dmi/id/bios_date": {Data: []byte("12/29/2021\n")}},
		fstest.MapFS{"/sys/devices/virtual/dmi/id/bios_version": {Data: []byte("1.80\n")}},
		fstest.MapFS{"/sys/devices/virtual/dmi/id/board_name": {Data: []byte("MAG X570 TOMAHAWK WIFI (MS-7C84)\n")}},
		fstest.MapFS{"/sys/devices/virtual/dmi/id/board_vendor": {Data: []byte("Micro-Star International Co., Ltd.\n")}},
		fstest.MapFS{"/sys/devices/virtual/dmi/id/chassis_type": {Data: []byte("3\n")}},
		fstest.MapFS{"/sys/devices/virtual/dmi/id/product_name": {Data: []byte("MS-7C84\n")}},
		efitest.SecureBootOn(),
		efitest.SetUpModeOff(),
	)

	if err := captureJsonOutput(&out, func() error {
		return RunStatus(cmd, []string{})
	}); err != nil {
		t.Fatal(err)
	}

	fq0001 := quirks.Quirk{}
	for _, quirk := range out.FirmwareQuirks {
		if quirk.ID == "FQ0001" {
			fq0001 = quirk
		}
	}

	if reflect.ValueOf(fq0001).IsZero() {
		t.Fatal("quirk not detected")
	} else if fq0001.Method != "device_name" {
		t.Fatal("expected 'device_name' method, got '" + fq0001.Method + "'")
	}
}

func TestFQ0001ExplicitlyUnaffected(t *testing.T) {
	cmd := SetFS(
		fstest.MapFS{"/sys/devices/virtual/dmi/id/bios_date": {Data: []byte("03/31/2022\n")}},
		fstest.MapFS{"/sys/devices/virtual/dmi/id/bios_version": {Data: []byte("1.B0\n")}},
		fstest.MapFS{"/sys/devices/virtual/dmi/id/board_name": {Data: []byte("MAG Z490 TOMAHAWK (MS-7C80)\n")}},
		fstest.MapFS{"/sys/devices/virtual/dmi/id/board_vendor": {Data: []byte("Micro-Star International Co., Ltd.\n")}},
		fstest.MapFS{"/sys/devices/virtual/dmi/id/chassis_type": {Data: []byte("3\n")}},
		fstest.MapFS{"/sys/devices/virtual/dmi/id/product_name": {Data: []byte("MS-7C80\n")}},
		efitest.SecureBootOn(),
		efitest.SetUpModeOff(),
	)

	if err := captureJsonOutput(&out, func() error {
		return RunStatus(cmd, []string{})
	}); err != nil {
		t.Fatal(err)
	}

	fq0001 := quirks.Quirk{}
	for _, quirk := range out.FirmwareQuirks {
		if quirk.ID == "FQ0001" {
			fq0001 = quirk
		}
	}

	if !reflect.ValueOf(fq0001).IsZero() {
		t.Fatal("quirk got detected, with method '" + fq0001.Method + "'")
	}
}

func TestFQ0001WrongChassis(t *testing.T) {
	cmd := SetFS(
		fstest.MapFS{"/sys/devices/virtual/dmi/id/bios_date": {Data: []byte("01/06/2023\n")}},
		fstest.MapFS{"/sys/devices/virtual/dmi/id/bios_version": {Data: []byte("A.30\n")}},
		fstest.MapFS{"/sys/devices/virtual/dmi/id/board_name": {Data: []byte("PRO Z790-A WIFI (MS-7E07)\n")}},
		fstest.MapFS{"/sys/devices/virtual/dmi/id/board_vendor": {Data: []byte("Micro-Star International Co., Ltd.\n")}},
		fstest.MapFS{"/sys/devices/virtual/dmi/id/chassis_type": {Data: []byte("5\n")}},
		fstest.MapFS{"/sys/devices/virtual/dmi/id/product_name": {Data: []byte("MS-7E07\n")}},
		efitest.SecureBootOn(),
		efitest.SetUpModeOff(),
	)

	if err := captureJsonOutput(&out, func() error {
		return RunStatus(cmd, []string{})
	}); err != nil {
		t.Fatal(err)
	}

	fq0001 := quirks.Quirk{}
	for _, quirk := range out.FirmwareQuirks {
		if quirk.ID == "FQ0001" {
			fq0001 = quirk
		}
	}

	if !reflect.ValueOf(fq0001).IsZero() {
		t.Fatal("quirk got detected using '" + fq0001.Method + "' method")
	}
}

func TestFQ0001WrongVendor(t *testing.T) {
	cmd := SetFS(
		fstest.MapFS{"/sys/devices/virtual/dmi/id/bios_date": {Data: []byte("01/06/2023\n")}},
		fstest.MapFS{"/sys/devices/virtual/dmi/id/bios_version": {Data: []byte("A.30\n")}},
		fstest.MapFS{"/sys/devices/virtual/dmi/id/board_name": {Data: []byte("PRO Z790-A WIFI (MS-7E07)\n")}},
		fstest.MapFS{"/sys/devices/virtual/dmi/id/board_vendor": {Data: []byte("More-Security Issues Co., Ltd.\n")}},
		fstest.MapFS{"/sys/devices/virtual/dmi/id/chassis_type": {Data: []byte("3\n")}},
		fstest.MapFS{"/sys/devices/virtual/dmi/id/product_name": {Data: []byte("MS-7E07\n")}},
		efitest.SecureBootOn(),
		efitest.SetUpModeOff(),
	)

	if err := captureJsonOutput(&out, func() error {
		return RunStatus(cmd, []string{})
	}); err != nil {
		t.Fatal(err)
	}

	fq0001 := quirks.Quirk{}
	for _, quirk := range out.FirmwareQuirks {
		if quirk.ID == "FQ0001" {
			fq0001 = quirk
		}
	}

	if !reflect.ValueOf(fq0001).IsZero() {
		t.Fatal("quirk got detected using '" + fq0001.Method + "' method")
	}
}
