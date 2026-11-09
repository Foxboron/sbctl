package main

import (
	"errors"
	"os"
	"testing"
	"testing/fstest"

	"github.com/foxboron/go-uefi/efi/efitest"
	"github.com/foxboron/sbctl"
	"github.com/foxboron/sbctl/config"
)

// resetEnrollKeysFlags clears the global flag state so RunEnrollKeys runs a
// full enrollment with no flags set, regardless of what other tests left behind.
func resetEnrollKeysFlags() {
	// Keep enrollment from blocking on an interactive prompt: point stdin at
	// /dev/null so promptYesNo sees a non-terminal and returns false.
	os.Stdin, _ = os.OpenFile(os.DevNull, os.O_RDONLY, 0)
	enrollKeysCmdOptions.Export.Value = ""
	enrollKeysCmdOptions.Partial.Value = ""
	enrollKeysCmdOptions.CustomBytes = ""
	enrollKeysCmdOptions.Append = false
	enrollKeysCmdOptions.MicrosoftKeys = false
	enrollKeysCmdOptions.TPMEventlogChecksums = false
	enrollKeysCmdOptions.Custom = false
	enrollKeysCmdOptions.Force = false
	enrollKeysCmdOptions.IgnoreImmutable = false
	enrollKeysCmdOptions.BuiltinFirmwareCerts = nil
}

// TestEnrollKeysConservativeSetupModeGate covers the conservative enrollment
// gate: knowing that Secure Boot appears enabled does not imply the firmware
// will accept a PK update, so a full enrollment with an absent or unreadable
// SetupMode variable is rejected rather than guessed. Full enrollment only
// proceeds past the gate when SetupMode reads as enabled. An absent SetupMode
// is reported as ErrSetupModeMissing, not ErrSetupModeDisabled, because its
// absence does not establish that Setup Mode is disabled.
func TestEnrollKeysConservativeSetupModeGate(t *testing.T) {
	// 1. Baseline: no EFI variables → rejected at the SetupMode gate.
	resetEnrollKeysFlags()
	baselineCmd := SetFS(fstest.MapFS{})
	baselineState := baselineCmd.Context().Value(stateDataKey{}).(*config.State)
	if err := RunEnrollKeys(baselineState); !errors.Is(err, ErrSetupModeMissing) {
		t.Fatalf("baseline: expected ErrSetupModeMissing, got %v", err)
	}

	// 2. SecureBoot present but SetupMode missing: still rejected, because
	//    secure-boot enabled does not grant enrollment.
	resetEnrollKeysFlags()
	secureCmd := SetFS(efitest.SecureBootOn())
	secureState := secureCmd.Context().Value(stateDataKey{}).(*config.State)
	if err := RunEnrollKeys(secureState); !errors.Is(err, ErrSetupModeMissing) {
		t.Fatalf("missing SetupMode should be rejected even with SecureBoot enabled, got %v", err)
	}

	// 3. SetupMode enabled → proceeds past the gate, then fails on the missing
	//    TPM eventlog / key material in the test FS (ErrNoEventlog).
	resetEnrollKeysFlags()
	setupCmd := SetFS(efitest.SetUpModeOn())
	setupState := setupCmd.Context().Value(stateDataKey{}).(*config.State)
	if err := RunEnrollKeys(setupState); !errors.Is(err, sbctl.ErrNoEventlog) {
		t.Fatalf("SetupMode enabled should pass the gate and fail on the eventlog (ErrNoEventlog), got %v", err)
	}
}

// TestEnrollKeysSecureBootConfigFirmwareConservative covers firmware that
// exposes the SecureBootData variable but no standalone SetupMode variable.
// Enrollment is NOT authorized by the mere presence of SecureBootData: the
// conservative gate still requires a readable SetupMode (or an export), unless
// the user explicitly confirms an interactive prompt or passes the force flag.
func TestEnrollKeysSecureBootConfigFirmwareConservative(t *testing.T) {
	resetEnrollKeysFlags()
	secureCmd := SetFS(fstest.MapFS{
		"/sys/firmware/efi/efivars/SecureBootData-" + secureBootConfigGUID: {
			Data: []byte{0x6, 0x0, 0x0, 0x0, 0x0},
		},
	})
	secureState := secureCmd.Context().Value(stateDataKey{}).(*config.State)
	if err := RunEnrollKeys(secureState); !errors.Is(err, ErrSetupModeMissing) {
		t.Fatalf("SecureBootData presence alone does not authorize enrollment; expected ErrSetupModeMissing, got %v", err)
	}
}
