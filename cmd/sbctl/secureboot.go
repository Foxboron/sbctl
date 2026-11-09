package main

import (
	"fmt"

	"github.com/foxboron/sbctl/config"
)

// efiStandardVariableGUID is the GUID shared by the standard EFI variables
// SecureBoot and SetupMode (and their sibling policy variables).
const efiStandardVariableGUID = "8be4df61-93ca-11d2-aa0d-00e098032b8c"

// secureBootConfigGUID is the GUID of the "SecureBootData" variable exposed by
// some UEFI firmware, which reports Secure Boot state through it instead of the
// standalone SetupMode/SecureBoot variables.
const secureBootConfigGUID = "aa1305b9-01f3-4afb-920e-c9b979a852fd"

// efivarPresent reports whether an EFI variable file exists in efivarfs.
//
// Presence only: it does not read or parse the variable, so a variable that
// exists but is unreadable (wrong attributes, malformed data, permissions, I/O)
// still counts as present. That distinction lets UEFI detection succeed even
// when a variable's payload cannot be parsed.
func efivarPresent(state *config.State, name, guid string) bool {
	if state == nil || state.Fs == nil {
		return false
	}
	path := fmt.Sprintf("/sys/firmware/efi/efivars/%s-%s", name, guid)
	_, err := state.Fs.Stat(path)
	return err == nil
}

// secureBootConfigPresent reports whether the firmware exposes the
// "SecureBootData" variable, which indicates that the system might be UEFI-booted even though
// the standalone SetupMode variable is absent on firmware using this interface.
// Its payload is undocumented, so it is never parsed.
func secureBootConfigPresent(state *config.State) bool {
	return efivarPresent(state, "SecureBootData", secureBootConfigGUID)
}
