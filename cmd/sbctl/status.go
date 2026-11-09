package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/foxboron/go-uefi/efi/signature"
	"github.com/foxboron/sbctl"
	"github.com/foxboron/sbctl/backend"
	"github.com/foxboron/sbctl/certs"
	"github.com/foxboron/sbctl/config"
	"github.com/foxboron/sbctl/logging"
	"github.com/foxboron/sbctl/lsm"
	"github.com/foxboron/sbctl/quirks"
	"github.com/spf13/cobra"
)

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show current boot status",
	RunE:  RunStatus,
}

// SetupModeState reflects what sbctl could establish about the UEFI Setup Mode,
// mirroring the Linux kernel's efi_secureboot_mode states. Firmware that does not
// expose the standalone SetupMode variable leaves it unknown rather than being
// reported as disabled.
type SetupModeState int32

const (
	// SetupModeUnknown means the SetupMode variable was absent or unreadable.
	SetupModeUnknown SetupModeState = iota
	// SetupModeDisabled means the SetupMode variable read as 0 (user mode).
	SetupModeDisabled
	// SetupModeEnabled means the SetupMode variable read as 1 (setup mode).
	SetupModeEnabled
)

// String renders the state for --json output as a stable, self-documenting
// value ("unknown", "disabled", "enabled") rather than a bare integer.
func (s SetupModeState) String() string {
	switch s {
	case SetupModeDisabled:
		return "disabled"
	case SetupModeEnabled:
		return "enabled"
	default:
		return "unknown"
	}
}

func (s SetupModeState) MarshalJSON() ([]byte, error) {
	return json.Marshal(s.String())
}

func (s *SetupModeState) UnmarshalJSON(data []byte) error {
	var v string
	if err := json.Unmarshal(data, &v); err != nil {
		return err
	}
	switch v {
	case "disabled":
		*s = SetupModeDisabled
	case "enabled":
		*s = SetupModeEnabled
	default:
		*s = SetupModeUnknown
	}
	return nil
}

// SecureBootState reflects what sbctl could establish about Secure Boot. The
// classification is inspired by the Linux kernel's efi_secureboot_mode, but is
// not an exact replica: where the kernel treats a missing SecureBoot variable as
// disabled, sbctl reports unknown, since that is more honest when no readable
// variable can establish the state. Firmware that reports its Secure Boot state
// through the "SecureBootData" variable exposes no readable SecureBoot
// variable, so its on/off state is left unknown rather than being reported as
// disabled.
type SecureBootState int32

const (
	// SecureBootUnknown means the Secure Boot state could not be established
	// from a readable EFI variable.
	SecureBootUnknown SecureBootState = iota
	// SecureBootDisabled means Secure Boot was read as disabled.
	SecureBootDisabled
	// SecureBootEnabled means Secure Boot was read as enabled.
	SecureBootEnabled
)

// String renders the state for --json output as a stable, self-documenting
// value ("unknown", "disabled", "enabled") rather than a bare integer.
func (s SecureBootState) String() string {
	switch s {
	case SecureBootDisabled:
		return "disabled"
	case SecureBootEnabled:
		return "enabled"
	default:
		return "unknown"
	}
}

func (s SecureBootState) MarshalJSON() ([]byte, error) {
	return json.Marshal(s.String())
}

func (s *SecureBootState) UnmarshalJSON(data []byte) error {
	var v string
	if err := json.Unmarshal(data, &v); err != nil {
		return err
	}
	switch v {
	case "disabled":
		*s = SecureBootDisabled
	case "enabled":
		*s = SecureBootEnabled
	default:
		*s = SecureBootUnknown
	}
	return nil
}

type Status struct {
	Installed      bool            `json:"installed"`
	GUID           string          `json:"guid"`
	SetupMode      SetupModeState  `json:"setup_mode"`
	SecureBoot     SecureBootState `json:"secure_boot"`
	Vendors        []string        `json:"vendors"`
	FirmwareQuirks []quirks.Quirk  `json:"firmware_quirks"`
}

func NewStatus() *Status {
	return &Status{
		Installed:      false,
		GUID:           "",
		SetupMode:      SetupModeUnknown,
		SecureBoot:     SecureBootUnknown,
		Vendors:        []string{},
		FirmwareQuirks: []quirks.Quirk{},
	}
}

func PrintStatus(s *Status) {
	logging.Print("Installed:\t")
	if s.Installed {
		logging.Ok("sbctl is installed")
		if s.GUID != "" {
			logging.Print("Owner GUID:\t")
			logging.Println(s.GUID)
		}
	} else {
		logging.NotOk("sbctl is not installed")
	}
	logging.Print("Setup Mode:\t")
	switch s.SetupMode {
	case SetupModeEnabled:
		logging.NotOk("Enabled")
	case SetupModeDisabled:
		logging.Ok("Disabled")
	default:
		logging.Unknown("Unknown")
	}
	logging.Print("Secure Boot:\t")
	switch s.SecureBoot {
	case SecureBootEnabled:
		logging.Ok("Enabled")
	case SecureBootDisabled:
		logging.NotOk("Disabled")
	default:
		logging.Unknown("Unknown")
	}
	if s.SecureBoot == SecureBootUnknown {
		logging.Println("\t\t(Secure Boot state cannot be determined from the available EFI variables)")
	}
	// TODO: We only have microsoft keys
	// this needs to be extended for more keys in the future
	logging.Print("Vendor Keys:\t")
	if len(s.Vendors) > 0 {
		logging.Println(strings.Join(s.Vendors, " "))
	} else {
		logging.Println("none")
	}
	if len(s.FirmwareQuirks) > 0 {
		logging.Print("Firmware:\t")
		logging.Print("%s", logging.Warnf("Your firmware has known quirks"))
		for _, quirk := range s.FirmwareQuirks {
			logging.Println("\t\t- " + quirk.ID + ": " + quirk.Name + " (" + quirk.Severity + ")\n\t\t  " + quirk.Link)
		}
	}
}

func RunDebug(state *config.State) error {
	kh, err := backend.GetKeyHierarchy(state.Fs, state)
	if err != nil {
		return err
	}

	efistate, err := sbctl.SystemEFIVariables(state.Efivarfs)
	if err != nil {
		return err
	}

	guid, err := state.Config.GetGUID(state.Fs)
	if err != nil {
		return err
	}

	if efistate.PK.SigDataExists(signature.CERT_X509_GUID, &signature.SignatureData{Owner: *guid, Data: kh.PK.Certificate().Raw}) {
		slog.Debug("PK is fine")
	}

	if efistate.KEK.SigDataExists(signature.CERT_X509_GUID, &signature.SignatureData{Owner: *guid, Data: kh.KEK.Certificate().Raw}) {
		slog.Debug("KEK is fine")
	}

	if efistate.Db.SigDataExists(signature.CERT_X509_GUID, &signature.SignatureData{Owner: *guid, Data: kh.Db.Certificate().Raw}) {
		slog.Debug("db is fine")
	}

	return nil
}

func RunStatus(cmd *cobra.Command, args []string) error {
	state := cmd.Context().Value(stateDataKey{}).(*config.State)

	if state.Config.Landlock {
		if err := lsm.Restrict(); err != nil {
			return err
		}
	}

	if cmdOptions.Debug {
		RunDebug(state)
	}

	stat := NewStatus()

	// Establish which EFI secure-boot interface this firmware exposes. Presence
	// of any of the standard SecureBoot, SetupMode or SecureBootData variables
	// proves the system is UEFI-booted, independently of whether the variable's
	// contents can be read: a variable that exists but is unreadable (wrong
	// attributes, malformed data, permissions, I/O errors) still counts as
	// present. A system exposing none of them is not booted with UEFI.
	secureBootPresent := efivarPresent(state, "SecureBoot", efiStandardVariableGUID)
	setupModePresent := efivarPresent(state, "SetupMode", efiStandardVariableGUID)
	secureBootConfig := secureBootConfigPresent(state)

	switch {
	case secureBootPresent:
	case setupModePresent:
	case secureBootConfig:
	default:
		return fmt.Errorf("system is not booted with UEFI")
	}

	if state.IsInstalled() {
		stat.Installed = true
		u, err := state.Config.GetGUID(state.Fs)
		if err == nil {
			stat.GUID = u.Format()
		}
	}

	// A missing variable yields os.ErrNotExist; any other failure is a genuine
	// read error that must not be mistaken for a zero value.
	secureBootValue, secureBootErr := state.Efivarfs.GetSecureBoot()
	setupModeValue, setupModeErr := state.Efivarfs.GetSetupMode()
	setupModeMissing := setupModeErr != nil && errors.Is(setupModeErr, os.ErrNotExist)
	setupModeUnreadable := setupModeErr != nil && !setupModeMissing

	// Setup Mode: report only what we can establish. An absent variable leaves
	// its state unknown rather than disabled; so does any other read error.
	switch {
	case setupModeErr != nil:
		stat.SetupMode = SetupModeUnknown
	case setupModeValue:
		stat.SetupMode = SetupModeEnabled
	default:
		stat.SetupMode = SetupModeDisabled
	}

	// Secure Boot: report the on/off state. Precedence:
	//  1. If SecureBoot is readable, use it. When enabled, a missing SetupMode
	//     is treated as user mode (enabled); an explicit Setup Mode means
	//     disabled; a genuine SetupMode read error leaves the state unknown.
	//  2. If SecureBootData is present, the state is unknown.
	//  3. Unknown.
	switch {
	case secureBootErr == nil:
		if secureBootValue {
			switch {
			case setupModeMissing:
				// Kernel treats a missing SetupMode as user mode (0).
				stat.SecureBoot = SecureBootEnabled
			case setupModeUnreadable:
				// A genuine read error on SetupMode is not evidence of user mode.
				stat.SecureBoot = SecureBootUnknown
			case setupModeValue:
				// Secure Boot=1 while in Setup Mode => disabled.
				stat.SecureBoot = SecureBootDisabled
			default:
				stat.SecureBoot = SecureBootEnabled
			}
		} else {
			stat.SecureBoot = SecureBootDisabled
		}
	case secureBootConfig:
		// Firmware exposing SecureBootData: state not exposed through the
		// standard variables.
	default:
		// SecureBoot variable absent/unreadable and no SecureBootData: unknown.
	}
	if keys := sbctl.GetEnrolledVendorCerts(); len(keys) > 0 {
		stat.Vendors = keys
	}
	if keys, err := certs.BuiltinSignatureOwners(); err == nil {
		stat.Vendors = append(stat.Vendors, keys...)
	}
	stat.FirmwareQuirks = quirks.CheckFirmwareQuirks(state)
	if cmdOptions.JsonOutput {
		if err := JsonOut(stat); err != nil {
			return err
		}
	} else {
		PrintStatus(stat)
	}
	return nil
}

func init() {
	CliCommands = append(CliCommands, cliCommand{
		Cmd: statusCmd,
	})
}
