package main

import (
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

type Status struct {
	Installed      bool           `json:"installed"`
	GUID           string         `json:"guid"`
	SetupMode      bool           `json:"setup_mode"`
	SecureBoot     bool           `json:"secure_boot"`
	Vendors        []string       `json:"vendors"`
	FirmwareQuirks []quirks.Quirk `json:"firmware_quirks"`
}

func NewStatus() *Status {
	return &Status{
		Installed:      false,
		GUID:           "",
		SetupMode:      false,
		SecureBoot:     false,
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
	if s.SetupMode {
		logging.NotOk("Enabled")
	} else {
		logging.Ok("Disabled")
	}
	logging.Print("Secure Boot:\t")
	if s.SecureBoot {
		logging.Ok("Enabled")
	} else {
		logging.NotOk("Disabled")
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
		logging.Print(logging.Warnf("Your firmware has known quirks"))
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
	if _, err := state.Fs.Stat("/sys/firmware/efi/efivars/SetupMode-8be4df61-93ca-11d2-aa0d-00e098032b8c"); os.IsNotExist(err) {
		return fmt.Errorf("system is not booted with UEFI")
	}

	if state.IsInstalled() {
		stat.Installed = true
		u, err := state.Config.GetGUID(state.Fs)
		if err == nil {
			stat.GUID = u.Format()
		}
	}
	if ok, _ := state.Efivarfs.GetSetupMode(); ok {
		stat.SetupMode = true
	}
	if ok, _ := state.Efivarfs.GetSecureBoot(); ok {
		stat.SecureBoot = true
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
