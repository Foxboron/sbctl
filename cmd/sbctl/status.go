package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/foxboron/go-uefi/efi"
	"github.com/foxboron/sbctl"
	"github.com/foxboron/sbctl/fs"
	"github.com/foxboron/sbctl/logging"
	"github.com/spf13/cobra"
)

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show current boot status",
	RunE:  RunStatus,
}

type Status struct {
	Installed  bool     `json:"installed"`
	GUID       string   `json:"guid"`
	SetupMode  bool     `json:"setup_mode"`
	SecureBoot bool     `json:"secure_boot"`
	Vendors    []string `json:"vendors"`
}

func NewStatus() *Status {
	return &Status{
		Installed:  false,
		GUID:       "",
		SetupMode:  false,
		SecureBoot: false,
		Vendors:    []string{},
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
}

func RunStatus(cmd *cobra.Command, args []string) error {
	stat := NewStatus()
	if _, err := fs.Fs.Stat("/sys/firmware/efi/efivars"); os.IsNotExist(err) {
		return fmt.Errorf("system is not booted with UEFI")
	}
	if sbctl.CheckSbctlInstallation(sbctl.DatabasePath) {
		stat.Installed = true
		u, err := sbctl.GetGUID()
		if err == nil {
			stat.GUID = u.String()
		}
	}
	if efi.GetSetupMode() {
		stat.SetupMode = true
	}
	if efi.GetSecureBoot() {
		stat.SecureBoot = true
	}
	if keys := sbctl.GetEnrolledVendorCerts(); len(keys) > 0 {
		stat.Vendors = keys
	}
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
