package main

import (
	"fmt"
	"os"

	"github.com/foxboron/go-uefi/efi"
	"github.com/foxboron/sbctl"
	"github.com/foxboron/sbctl/logging"
	"github.com/spf13/cobra"
)

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show current boot status",
	RunE:  RunStatus,
}

type Status struct {
	Installed  bool   `json:"installed"`
	GUID       string `json:"guid"`
	SetupMode  bool   `json:"setup_mode"`
	SecureBoot bool   `json:"secure_boot"`
}

func NewStatus() *Status {
	return &Status{
		Installed:  false,
		GUID:       "",
		SetupMode:  false,
		SecureBoot: false,
	}
}

func PrintStatus(s *Status) {
	logging.Print("Installed:\t")
	if s.Installed {
		logging.Ok("sbctl is installed")
		logging.Print("Owner GUID:\t")
		logging.Println(s.GUID)
	} else {
		logging.NotOk("Sbctl is not installed")
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
}

func RunStatus(cmd *cobra.Command, args []string) error {
	stat := NewStatus()
	if _, err := os.Stat("/sys/firmware/efi/efivars"); os.IsNotExist(err) {
		return fmt.Errorf("system is not booted with UEFI")
	}
	if sbctl.CheckSbctlInstallation(sbctl.DatabasePath) {
		stat.Installed = true
		u, err := sbctl.GetGUID()
		if err != nil {
			return err
		}
		stat.GUID = u.String()
	}
	if efi.GetSetupMode() {
		stat.SetupMode = true
	}
	if efi.GetSecureBoot() {
		stat.SecureBoot = true
	}
	if cmdOptions.JsonOutput {
		JsonOut(stat)
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
