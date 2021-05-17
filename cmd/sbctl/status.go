package main

import (
	"fmt"
	"os"

	"github.com/foxboron/go-uefi/efi"
	"github.com/foxboron/sbctl/logging"
	"github.com/spf13/cobra"
)

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show current boot status",
	RunE:  RunStatus,
}

func RunStatus(cmd *cobra.Command, args []string) error {
	ret := map[string]bool{}
	if _, err := os.Stat("/sys/firmware/efi/efivars"); os.IsNotExist(err) {
		return fmt.Errorf("system is not booted with UEFI!")
	}
	logging.Print("Setup Mode:\t")
	if efi.GetSetupMode() {
		logging.NotOk("Enabled")
		ret["Setup Mode"] = true
	} else {
		logging.Ok("Disabled")
		ret["Setup Mode"] = false
	}
	logging.Print("Secure Boot:\t")
	if efi.GetSecureBoot() {
		logging.Ok("Enabled")
		ret["Secure Boot"] = true
	} else {
		logging.NotOk("Disabled")
		ret["Secure Boot"] = false
	}
	if cmdOptions.JsonOutput {
		JsonOut(ret)
	}
	return nil
}

func init() {
	CliCommands = append(CliCommands, cliCommand{
		Cmd: statusCmd,
	})
}
