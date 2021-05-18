package main

import (
	"github.com/foxboron/sbctl"
	"github.com/spf13/cobra"
)

var enrollKeysCmd = &cobra.Command{
	Use:   "enroll-keys",
	Short: "Enroll the current keys to EFI",
	RunE: func(cmd *cobra.Command, args []string) error {
		return sbctl.SyncKeys()
	},
}

func init() {
	CliCommands = append(CliCommands, cliCommand{
		Cmd: enrollKeysCmd,
	})
}
