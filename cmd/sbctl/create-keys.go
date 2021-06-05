package main

import (
	"fmt"

	"github.com/foxboron/sbctl"
	"github.com/foxboron/sbctl/logging"
	"github.com/spf13/cobra"
)

var createKeysCmd = &cobra.Command{
	Use:   "create-keys",
	Short: "Create a set of secure boot signing keys",
	RunE: func(cmd *cobra.Command, args []string) error {
		if !sbctl.CheckIfKeysInitialized(sbctl.KeysPath) {
			logging.Print("Creating secure boot keys...")
			err := sbctl.InitializeSecureBootKeys(sbctl.DatabasePath)
			if err != nil {
				return fmt.Errorf("couldn't initialize secure boot: %w", err)
			}
		} else {
			logging.Ok("Secure boot keys has already been created!")
		}
		return nil
	},
}

func init() {
	CliCommands = append(CliCommands, cliCommand{
		Cmd: createKeysCmd,
	})
}
