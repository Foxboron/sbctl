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
	Long: `Creates a set of signing keys used to sign EFI binaries. Currently it
will create the following keys:

* Platform Key
* Key Exchange key
* Signature Database Key`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := sbctl.CreateDirectory(sbctl.KeysPath); err != nil {
			return err
		}
		uuid, err := sbctl.CreateGUID(sbctl.DatabasePath)
		if err != nil {
			return err
		}
		logging.Print("Created Owner UUID %s\n", uuid)
		if !sbctl.CheckIfKeysInitialized(sbctl.KeysPath) {
			logging.Print("Creating secure boot keys...")
			err := sbctl.InitializeSecureBootKeys(sbctl.KeysPath)
			if err != nil {
				logging.NotOk("")
				return fmt.Errorf("couldn't initialize secure boot: %w", err)
			}
			logging.Ok("\nSecure boot keys created!")
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
