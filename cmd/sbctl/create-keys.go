package main

import (
	"fmt"

	"github.com/foxboron/sbctl"
	"github.com/foxboron/sbctl/logging"
	"github.com/spf13/cobra"
)

var (
	exportPath   string = sbctl.KeysPath
	databasePath string = sbctl.DatabasePath
)

var createKeysCmd = &cobra.Command{
	Use:   "create-keys",
	Short: "Create a set of secure boot signing keys",
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := sbctl.CreateDirectory(exportPath); err != nil {
			return err
		}
		uuid, err := sbctl.CreateGUID(databasePath)
		if err != nil {
			return err
		}
		logging.Print("Created Owner UUID %s\n", uuid)
		if !sbctl.CheckIfKeysInitialized(exportPath) {
			logging.Print("Creating secure boot keys...")
			err := sbctl.InitializeSecureBootKeys(exportPath)
			if err != nil {
				logging.NotOk("")
				return fmt.Errorf("couldn't initialize secure boot: %w", err)
			}
			logging.Ok("")
			logging.Println("Secure boot keys created!")
		} else {
			logging.Ok("Secure boot keys have already been created!")
		}
		return nil
	},
}

func createKeysCmdFlags(cmd *cobra.Command) {
	f := cmd.Flags()
	f.StringVarP(&exportPath, "export", "e", sbctl.KeysPath, "export file path. defaults to "+sbctl.KeysPath)
	f.StringVarP(&databasePath, "database-path", "d", sbctl.DatabasePath, "location to create GUID file. defaults to "+sbctl.DatabasePath)
}

func init() {
	createKeysCmdFlags(createKeysCmd)

	CliCommands = append(CliCommands, cliCommand{
		Cmd: createKeysCmd,
	})
}
