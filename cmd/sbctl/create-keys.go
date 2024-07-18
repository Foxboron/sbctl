package main

import (
	"fmt"
	"path"

	"github.com/foxboron/sbctl"
	"github.com/foxboron/sbctl/backend"
	"github.com/foxboron/sbctl/config"
	"github.com/foxboron/sbctl/logging"
	"github.com/spf13/cobra"
)

var (
	exportPath                       string
	databasePath                     string
	Keytype                          string
	PKKeyType, KEKKeyType, DbKeyType string
)

var createKeysCmd = &cobra.Command{
	Use:   "create-keys",
	Short: "Create a set of secure boot signing keys",
	RunE: func(cmd *cobra.Command, args []string) error {
		state := cmd.Context().Value("state").(*config.State)

		// Overrides keydir or GUID location
		if exportPath != "" {
			state.Config.Keydir = exportPath
		}

		if databasePath != "" {
			state.Config.GUID = databasePath
		}

		if err := sbctl.CreateDirectory(state.Fs, state.Config.Keydir); err != nil {
			return err
		}
		if err := sbctl.CreateDirectory(state.Fs, path.Dir(state.Config.GUID)); err != nil {
			return err
		}

		uuid, err := sbctl.CreateGUID(state.Fs, state.Config.GUID)
		if err != nil {
			return err
		}
		logging.Print("Created Owner UUID %s\n", uuid)
		fmt.Println(state.Config.Keydir)
		if !sbctl.CheckIfKeysInitialized(state.Fs, state.Config.Keydir) {
			logging.Print("Creating secure boot keys...")

			hier, err := backend.CreateKeys(state.Config)
			if err != nil {
				logging.NotOk("")
				return fmt.Errorf("couldn't initialize secure boot: %w", err)
			}
			err = hier.SaveKeys(state.Fs, state.Config.Keydir)
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
	f.StringVarP(&exportPath, "export", "e", "", "export file path")
	f.StringVarP(&databasePath, "database-path", "d", "", "location to create GUID file")
	f.StringVarP(&Keytype, "keytype", "", "file", "key type for all keys")
	f.StringVarP(&PKKeyType, "pk-type", "", "file", "PK key type (file | tpm)")
	f.StringVarP(&KEKKeyType, "kek-type", "", "file", "PK key type (file | tpm)")
	f.StringVarP(&DbKeyType, "db-type", "", "file", "PK key type (file | tpm)")
}

func init() {
	createKeysCmdFlags(createKeysCmd)

	CliCommands = append(CliCommands, cliCommand{
		Cmd: createKeysCmd,
	})
}
