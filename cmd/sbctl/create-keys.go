package main

import (
	"fmt"
	"path"
	"path/filepath"

	"github.com/foxboron/sbctl"
	"github.com/foxboron/sbctl/backend"
	"github.com/foxboron/sbctl/config"
	"github.com/foxboron/sbctl/logging"
	"github.com/foxboron/sbctl/lsm"
	"github.com/landlock-lsm/go-landlock/landlock"
	"github.com/spf13/cobra"
)

var (
	exportPath                       string
	databasePath                     string
	Keytype                          string
	PKKeytype, KEKKeytype, DbKeytype string
)

var createKeysCmd = &cobra.Command{
	Use:   "create-keys",
	Short: "Create a set of secure boot signing keys",
	RunE: func(cmd *cobra.Command, args []string) error {
		state := cmd.Context().Value(stateDataKey{}).(*config.State)
		return RunCreateKeys(state)
	},
}

func RunCreateKeys(state *config.State) error {
	if state.Config.Landlock {
		lsm.RestrictAdditionalPaths(
			landlock.RWDirs(filepath.Dir(filepath.Dir(filepath.Clean(state.Config.Keydir)))),
		)
		if err := lsm.Restrict(); err != nil {
			return err
		}
	}
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

	// Should be own flag type
	if Keytype != "" && (Keytype == "file" || Keytype == "tpm") {
		state.Config.Keys.PK.Type = Keytype
		state.Config.Keys.KEK.Type = Keytype
		state.Config.Keys.Db.Type = Keytype
	} else {
		if PKKeytype != "" && (PKKeytype == "file" || PKKeytype == "tpm") {
			state.Config.Keys.PK.Type = PKKeytype
		}
		if KEKKeytype != "" && (KEKKeytype == "file" || KEKKeytype == "tpm") {
			state.Config.Keys.KEK.Type = KEKKeytype
		}
		if DbKeytype != "" && (DbKeytype == "file" || DbKeytype == "tpm") {
			state.Config.Keys.Db.Type = DbKeytype
		}
	}

	uuid, err := sbctl.CreateGUID(state.Fs, state.Config.GUID)
	if err != nil {
		return err
	}
	logging.Print("Created Owner UUID %s\n", uuid)
	if !sbctl.CheckIfKeysInitialized(state.Fs, state.Config.Keydir) {
		logging.Print("Creating secure boot keys...")

		hier, err := backend.CreateKeys(state)
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
}

func createKeysCmdFlags(cmd *cobra.Command) {
	f := cmd.Flags()
	f.StringVarP(&exportPath, "export", "e", "", "export file path")
	f.StringVarP(&databasePath, "database-path", "d", "", "location to create GUID file")
	f.StringVarP(&Keytype, "keytype", "", "", "key type for all keys")
	f.StringVarP(&PKKeytype, "pk-keytype", "", "", "PK key type (default: file)")
	f.StringVarP(&KEKKeytype, "kek-keytype", "", "", "KEK key type (default: file)")
	f.StringVarP(&DbKeytype, "db-keytype", "", "", "db key type (default: file)")
}

func init() {
	createKeysCmdFlags(createKeysCmd)

	CliCommands = append(CliCommands, cliCommand{
		Cmd: createKeysCmd,
	})
}
