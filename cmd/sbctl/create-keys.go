package main

import (
	"fmt"
	"path"
	"path/filepath"
	"strings"

	"github.com/foxboron/sbctl"
	"github.com/foxboron/sbctl/backend"
	"github.com/foxboron/sbctl/config"
	"github.com/foxboron/sbctl/logging"
	"github.com/foxboron/sbctl/lsm"
	"github.com/landlock-lsm/go-landlock/landlock"
	"github.com/spf13/cobra"
)

var (
	exportPath       string
	databasePath     string
	Keytype          string
	KEKKeytype       string
	DbKeytype        string
	PKKeytype        string
	PKSubject        string
	KEKSubject       string
	DbSubject        string
	OverwriteYubikey bool
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

	if OverwriteYubikey {
		logging.Warn("Overwriting Yubikey option enabled")
		state.Yubikey.Overwrite = true
	}

	if err := sbctl.CreateDirectory(state.Fs, state.Config.Keydir); err != nil {
		return err
	}
	if err := sbctl.CreateDirectory(state.Fs, path.Dir(state.Config.GUID)); err != nil {
		return err
	}

	if Keytype != "" && (strings.HasPrefix(Keytype, "file") || strings.HasPrefix(Keytype, "tpm") || strings.HasPrefix(Keytype, "yubikey")) {
		state.Config.Keys.PK.Type, state.Config.Keys.PK.Algorithm, state.Config.Keys.PK.Slot = splitKeyType(Keytype)
		state.Config.Keys.KEK.Type, state.Config.Keys.KEK.Algorithm, state.Config.Keys.KEK.Slot = splitKeyType(Keytype)
		state.Config.Keys.Db.Type, state.Config.Keys.Db.Algorithm, state.Config.Keys.Db.Slot = splitKeyType(Keytype)
	} else {
		if PKKeytype != "" && (strings.HasPrefix(PKKeytype, "file") || strings.HasPrefix(PKKeytype, "tpm") || strings.HasPrefix(PKKeytype, "yubikey")) {
			state.Config.Keys.PK.Type, state.Config.Keys.PK.Algorithm, state.Config.Keys.PK.Slot = splitKeyType(PKKeytype)
		}
		if KEKKeytype != "" && (strings.HasPrefix(KEKKeytype, "file") || strings.HasPrefix(KEKKeytype, "tpm") || strings.HasPrefix(KEKKeytype, "yubikey")) {
			state.Config.Keys.KEK.Type, state.Config.Keys.KEK.Algorithm, state.Config.Keys.KEK.Slot = splitKeyType(KEKKeytype)
		}
		if DbKeytype != "" && (strings.HasPrefix(DbKeytype, "file") || strings.HasPrefix(DbKeytype, "tpm") || strings.HasPrefix(DbKeytype, "yubikey")) {
			state.Config.Keys.Db.Type, state.Config.Keys.Db.Algorithm, state.Config.Keys.Db.Slot = splitKeyType(DbKeytype)
		}
	}

	state.Config.Keys.PK.Subject = PKSubject
	state.Config.Keys.KEK.Subject = KEKSubject
	state.Config.Keys.Db.Subject = DbSubject

	// if any keytype is yubikey close it appropriately at the end
	if strings.HasPrefix(Keytype, "yubikey") || strings.HasPrefix(PKKeytype, "yubikey") || strings.HasPrefix(KEKKeytype, "yubikey") || strings.HasPrefix(DbKeytype, "yubikey") {
		defer state.Yubikey.Close()
	}

	uuid, err := sbctl.CreateGUID(state.Fs, state.Config.GUID)
	if err != nil {
		return err
	}
	logging.Print("Created Owner UUID %s\n", uuid)
	if !sbctl.CheckIfKeysInitialized(state.Fs, state.Config.Keydir) {
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
		logging.Ok("Secure boot keys created!")
	} else {
		logging.Ok("Secure boot keys have already been created!")
	}
	return nil
}

func createKeysCmdFlags(cmd *cobra.Command) {
	f := cmd.Flags()
	f.BoolVar(&OverwriteYubikey, "yk-overwrite", false, "overwrite existing key if it exists in the Yubikey slot")
	f.StringVarP(&exportPath, "export", "e", "", "export file path")
	f.StringVarP(&databasePath, "database-path", "d", "", "location to create GUID file")
	f.StringVarP(&Keytype, "keytype", "", "", "key type for all keys. Algorithm and slot for yubikey can also be specified: yubikey:RSA4096:9c (default: file)")
	f.StringVarP(&PKKeytype, "pk-keytype", "", "", "PK key type Algorithm and slot for yubikey can also be specified: yubikey:RSA4096:9c (default: file)")
	f.StringVarP(&KEKKeytype, "kek-keytype", "", "", "KEK key type Algorithm and slot for yubikey can also be specified: yubikey:RSA4096:9c (default: file)")
	f.StringVarP(&DbKeytype, "db-keytype", "", "", "db key type Algorithm and slot for yubikey can also be specified: yubikey:RSA4096:9c (default: file)")
	f.StringVarP(&PKSubject, "pk-subj", "", "", "Subject DN for Platform Key certificate (default: /CN=Platform Key/C=WW/)")
	f.StringVarP(&KEKSubject, "kek-subj", "", "", "Subject DN for Key Exchange Key certificate (default: /CN=Key Exchange Key/C=WW/)")
	f.StringVarP(&DbSubject, "db-subj", "", "", "Subject DN for Database Key certificate (default: /CN=Database Key/C=WW/)")
}

func init() {
	createKeysCmdFlags(createKeysCmd)

	CliCommands = append(CliCommands, cliCommand{
		Cmd: createKeysCmd,
	})
}

func splitKeyType(keyType string) (string, string, string) {
	arr := strings.SplitN(keyType, ":", 3)

	if len(arr) == 1 {
		return arr[0], "", ""
	}
	if len(arr) == 2 {
		return arr[0], arr[1], ""
	}
	if len(arr) == 3 {
		return arr[0], arr[1], arr[2]
	}
	return "", "", ""
}
