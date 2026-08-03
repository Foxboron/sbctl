package main

import (
	"fmt"
	"path"
	"path/filepath"

	"github.com/foxboron/sbctl"
	"github.com/foxboron/sbctl/backend"
	"github.com/foxboron/sbctl/config"
	"github.com/foxboron/sbctl/hierarchy"
	"github.com/foxboron/sbctl/logging"
	"github.com/foxboron/sbctl/lsm"
	"github.com/foxboron/sbctl/stringset"
	"github.com/landlock-lsm/go-landlock/landlock"
	"github.com/spf13/cobra"
)

type CreateKeysCmdOptions struct {
	exportPath       string
	databasePath     string
	Keytype          string
	KEKKeytype       string
	DbKeytype        string
	PKKeytype        string
	Partial          stringset.StringSet
	OverwriteYubikey bool
}

var (
	createKeysCmdOptions = CreateKeysCmdOptions{
		Partial: stringset.StringSet{Allowed: []string{"PK", "KEK", "db"}},
	}
	createKeysCmd = &cobra.Command{
		Use:   "create-keys",
		Short: "Create a set of secure boot signing keys",
		RunE: func(cmd *cobra.Command, args []string) error {
			state := cmd.Context().Value(stateDataKey{}).(*config.State)
			return RunCreateKeys(state)
		},
	}
)

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
	if createKeysCmdOptions.exportPath != "" {
		state.Config.Keydir = createKeysCmdOptions.exportPath
	}

	if createKeysCmdOptions.databasePath != "" {
		state.Config.GUID = createKeysCmdOptions.databasePath
	}

	if createKeysCmdOptions.OverwriteYubikey {
		logging.Warn("Overwriting Yubikey option enabled")
		state.Yubikey.Overwrite = true
	}

	if err := sbctl.CreateDirectory(state.Fs, state.Config.Keydir); err != nil {
		return err
	}
	if err := sbctl.CreateDirectory(state.Fs, path.Dir(state.Config.GUID)); err != nil {
		return err
	}

	// Should be own flag type
	if createKeysCmdOptions.Keytype != "" {
		state.Config.Keys.PK.Type = createKeysCmdOptions.Keytype
		state.Config.Keys.KEK.Type = createKeysCmdOptions.Keytype
		state.Config.Keys.Db.Type = createKeysCmdOptions.Keytype
	}
	if createKeysCmdOptions.PKKeytype != "" {
		state.Config.Keys.PK.Type = createKeysCmdOptions.PKKeytype
	}
	if createKeysCmdOptions.KEKKeytype != "" {
		state.Config.Keys.KEK.Type = createKeysCmdOptions.KEKKeytype
	}
	if createKeysCmdOptions.DbKeytype != "" {
		state.Config.Keys.Db.Type = createKeysCmdOptions.DbKeytype
	}

	// if any keytype is yubikey close it appropriately at the end
	if createKeysCmdOptions.Keytype == "yubikey" || createKeysCmdOptions.PKKeytype == "yubikey" || createKeysCmdOptions.KEKKeytype == "yubikey" || createKeysCmdOptions.DbKeytype == "yubikey" {
		defer state.Yubikey.Close()
	}

	uuid, err := sbctl.CreateGUID(state.Fs, state.Config.GUID)
	if err != nil {
		return err
	}
	logging.Print("Created Owner UUID %s\n", uuid)

	var beType backend.BackendType
	var hier hierarchy.Hierarchy
	var desc string
	kh := backend.NewKeyHierarchy(state)

	switch createKeysCmdOptions.Partial.Value {
	case "PK":
		hier = hierarchy.PK
		beType = backend.BackendType(state.Config.Keys.PK.Type)
		desc = state.Config.Keys.PK.Description

	case "KEK":
		hier = hierarchy.KEK
		beType = backend.BackendType(state.Config.Keys.KEK.Type)
		desc = state.Config.Keys.KEK.Description

	case "db":
		hier = hierarchy.Db
		beType = backend.BackendType(state.Config.Keys.Db.Type)
		desc = state.Config.Keys.Db.Description

	default:
		// if no partial flag is given, create all keys
		if sbctl.CheckIfKeysInitialized(state.Fs, state.Config.Keydir) {
			logging.Ok("Secure boot keys have already been created!")
			return nil
		}

		err := kh.CreateKeys()
		if err != nil {
			logging.NotOk("")
			return fmt.Errorf("couldn't initialize secure boot: %w", err)
		}
		err = kh.SaveKeys(state.Fs, state.Config.Keydir)
		if err != nil {
			logging.NotOk("")
			return fmt.Errorf("couldn't initialize secure boot: %w", err)
		}

		logging.Ok("")
		logging.Println("Secure boot keys created!")
		return nil
	}

	if sbctl.CheckIfKeyInitialized(state.Fs, state.Config.Keydir, hier) {
		logging.Ok("%s has already been created!", hier.String())
		return nil
	}

	err = kh.CreateKey(beType, hier, desc)
	if err != nil {
		return fmt.Errorf("couldn't initialize %s: %w", hier.String(), err)
	}
	err = kh.SaveKey(state.Fs, hier, state.Config.Keydir)
	if err != nil {
		return fmt.Errorf("couldn't initialize %s: %w", hier.String(), err)
	}

	logging.Ok("")
	logging.Print("%s created!\n", hier.String())
	return nil
}

func createKeysCmdFlags(cmd *cobra.Command) {
	f := cmd.Flags()
	f.BoolVar(&createKeysCmdOptions.OverwriteYubikey, "yk-overwrite", false, "overwrite existing key if it exists in the Yubikey Signature slot")
	f.StringVarP(&createKeysCmdOptions.exportPath, "export", "e", "", "export file path")
	f.StringVarP(&createKeysCmdOptions.databasePath, "database-path", "d", "", "location to create GUID file")
	f.StringVarP(&createKeysCmdOptions.Keytype, "keytype", "", "", "key type for all keys (individual types take priority)")
	f.StringVarP(&createKeysCmdOptions.PKKeytype, "pk-keytype", "", "", "PK key type (default: file)")
	f.StringVarP(&createKeysCmdOptions.KEKKeytype, "kek-keytype", "", "", "KEK key type (default: file)")
	f.StringVarP(&createKeysCmdOptions.DbKeytype, "db-keytype", "", "", "db key type (default: file)")
	f.VarPF(&createKeysCmdOptions.Partial, "partial", "p", "create a partial set of keys")
}

func init() {
	createKeysCmdFlags(createKeysCmd)

	CliCommands = append(CliCommands, cliCommand{
		Cmd: createKeysCmd,
	})
}
