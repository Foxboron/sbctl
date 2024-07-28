package main

import (
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"

	"github.com/foxboron/go-uefi/efi/util"
	"github.com/foxboron/sbctl"
	"github.com/foxboron/sbctl/config"
	"github.com/foxboron/sbctl/logging"
	"github.com/foxboron/sbctl/lsm"
	"github.com/landlock-lsm/go-landlock/landlock"
	"github.com/spf13/afero"
	"github.com/spf13/cobra"
)

type ImportKeysCmdOptions struct {
	Force     bool
	DbCert    string
	DbKey     string
	KEKCert   string
	KEKKey    string
	PKCert    string
	PKKey     string
	Directory string
}

var (
	importKeysCmdOptions = ImportKeysCmdOptions{}
	importKeysCmd        = &cobra.Command{
		Use:   "import-keys",
		Short: "Import keys into sbctl",
		RunE:  RunImportKeys,
	}
)

func Import(vfs afero.Fs, src, dst string) error {
	logging.Print("Importing %s...", src)
	if err := os.MkdirAll(filepath.Dir(dst), 0777); err != nil {
		logging.NotOk("")
		return fmt.Errorf("could not create directory for %q: %w", dst, err)
	}
	if err := sbctl.CopyFile(vfs, src, dst); err != nil {
		logging.NotOk("")
		return fmt.Errorf("could not move %s: %w", src, err)
	}
	logging.Ok("")
	return nil
}

func ImportKeysFromDirectory(state *config.State, dir string) error {
	keys := []string{
		"PK/PK.key",
		"PK/PK.pem",
		"KEK/KEK.key",
		"KEK/KEK.pem",
		"db/db.key",
		"db/db.pem",
	}
	dir, err := filepath.Abs(dir)
	if err != nil {
		return err
	}
	for _, f := range keys {
		keyFile := path.Join(dir, f)
		if _, err := state.Fs.Stat(keyFile); errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("file does not exist: %s", keyFile)
		}
	}

	for _, f := range keys {
		keyFile := path.Join(dir, f)
		dstFile := path.Join(state.Config.Keydir, f)
		if err = Import(state.Fs, keyFile, dstFile); err != nil {
			return err
		}
	}
	return nil
}

func RunImportKeys(cmd *cobra.Command, args []string) error {
	var err error
	keypairs := []struct {
		Type string
		Key  string
		Cert string
	}{
		{"db", importKeysCmdOptions.DbKey, importKeysCmdOptions.DbCert},
		{"KEK", importKeysCmdOptions.KEKKey, importKeysCmdOptions.KEKCert},
		{"PK", importKeysCmdOptions.PKKey, importKeysCmdOptions.PKCert},
	}

	state := cmd.Context().Value(stateDataKey{}).(*config.State)

	if state.Config.Landlock {
		for _, key := range keypairs {
			if key.Key != "" {
				lsm.RestrictAdditionalPaths(
					landlock.RWFiles(key.Key),
				)
			}
			if key.Cert != "" {
				lsm.RestrictAdditionalPaths(
					landlock.RWFiles(key.Cert),
				)
			}
		}

		if importKeysCmdOptions.Directory != "" {
			lsm.RestrictAdditionalPaths(
				landlock.ROFiles(importKeysCmdOptions.Directory),
			)
		}

		if err := lsm.Restrict(); err != nil {
			return err
		}
	}

	if importKeysCmdOptions.Directory != "" {
		_, err := state.Fs.Stat(state.Config.Keydir)
		if err == nil && !importKeysCmdOptions.Force {
			return fmt.Errorf("key directory exists. Use --force to overwrite the current directory")
		}
		return ImportKeysFromDirectory(state, importKeysCmdOptions.Directory)
	}
	for _, key := range keypairs {
		if key.Key == "" && key.Cert == "" {
			continue
		}

		for _, s := range []string{key.Key, key.Cert} {
			if _, err = state.Fs.Stat(s); errors.Is(err, os.ErrNotExist) {
				return fmt.Errorf("keyfile %s does not exist", s)
			}
		}

		if !importKeysCmdOptions.Force {
			if _, err := util.ReadCertFromFile(key.Cert); err != nil {
				return fmt.Errorf("invalid certificate file")
			}
			if _, err := util.ReadKeyFromFile(key.Key); err != nil {
				return fmt.Errorf("invalid private key file")
			}
		}

		for src, dst := range map[string]string{
			key.Cert: path.Join(state.Config.Keydir, key.Type, key.Type+".pem"),
			key.Key:  path.Join(state.Config.Keydir, key.Type, key.Type+".key"),
		} {
			srcFile, err := filepath.Abs(src)
			if err != nil {
				return err
			}
			if err = Import(state.Fs, srcFile, dst); err != nil {
				return err
			}
		}
	}
	return nil
}

func importKeysCmdFlags(cmd *cobra.Command) {
	f := cmd.Flags()
	f.StringVarP(&importKeysCmdOptions.DbCert, "db-cert", "", "", "Database (db) certificate")
	f.StringVarP(&importKeysCmdOptions.DbKey, "db-key", "", "", "Database (db) key")
	f.StringVarP(&importKeysCmdOptions.KEKCert, "kek-cert", "", "", "Key Exchange Key (KEK) certificate")
	f.StringVarP(&importKeysCmdOptions.KEKKey, "kek-key", "", "", "Key Exchange Key (KEK) key")
	f.StringVarP(&importKeysCmdOptions.PKCert, "pk-cert", "", "", "Platform Key (PK) certificate")
	f.StringVarP(&importKeysCmdOptions.PKKey, "pk-key", "", "", "Platform Key (PK) key")
	f.StringVarP(&importKeysCmdOptions.Directory, "directory", "d", "", "Import keys from a directory")
	f.BoolVarP(&importKeysCmdOptions.Force, "force", "", false, "Force import")
}

func init() {
	importKeysCmdFlags(importKeysCmd)
	CliCommands = append(CliCommands, cliCommand{
		Cmd: importKeysCmd,
	})
}
