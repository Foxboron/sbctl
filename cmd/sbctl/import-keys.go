package main

import (
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"

	"github.com/foxboron/go-uefi/efi/util"
	"github.com/foxboron/sbctl"
	"github.com/foxboron/sbctl/fs"
	"github.com/foxboron/sbctl/logging"
	"github.com/spf13/cobra"
)

type ImportKeysCmdOptions struct {
	Force     bool
	DbCert    string
	DbKey     string
	DbxCert   string
	DbxKey    string
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

func Import(src, dst string) error {
	logging.Print("Importing %s...", src)
	if err := sbctl.CopyFile(src, dst); err != nil {
		logging.NotOk("")
		return fmt.Errorf("could not move %s: %w", src, err)
	}
	logging.Ok("")
	return nil
}

func ImportKeysFromDirectory(dir string) error {
	keys := []string{
		"PK/PK.key",
		"PK/PK.pem",
		"KEK/KEK.key",
		"KEK/KEK.pem",
		"db/db.key",
		"db/db.pem",
		"dbx/dbx.key",
		"dbx/dbx.pem",
	}
	dir, err := filepath.Abs(dir)
	if err != nil {
		return err
	}
	for _, f := range keys {
		keyFile := path.Join(dir, f)
		if _, err := fs.Fs.Stat(keyFile); errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("file does not exist: %s", keyFile)
		}
	}

	for _, f := range keys {
		keyFile := path.Join(dir, f)
		dstFile := path.Join(sbctl.KeysPath, f)
		if err = Import(keyFile, dstFile); err != nil {
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
		{"dbx", importKeysCmdOptions.DbxKey, importKeysCmdOptions.DbxCert},
		{"KEK", importKeysCmdOptions.KEKKey, importKeysCmdOptions.KEKCert},
		{"PK", importKeysCmdOptions.PKKey, importKeysCmdOptions.PKCert},
	}

	if importKeysCmdOptions.Directory != "" {
		_, err := fs.Fs.Stat(sbctl.KeysPath)
		if err == nil && !importKeysCmdOptions.Force {
			return fmt.Errorf("key directory exists. Use --force to overwrite the current directory")
		}
		return ImportKeysFromDirectory(importKeysCmdOptions.Directory)
	}
	for _, key := range keypairs {
		if key.Key == "" && key.Cert == "" {
			continue
		}

		for _, s := range []string{key.Key, key.Cert} {
			if _, err = fs.Fs.Stat(s); errors.Is(err, os.ErrNotExist) {
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
			key.Cert: path.Join(sbctl.KeysPath, key.Type, key.Type+".pem"),
			key.Key:  path.Join(sbctl.KeysPath, key.Type, key.Type+".key"),
		} {
			srcFile, err := filepath.Abs(src)
			if err != nil {
				return err
			}
			if err = Import(srcFile, dst); err != nil {
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
	f.StringVarP(&importKeysCmdOptions.DbxCert, "dbx-cert", "", "", "Forbidden Database (dbx) certificate")
	f.StringVarP(&importKeysCmdOptions.DbxKey, "dbx-key", "", "", "Forbidden Database (dbx) key")
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
