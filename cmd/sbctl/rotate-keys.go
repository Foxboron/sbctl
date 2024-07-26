package main

import (
	"fmt"
	"path/filepath"
	"time"

	"github.com/foxboron/go-uefi/efi/signature"
	"github.com/foxboron/sbctl"
	"github.com/foxboron/sbctl/backend"
	"github.com/foxboron/sbctl/config"
	"github.com/foxboron/sbctl/fs"
	"github.com/foxboron/sbctl/hierarchy"
	"github.com/foxboron/sbctl/logging"
	"github.com/foxboron/sbctl/stringset"
	"github.com/spf13/cobra"
)

type RotateKeysCmdOptions struct {
	BackupDir  string
	NewKeysDir string
	Partial    stringset.StringSet
	KeyFile    string
	CertFile   string
}

var (
	rotateKeysCmdOptions = RotateKeysCmdOptions{
		Partial: stringset.StringSet{Allowed: []string{hierarchy.PK.String(), hierarchy.KEK.String(), hierarchy.Db.String()}},
	}
	rotateKeysCmd = &cobra.Command{
		Use:   "rotate-keys",
		Short: "Rotate secure boot keys with new keys.",
		RunE:  RunRotateKeys,
	}
)

func rotateCerts(state *config.State, hier hierarchy.Hierarchy, oldkeys *backend.KeyHierarchy, newkeys *backend.KeyHierarchy, efistate *sbctl.EFIVariables) error {
	guid, err := state.Config.GetGUID(state.Fs)
	if err != nil {
		return err
	}

	switch hier {
	case hierarchy.PK:
		cert := oldkeys.PK.CertificateBytes()
		if err := efistate.PK.Remove(signature.CERT_X509_GUID, *guid, cert); err != nil {
			return fmt.Errorf("can't remove old key from PK siglist: %v", err)
		}
		efistate.PK.Append(signature.CERT_X509_GUID, *guid, newkeys.PK.CertificateBytes())
		return efistate.EnrollKey(hier.Efivar(), oldkeys)
	case hierarchy.KEK:
		cert := oldkeys.KEK.CertificateBytes()
		if err := efistate.KEK.Remove(signature.CERT_X509_GUID, *guid, cert); err != nil {
			return fmt.Errorf("can't remove old key from KEK siglist: %v", err)
		}
		efistate.KEK.Append(signature.CERT_X509_GUID, *guid, newkeys.KEK.CertificateBytes())
		return efistate.EnrollKey(hier.Efivar(), oldkeys)
	case hierarchy.Db:
		cert := oldkeys.Db.CertificateBytes()
		if err := efistate.Db.Remove(signature.CERT_X509_GUID, *guid, cert); err != nil {
			return fmt.Errorf("can't remove old key from Db siglist: %v", err)
		}
		efistate.Db.Append(signature.CERT_X509_GUID, *guid, newkeys.Db.CertificateBytes())
		return efistate.EnrollKey(hier.Efivar(), oldkeys)
	default:
		return fmt.Errorf("unknown efivar hierarchy")
	}
}

func RunRotateKeys(cmd *cobra.Command, args []string) error {
	state := cmd.Context().Value(stateDataKey{}).(*config.State)
	partial := rotateKeysCmdOptions.Partial.Value

	// rotate all keys if no specific key should be replaced
	if partial == "" {
		if err := rotateAllKeys(state, rotateKeysCmdOptions.BackupDir, rotateKeysCmdOptions.NewKeysDir); err != nil {
			return err
		}

		return nil
	}

	return rotateKey(state, partial, rotateKeysCmdOptions.KeyFile, rotateKeysCmdOptions.CertFile)
}

func rotateAllKeys(state *config.State, backupDir, newKeysDir string) error {
	oldKeys, err := backend.GetKeyHierarchy(state.Fs, state.Config)
	if err != nil {
		return fmt.Errorf("can't read old keys from dir: %v", err)
	}

	efistate, err := sbctl.SystemEFIVariables(state.Efivarfs)
	if err != nil {
		return fmt.Errorf("can't read efivariables: %v", err)
	}

	if backupDir == "" {
		backupDir = filepath.Join("/var/tmp", fmt.Sprintf("sbctl_backup_keys_%d", time.Now().Unix()))
	}

	if err := sbctl.CopyDirectory(state.Fs, state.Config.Keydir, backupDir); err != nil {
		return err
	}
	logging.Print("Backed up keys to %s\n", backupDir)

	if err := state.Fs.RemoveAll(state.Config.Keydir); err != nil {
		return fmt.Errorf("failed removing old keys: %v", err)
	}

	var newKeyHierarchy *backend.KeyHierarchy

	if newKeysDir == "" {
		logging.Print("Creating secure boot keys...")
		newKeyHierarchy, err = backend.CreateKeys(state.Config)
		if err != nil {
			logging.NotOk("")
			return fmt.Errorf("couldn't initialize secure boot: %w", err)
		}
		err = newKeyHierarchy.SaveKeys(state.Fs, state.Config.Keydir)
		if err != nil {
			logging.NotOk("")
			return fmt.Errorf("couldn't initialize secure boot: %w", err)
		}
		logging.Ok("")
		logging.Println("Secure boot keys created!")

	} else {
		logging.Print("Importing new secure boot keys from %s...", newKeysDir)
		newKeyHierarchy, err = backend.ImportKeys(newKeysDir)
		if err != nil {
			logging.NotOk("")
			return fmt.Errorf("couldn't import secure boot keys: %w", err)
		}
		err = newKeyHierarchy.SaveKeys(state.Fs, state.Config.Keydir)
		if err != nil {
			logging.NotOk("")
			return fmt.Errorf("couldn't import secure boot keys: %w", err)
		}
		logging.Ok("")
		logging.Println("Secure boot keys updated!")

	}

	if err := rotateCerts(state, hierarchy.PK, oldKeys, newKeyHierarchy, efistate); err != nil {
		return fmt.Errorf("could not rotate PK: %v", err)
	}

	if err := rotateCerts(state, hierarchy.KEK, oldKeys, newKeyHierarchy, efistate); err != nil {
		return fmt.Errorf("could not rotate KEK: %v", err)
	}

	if err := rotateCerts(state, hierarchy.Db, oldKeys, newKeyHierarchy, efistate); err != nil {
		return fmt.Errorf("could not rotate Db: %v", err)
	}

	logging.Ok("Enrolled new keys into UEFI!")

	if err := SignAll(state); err != nil {
		return fmt.Errorf("failed resigning files: %v", err)
	}

	return nil
}

func rotateKey(state *config.State, hiera string, keyPath, certPath string) error {
	if keyPath == "" {
		return fmt.Errorf("a new key needs to be provided for a partial reset of %s", hiera)
	}

	if certPath == "" {
		return fmt.Errorf("a new certificate needs to be provided for a partial reset of %s", hiera)
	}

	oldKH, err := backend.GetKeyHierarchy(state.Fs, state.Config)
	if err != nil {
		return fmt.Errorf("can't read old keys from dir: %v", err)
	}

	newCert, err := fs.ReadFile(state.Fs, certPath)
	if err != nil {
		return fmt.Errorf("can't read new certificate from path %s: %v", certPath, err)
	}

	newKey, err := fs.ReadFile(state.Fs, keyPath)
	if err != nil {
		return fmt.Errorf("can't read new certificate from path %s: %v", certPath, err)
	}

	// We will mutate this to the new state
	newKH, err := backend.GetKeyHierarchy(state.Fs, state.Config)
	if err != nil {
		return fmt.Errorf("can't read old keys from dir: %v", err)
	}

	efistate, err := sbctl.SystemEFIVariables(state.Efivarfs)
	if err != nil {
		return fmt.Errorf("can't read efivariables: %v", err)
	}

	switch hiera {
	case hierarchy.PK.String():
		bk, err := backend.InitBackendFromKeys(newKey, newCert, hierarchy.PK)
		if err != nil {
			return fmt.Errorf("could not rotate PK: %v", err)
		}
		newKH.PK = bk
		if err := rotateCerts(state, hierarchy.PK, oldKH, newKH, efistate); err != nil {
			return fmt.Errorf("could not rotate PK: %v", err)
		}
	case hierarchy.KEK.String():
		bk, err := backend.InitBackendFromKeys(newKey, newCert, hierarchy.KEK)
		if err != nil {
			return fmt.Errorf("could not rotate KEK: %v", err)
		}
		newKH.KEK = bk
		if err := rotateCerts(state, hierarchy.KEK, oldKH, newKH, efistate); err != nil {
			return fmt.Errorf("could not rotate KEK: %v", err)
		}
	case hierarchy.Db.String():
		bk, err := backend.InitBackendFromKeys(newKey, newCert, hierarchy.Db)
		if err != nil {
			return fmt.Errorf("could not rotate db: %v", err)
		}
		newKH.Db = bk
		if err := rotateCerts(state, hierarchy.Db, oldKH, newKH, efistate); err != nil {
			return fmt.Errorf("could not rotate db: %v", err)
		}
	}

	if err := newKH.SaveKeys(state.Fs, state.Config.Keydir); err != nil {
		return fmt.Errorf("can't save new key hierarchy: %v", err)
	}

	logging.Ok("Enrolled new key of hierarchy %s into UEFI!", hiera)

	return nil
}

func rotateKeysCmdFlags(cmd *cobra.Command) {
	f := cmd.Flags()
	f.StringVarP(&rotateKeysCmdOptions.BackupDir, "backup-dir", "b", "", "Backup keys to directory")
	f.StringVarP(&rotateKeysCmdOptions.NewKeysDir, "new-keys-dir", "n", "", "Provide new keys to enroll by directory")
	f.VarPF(&rotateKeysCmdOptions.Partial, "partial", "p", "rotate a key of a specific hierarchy")
	f.StringVarP(&rotateKeysCmdOptions.KeyFile, "key-file", "k", "", "key file to replace (only with partial flag)")
	f.StringVarP(&rotateKeysCmdOptions.CertFile, "cert-file", "c", "", "certificate file to replace (only with partial flag)")
}

func init() {
	rotateKeysCmdFlags(rotateKeysCmd)
	CliCommands = append(CliCommands, cliCommand{
		Cmd: rotateKeysCmd,
	})
}
