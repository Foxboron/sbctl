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
	"github.com/foxboron/sbctl/lsm"
	"github.com/foxboron/sbctl/stringset"
	"github.com/landlock-lsm/go-landlock/landlock"
	"github.com/spf13/cobra"
)

type RotateKeysCmdOptions struct {
	BackupDir  string
	NewKeysDir string
	Partial    stringset.StringSet
	KeyFile    string
	CertFile   string

	Keytype                          string
	PKKeytype, KEKKeytype, DbKeytype string
}

var (
	tmpPath              = "/var/tmp/sbctl/"
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

	// Note:
	// PK needs to be signed by the old key hierarchy, as old PK signs new PK
	// However db and KEK needs to be signed by new key hierarchy, as new PK -> new KEK,
	// and new KEK -> new Db

	switch hier {
	case hierarchy.PK:
		// fmt.Printf("Old PK: %s\n", oldkeys.PK.Certificate().SerialNumber.String())
		// fmt.Printf("New PK: %s\n", newkeys.PK.Certificate().SerialNumber.String())
		cert := oldkeys.PK.Certificate().Raw
		if efistate.PK.SigDataExists(signature.CERT_X509_GUID, &signature.SignatureData{Owner: *guid, Data: cert}) {
			if err := efistate.PK.Remove(signature.CERT_X509_GUID, *guid, cert); err != nil {
				return fmt.Errorf("can't remove old key from PK siglist: %v", err)
			}
		}
		efistate.PK.Append(signature.CERT_X509_GUID, *guid, newkeys.PK.CertificateBytes())
		return efistate.EnrollKey(hier.Efivar(), oldkeys)
	case hierarchy.KEK:
		// fmt.Printf("Old KEK: %s\n", oldkeys.KEK.Certificate().SerialNumber.String())
		// fmt.Printf("New KEK: %s\n", newkeys.KEK.Certificate().SerialNumber.String())
		cert := oldkeys.KEK.Certificate().Raw
		if efistate.KEK.SigDataExists(signature.CERT_X509_GUID, &signature.SignatureData{Owner: *guid, Data: cert}) {
			if err := efistate.KEK.Remove(signature.CERT_X509_GUID, *guid, cert); err != nil {
				return fmt.Errorf("can't remove old key from KEK siglist: %v", err)
			}
		}
		efistate.KEK.Append(signature.CERT_X509_GUID, *guid, newkeys.KEK.CertificateBytes())
		return efistate.EnrollKey(hier.Efivar(), newkeys)
	case hierarchy.Db:
		// fmt.Printf("Old Db: %s\n", oldkeys.Db.Certificate().SerialNumber.String())
		// fmt.Printf("New Db: %s\n", newkeys.Db.Certificate().SerialNumber.String())
		cert := oldkeys.Db.Certificate().Raw
		if efistate.Db.SigDataExists(signature.CERT_X509_GUID, &signature.SignatureData{Owner: *guid, Data: cert}) {
			if err := efistate.Db.Remove(signature.CERT_X509_GUID, *guid, cert); err != nil {
				return fmt.Errorf("can't remove old key from Db siglist: %v", err)
			}
		}
		efistate.Db.Append(signature.CERT_X509_GUID, *guid, newkeys.Db.CertificateBytes())
		return efistate.EnrollKey(hier.Efivar(), newkeys)
	default:
		return fmt.Errorf("unknown efivar hierarchy")
	}
}

func RunRotateKeys(cmd *cobra.Command, args []string) error {
	state := cmd.Context().Value(stateDataKey{}).(*config.State)

	if err := state.Fs.MkdirAll(tmpPath, 0600); err != nil {
		return fmt.Errorf("can't create tmp directory: %v", err)
	}

	if state.Config.Landlock {
		lsm.RestrictAdditionalPaths(
			landlock.RWDirs(tmpPath),
		)
		if err := sbctl.LandlockFromFileDatabase(state); err != nil {
			return err
		}
		if err := lsm.Restrict(); err != nil {
			return err
		}
	}

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
	oldKeys, err := backend.GetKeyHierarchy(state.Fs, state)
	if err != nil {
		return fmt.Errorf("can't read old keys from dir: %v", err)
	}

	efistate, err := sbctl.SystemEFIVariables(state.Efivarfs)
	if err != nil {
		return fmt.Errorf("can't read efivariables: %v", err)
	}

	if backupDir == "" {
		backupDir = filepath.Join(tmpPath, fmt.Sprintf("sbctl_backup_keys_%d", time.Now().Unix()))
	}

	if err := sbctl.CopyDirectory(state.Fs, state.Config.Keydir, backupDir); err != nil {
		return err
	}
	logging.Print("Backed up keys to %s\n", backupDir)

	if err := state.Fs.RemoveAll(state.Config.Keydir); err != nil {
		return fmt.Errorf("failed removing old keys: %v", err)
	}

	// Should be own flag type, and deduplicated
	// It should be fine to modify the state here?
	if rotateKeysCmdOptions.Keytype != "" && (rotateKeysCmdOptions.Keytype == "file" || rotateKeysCmdOptions.Keytype == "tpm") {
		state.Config.Keys.PK.Type = rotateKeysCmdOptions.Keytype
		state.Config.Keys.KEK.Type = rotateKeysCmdOptions.Keytype
		state.Config.Keys.Db.Type = rotateKeysCmdOptions.Keytype
	} else {
		if rotateKeysCmdOptions.PKKeytype != "" && (rotateKeysCmdOptions.PKKeytype == "file" || rotateKeysCmdOptions.PKKeytype == "tpm") {
			state.Config.Keys.PK.Type = rotateKeysCmdOptions.PKKeytype
		}
		if rotateKeysCmdOptions.KEKKeytype != "" && (rotateKeysCmdOptions.KEKKeytype == "file" || rotateKeysCmdOptions.KEKKeytype == "tpm") {
			state.Config.Keys.KEK.Type = rotateKeysCmdOptions.KEKKeytype
		}
		if rotateKeysCmdOptions.DbKeytype != "" && (rotateKeysCmdOptions.DbKeytype == "file" || rotateKeysCmdOptions.DbKeytype == "tpm") {
			state.Config.Keys.Db.Type = rotateKeysCmdOptions.DbKeytype
		}
	}

	var newKeyHierarchy *backend.KeyHierarchy

	if newKeysDir == "" {
		logging.Print("Creating secure boot keys...")
		newKeyHierarchy, err = backend.CreateKeys(state)
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

	oldKH, err := backend.GetKeyHierarchy(state.Fs, state)
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
	newKH, err := backend.GetKeyHierarchy(state.Fs, state)
	if err != nil {
		return fmt.Errorf("can't read old keys from dir: %v", err)
	}

	efistate, err := sbctl.SystemEFIVariables(state.Efivarfs)
	if err != nil {
		return fmt.Errorf("can't read efivariables: %v", err)
	}

	// Should be own flag type, and deduplicated
	// It should be fine to modify the state here?
	if rotateKeysCmdOptions.Keytype != "" && (rotateKeysCmdOptions.Keytype == "file" || rotateKeysCmdOptions.Keytype == "tpm") {
		state.Config.Keys.PK.Type = rotateKeysCmdOptions.Keytype
		state.Config.Keys.KEK.Type = rotateKeysCmdOptions.Keytype
		state.Config.Keys.Db.Type = rotateKeysCmdOptions.Keytype
	} else {
		if rotateKeysCmdOptions.PKKeytype != "" && (rotateKeysCmdOptions.PKKeytype == "file" || rotateKeysCmdOptions.PKKeytype == "tpm") {
			state.Config.Keys.PK.Type = rotateKeysCmdOptions.PKKeytype
		}
		if rotateKeysCmdOptions.KEKKeytype != "" && (rotateKeysCmdOptions.KEKKeytype == "file" || rotateKeysCmdOptions.KEKKeytype == "tpm") {
			state.Config.Keys.KEK.Type = rotateKeysCmdOptions.KEKKeytype
		}
		if rotateKeysCmdOptions.DbKeytype != "" && (rotateKeysCmdOptions.DbKeytype == "file" || rotateKeysCmdOptions.DbKeytype == "tpm") {
			state.Config.Keys.Db.Type = rotateKeysCmdOptions.DbKeytype
		}
	}

	switch hiera {
	case hierarchy.PK.String():
		bk, err := backend.InitBackendFromKeys(state, newKey, newCert, hierarchy.PK)
		if err != nil {
			return fmt.Errorf("could not rotate PK: %v", err)
		}
		newKH.PK = bk
		if err := rotateCerts(state, hierarchy.PK, oldKH, newKH, efistate); err != nil {
			return fmt.Errorf("could not rotate PK: %v", err)
		}
	case hierarchy.KEK.String():
		bk, err := backend.InitBackendFromKeys(state, newKey, newCert, hierarchy.KEK)
		if err != nil {
			return fmt.Errorf("could not rotate KEK: %v", err)
		}
		newKH.KEK = bk
		if err := rotateCerts(state, hierarchy.KEK, oldKH, newKH, efistate); err != nil {
			return fmt.Errorf("could not rotate KEK: %v", err)
		}
	case hierarchy.Db.String():
		bk, err := backend.InitBackendFromKeys(state, newKey, newCert, hierarchy.Db)
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

	f.StringVarP(&rotateKeysCmdOptions.Keytype, "keytype", "", "", "key type for all keys")
	f.StringVarP(&rotateKeysCmdOptions.PKKeytype, "pk-keytype", "", "", "PK key type (default: file)")
	f.StringVarP(&rotateKeysCmdOptions.KEKKeytype, "kek-keytype", "", "", "KEK key type (default: file)")
	f.StringVarP(&rotateKeysCmdOptions.DbKeytype, "db-keytype", "", "", "db key type (default: file)")
}

func init() {
	rotateKeysCmdFlags(rotateKeysCmd)
	CliCommands = append(CliCommands, cliCommand{
		Cmd: rotateKeysCmd,
	})
}
