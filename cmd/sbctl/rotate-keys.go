package main

import (
	"fmt"
	"path/filepath"
	"time"

	"github.com/foxboron/go-uefi/efi"
	"github.com/foxboron/go-uefi/efi/signature"
	"github.com/foxboron/go-uefi/efi/util"
	"github.com/foxboron/sbctl"
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

type KeyCertPair struct {
	Key  []byte
	Cert []byte
}

type Keys struct {
	PK  *KeyCertPair
	KEK *KeyCertPair
	Db  *KeyCertPair
}

func ReadKeysFromDir(src string) (*Keys, error) {
	k := Keys{}
	var err error

	k.PK, err = ReadPair(src, hierarchy.PK)
	if err != nil {
		return &k, err
	}

	k.KEK, err = ReadPair(src, hierarchy.KEK)
	if err != nil {
		return &k, err
	}

	k.Db, err = ReadPair(src, hierarchy.Db)
	if err != nil {
		return &k, err
	}
	return &k, err
}

func ReadPair(src string, hierarchy hierarchy.Hierarchy) (*KeyCertPair, error) {
	var (
		k   KeyCertPair
		err error
	)

	k.Key, err = fs.ReadFile(filepath.Join(src, hierarchy.String(), fmt.Sprintf("%s.key", hierarchy.String())))
	if err != nil {
		return &k, err
	}

	k.Cert, err = fs.ReadFile(filepath.Join(src, hierarchy.String(), fmt.Sprintf("%s.pem", hierarchy.String())))
	if err != nil {
		return &k, err
	}

	return &k, err
}

func rotateCerts(hiera hierarchy.Hierarchy, oldCert, newCert []byte, keyCertPair *KeyCertPair) error {
	var (
		sl  *signature.SignatureDatabase
		err error
	)

	switch hiera {
	case hierarchy.PK:
		sl, err = efi.GetPK()
	case hierarchy.KEK:
		sl, err = efi.GetKEK()
	case hierarchy.Db:
		sl, err = efi.Getdb()
	}

	if err != nil {
		return err
	}

	uuid, err := sbctl.GetGUID()
	if err != nil {
		return err
	}

	guid := util.StringToGUID(uuid.String())

	cert, err := util.ReadCert(oldCert)
	if err != nil {
		return err
	}

	if err = sl.Remove(signature.CERT_X509_GUID, *guid, cert.Raw); err != nil {
		return err
	}

	sl.Append(signature.CERT_X509_GUID, *guid, newCert)

	return sbctl.Enroll(sl, keyCertPair.Key, keyCertPair.Cert, hiera.String())
}

func RunRotateKeys(cmd *cobra.Command, args []string) error {
	partial := rotateKeysCmdOptions.Partial.Value

	// rotate all keys if no specific key should be replaced
	if partial == "" {

		if err := rotateAllKeys(rotateKeysCmdOptions.BackupDir, rotateKeysCmdOptions.NewKeysDir); err != nil {
			return err
		}

		return nil
	}

	return rotateKey(partial, rotateKeysCmdOptions.KeyFile, rotateKeysCmdOptions.CertFile)
}

func rotateAllKeys(backupDir, newKeysDir string) error {
	oldKeys, err := ReadKeysFromDir(sbctl.KeysPath)
	if err != nil {
		return fmt.Errorf("can't read old keys from dir: %v", err)
	}

	if backupDir == "" {
		backupDir = filepath.Join("/var/tmp", fmt.Sprintf("sbctl_backup_keys_%d", time.Now().Unix()))
	}

	if err := sbctl.CopyDirectory(sbctl.KeysPath, backupDir); err != nil {
		return err
	}
	logging.Print("Backed up keys to %s\n", backupDir)

	if err := fs.Fs.RemoveAll(sbctl.KeysPath); err != nil {
		return fmt.Errorf("failed removing old keys: %v", err)
	}

	var newKeys *Keys

	if newKeysDir == "" {
		logging.Print("Creating secure boot keys...")
		if err = sbctl.InitializeSecureBootKeys(sbctl.KeysPath); err != nil {
			logging.NotOk("")
			return fmt.Errorf("couldn't initialize secure boot: %w", err)
		}
		logging.Ok("")
		logging.Println("Secure boot keys created!")

	} else {
		logging.Print("Importing new secure boot keys from %s...", newKeysDir)
		if err := ImportKeysFromDirectory(newKeysDir); err != nil {
			logging.NotOk("")
			return fmt.Errorf("couldn't import secure boot: %w", err)
		}
		logging.Ok("")
		logging.Println("Secure boot keys updated!")

	}

	newKeys, err = ReadKeysFromDir(sbctl.KeysPath)
	if err != nil {
		return fmt.Errorf("can't read new keys from dir: %v", err)
	}

	if err := rotateCerts(hierarchy.PK, oldKeys.PK.Cert, newKeys.PK.Cert, oldKeys.PK); err != nil {
		return fmt.Errorf("could not rotate PK: %v", err)
	}

	if err := rotateCerts(hierarchy.KEK, oldKeys.KEK.Cert, newKeys.KEK.Cert, newKeys.PK); err != nil {
		return fmt.Errorf("could not rotate KEK: %v", err)
	}

	if err := rotateCerts(hierarchy.Db, oldKeys.Db.Cert, newKeys.Db.Cert, newKeys.KEK); err != nil {
		return fmt.Errorf("could not rotate db: %v", err)
	}

	logging.Ok("Enrolled new keys into UEFI!")

	if err := SignAll(); err != nil {
		return fmt.Errorf("failed resigning files: %v", err)
	}

	return nil
}

func rotateKey(hiera string, keyPath, certPath string) error {
	if keyPath == "" {
		return fmt.Errorf("a new key needs to be provided for a partial reset of %s", hiera)
	}

	if certPath == "" {
		return fmt.Errorf("a new certificate needs to be provided for a partial reset of %s", hiera)
	}

	oldKeys, err := ReadKeysFromDir(sbctl.KeysPath)
	if err != nil {
		return fmt.Errorf("can't read old keys from dir: %v", err)
	}

	newCert, err := fs.ReadFile(certPath)
	if err != nil {
		return fmt.Errorf("can't read new certificate from path %s: %v", certPath, err)
	}

	var (
		importKeyDst  string
		importCertDst string
	)

	switch hiera {
	case hierarchy.PK.String():
		if err := rotateCerts(hierarchy.PK, oldKeys.PK.Cert, newCert, oldKeys.PK); err != nil {
			return fmt.Errorf("could not rotate PK: %v", err)
		}

		importKeyDst = sbctl.PKKey
		importCertDst = sbctl.PKCert
	case hierarchy.KEK.String():
		if err := rotateCerts(hierarchy.KEK, oldKeys.KEK.Cert, newCert, oldKeys.PK); err != nil {
			return fmt.Errorf("could not rotate KEK: %v", err)
		}

		importKeyDst = sbctl.KEKKey
		importCertDst = sbctl.KEKCert
	case hierarchy.Db.String():
		if err := rotateCerts(hierarchy.Db, oldKeys.Db.Cert, newCert, oldKeys.KEK); err != nil {
			return fmt.Errorf("could not rotate db: %v", err)
		}

		importKeyDst = sbctl.DBKey
		importCertDst = sbctl.DBCert
	}
	
	logging.Ok("Enrolled new key of hierarchy %s into UEFI!", hiera)

	// import new key and certificate
	if err = Import(keyPath, importKeyDst); err != nil {
		return fmt.Errorf("could not replace key: %s", err)
	}

	if err = Import(certPath, importCertDst); err != nil {
		return fmt.Errorf("could not replace certificate: %s", err)
	}

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
