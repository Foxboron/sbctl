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
	"github.com/foxboron/sbctl/logging"
	"github.com/spf13/cobra"
)

// TODO: Be more selective what you can rotate
type RotateKeysCmdOptions struct {
	BackupDir string
	Db        bool
	Kek       bool
	PK        bool
	All       bool
}

var (
	rotateKeysCmdOptions = RotateKeysCmdOptions{}
	rotateKeysCmd        = &cobra.Command{
		Use:   "rotate-keys",
		Short: "Rotate secure boot keys with new keys.",
		RunE:  RunRotateKeys,
	}
)

// TODO: Abstract this to some common keyhandling abstractions
type Keys struct {
	PKKey   []byte
	PKCert  []byte
	KEKKey  []byte
	KEKCert []byte
	DbKey   []byte
	DbCert  []byte
}

func ReadKeysFromDir(src string) (*Keys, error) {
	k := Keys{}
	var err error
	k.PKKey, err = fs.ReadFile(filepath.Join(src, "PK", "PK.key"))
	if err != nil {
		return &k, err
	}

	k.PKCert, err = fs.ReadFile(filepath.Join(src, "PK", "PK.pem"))
	if err != nil {
		return &k, err
	}

	k.KEKKey, err = fs.ReadFile(filepath.Join(src, "KEK", "KEK.key"))
	if err != nil {
		return &k, err
	}

	k.KEKCert, err = fs.ReadFile(filepath.Join(src, "KEK", "KEK.pem"))
	if err != nil {
		return &k, err
	}

	k.DbCert, err = fs.ReadFile(filepath.Join(src, "db", "db.pem"))
	if err != nil {
		return &k, err
	}
	return &k, err
}

func rotateDb(oldKeys *Keys, newKeys *Keys) error {
	sl, err := efi.Getdb()
	if err != nil {
		return err
	}
	uuid, err := sbctl.GetGUID()
	if err != nil {
		return err
	}
	guid := util.StringToGUID(uuid.String())
	db, err := util.ReadCert(oldKeys.DbCert)
	if err != nil {
		return err
	}
	if err = sl.Remove(signature.CERT_X509_GUID, *guid, db.Raw); err != nil {
		return err
	}
	sl.Append(signature.CERT_X509_GUID, *guid, newKeys.DbCert)
	return sbctl.Enroll(sl, newKeys.KEKKey, newKeys.KEKCert, "db")
}

func rotateKEK(oldKeys *Keys, newKeys *Keys) error {
	sl, err := efi.GetKEK()
	if err != nil {
		return err
	}
	uuid, err := sbctl.GetGUID()
	if err != nil {
		return err
	}
	guid := util.StringToGUID(uuid.String())
	kekCert, err := util.ReadCert(oldKeys.KEKCert)
	if err != nil {
		return err
	}
	if err = sl.Remove(signature.CERT_X509_GUID, *guid, kekCert.Raw); err != nil {
		return err
	}
	sl.Append(signature.CERT_X509_GUID, *guid, newKeys.KEKCert)
	return sbctl.Enroll(sl, newKeys.PKKey, newKeys.PKCert, "KEK")
}

func rotatePK(oldKeys *Keys, newKeys *Keys) error {
	sl, err := efi.GetPK()
	if err != nil {
		return err
	}
	uuid, err := sbctl.GetGUID()
	if err != nil {
		return err
	}
	guid := util.StringToGUID(uuid.String())
	pkCert, err := util.ReadCert(oldKeys.PKCert)
	if err != nil {
		return err
	}
	// We have most likely reset the PK so we don't care about missing sigdata
	sl.Remove(signature.CERT_X509_GUID, *guid, pkCert.Raw)
	sl.Append(signature.CERT_X509_GUID, *guid, newKeys.PKCert)
	return sbctl.Enroll(sl, oldKeys.PKKey, oldKeys.PKCert, "PK")
}

func RunRotateKeys(cmd *cobra.Command, args []string) error {
	if err := resetPK(); err != nil {
		fmt.Println(err)
	}

	oldKeys, err := ReadKeysFromDir(sbctl.KeysPath)
	if err != nil {
		return fmt.Errorf("can't read old keys from dir: %v", err)
	}
	backupDir := rotateKeysCmdOptions.BackupDir
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

	logging.Print("Creating secure boot keys...")
	if err = sbctl.InitializeSecureBootKeys(sbctl.KeysPath); err != nil {
		logging.NotOk("")
		return fmt.Errorf("couldn't initialize secure boot: %w", err)
	}
	logging.Ok("")
	logging.Println("Secure boot keys created!")
	newKeys, err := ReadKeysFromDir(sbctl.KeysPath)
	if err != nil {
		return fmt.Errorf("can't read new keys from dir: %v", err)
	}
	if err := rotatePK(oldKeys, newKeys); err != nil {
		return fmt.Errorf("could not rotate PK: %v", err)
	}
	if err := rotateKEK(oldKeys, newKeys); err != nil {
		return fmt.Errorf("could not rotate KEK: %v", err)
	}
	if err := rotateDb(oldKeys, newKeys); err != nil {
		return fmt.Errorf("could not rotate db: %v", err)
	}
	logging.Ok("Enrolled new keys into UEFI!")

	if err := SignAll(); err != nil {
		return fmt.Errorf("failed resigning files: %v", err)
	}
	return nil
}

func rotateKeysCmdFlags(cmd *cobra.Command) {
	f := cmd.Flags()
	f.StringVarP(&rotateKeysCmdOptions.BackupDir, "backup-dir", "", "", "Backup keys to directory")
}

func init() {
	rotateKeysCmdFlags(rotateKeysCmd)
	CliCommands = append(CliCommands, cliCommand{
		Cmd: rotateKeysCmd,
	})
}
