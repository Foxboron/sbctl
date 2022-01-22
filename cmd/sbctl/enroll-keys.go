package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/foxboron/go-uefi/efi/signature"
	"github.com/foxboron/go-uefi/efi/util"
	"github.com/foxboron/sbctl"
	"github.com/foxboron/sbctl/certs"
	"github.com/foxboron/sbctl/logging"
	"github.com/spf13/cobra"
)

type EnrollKeysCmdOptions struct {
	MicrosoftKeys        bool
	IgnoreImmutable      bool
	Force                bool
	TPMEventlogChecksums bool
}

var (
	systemEventlog       = "/sys/kernel/security/tpm0/binary_bios_measurements"
	enrollKeysCmdOptions = EnrollKeysCmdOptions{}
	enrollKeysCmd        = &cobra.Command{
		Use:   "enroll-keys",
		Short: "Enroll the current keys to EFI",
		RunE:  RunEnrollKeys,
	}
)

// Sync keys from a key directory into efivarfs
func KeySync(guid util.EFIGUID, keydir string, oems []string) error {
	var sigdb *signature.SignatureDatabase

	PKKey, _ := os.ReadFile(filepath.Join(keydir, "PK", "PK.key"))
	PKPem, _ := os.ReadFile(filepath.Join(keydir, "PK", "PK.pem"))
	KEKKey, _ := os.ReadFile(filepath.Join(keydir, "KEK", "KEK.key"))
	KEKPem, _ := os.ReadFile(filepath.Join(keydir, "KEK", "KEK.pem"))
	dbPem, _ := os.ReadFile(filepath.Join(keydir, "db", "db.pem"))

	sigdb = signature.NewSignatureDatabase()
	sigdb.Append(signature.CERT_X509_GUID, guid, dbPem)

	if len(oems) > 0 {
		for _, oem := range oems {
			switch oem {
			case "tpm-eventlog":
				logging.Print("\nWith cheksums from the TPM Eventlog...")
				eventlogDB, err := sbctl.GetEventlogChecksums(systemEventlog)
				if err != nil {
					return fmt.Errorf("could not enroll db keys: %w", err)
				}
				if len((*eventlogDB)) == 0 {
					return fmt.Errorf("could not find any OpROM entries in the TPM eventlog")
				}
				sigdb.AppendDatabase(eventlogDB)
			default:
				logging.Print("\nWith vendor keys from %s...", strings.Title(oem))
				oemSigDb, err := certs.GetCerts(oem)
				if err != nil {
					return fmt.Errorf("could not enroll db keys: %w", err)
				}
				sigdb.AppendDatabase(oemSigDb)
			}
		}
	}
	if err := sbctl.Enroll(sigdb, dbPem, KEKKey, KEKPem, "db"); err != nil {
		return err
	}

	sigdb = signature.NewSignatureDatabase()
	sigdb.Append(signature.CERT_X509_GUID, guid, KEKPem)
	if err := sbctl.Enroll(sigdb, KEKPem, PKKey, PKPem, "KEK"); err != nil {
		return err
	}

	sigdb = signature.NewSignatureDatabase()
	sigdb.Append(signature.CERT_X509_GUID, guid, PKPem)
	if err := sbctl.Enroll(sigdb, PKPem, PKKey, PKPem, "PK"); err != nil {
		return err
	}
	return nil
}

func RunEnrollKeys(cmd *cobra.Command, args []string) error {
	oems := []string{}
	if enrollKeysCmdOptions.MicrosoftKeys {
		oems = append(oems, "microsoft")
	}
	if enrollKeysCmdOptions.TPMEventlogChecksums {
		oems = append(oems, "tpm-eventlog")
	}
	if !enrollKeysCmdOptions.IgnoreImmutable {
		if err := sbctl.CheckImmutable(); err != nil {
			return err
		}
	}
	if !(enrollKeysCmdOptions.Force || enrollKeysCmdOptions.TPMEventlogChecksums || enrollKeysCmdOptions.MicrosoftKeys) {
		if err := sbctl.CheckEventlogOprom(systemEventlog); err != nil {
			return err
		}
	}
	uuid, err := sbctl.GetGUID()
	if err != nil {
		return err
	}
	guid := util.StringToGUID(uuid.String())
	logging.Print("Enrolling keys to EFI variables...")
	if err := KeySync(*guid, sbctl.KeysPath, oems); err != nil {
		logging.NotOk("")
		return fmt.Errorf("couldn't sync keys: %w", err)
	}
	logging.Ok("\nEnrolled keys to the EFI variables!")
	return nil
}

func vendorFlags(cmd *cobra.Command) {
	f := cmd.Flags()
	f.BoolVarP(&enrollKeysCmdOptions.MicrosoftKeys, "microsoft", "m", false, "include microsoft keys into key enrollment")
	f.BoolVarP(&enrollKeysCmdOptions.TPMEventlogChecksums, "tpm-eventlog", "t", false, "include TPM eventlog checksums into the db database")
}

func enrollKeysCmdFlags(cmd *cobra.Command) {
	f := cmd.Flags()
	f.BoolVarP(&enrollKeysCmdOptions.Force, "yes-this-might-brick-my-machine", "", false, "ignore any errors and enroll keys")
	f.BoolVarP(&enrollKeysCmdOptions.Force, "yolo", "", false, "yolo")
	f.MarkHidden("yolo")
	f.BoolVarP(&enrollKeysCmdOptions.IgnoreImmutable, "ignore-immutable", "i", false, "ignore checking for immutable efivarfs files")
}

func init() {
	enrollKeysCmdFlags(enrollKeysCmd)
	vendorFlags(enrollKeysCmd)
	CliCommands = append(CliCommands, cliCommand{
		Cmd: enrollKeysCmd,
	})
}
