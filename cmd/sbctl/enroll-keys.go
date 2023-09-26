package main

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/foxboron/go-uefi/efi"
	"github.com/foxboron/go-uefi/efi/signature"
	"github.com/foxboron/go-uefi/efi/util"
	"github.com/foxboron/sbctl"
	"github.com/foxboron/sbctl/certs"
	"github.com/foxboron/sbctl/fs"
	"github.com/foxboron/sbctl/logging"
	"github.com/foxboron/sbctl/stringset"
	"github.com/spf13/cobra"
)

type FirmwareBuiltinFlags []string

func (f *FirmwareBuiltinFlags) String() string {
	return strings.Join(*f, ",")
}

// Set must have pointer receiver so it doesn't change the value of a copy
func (f *FirmwareBuiltinFlags) Set(v string) error {
	for _, val := range strings.Split(v, ",") {
		*f = append(*f, val)
	}
	return nil
}

func (f *FirmwareBuiltinFlags) Type() string {
	return ""
}

type EnrollKeysCmdOptions struct {
	Append               bool
	MicrosoftKeys        bool
	IgnoreImmutable      bool
	Force                bool
	TPMEventlogChecksums bool
	Custom               bool
	CustomBytes          string
	Partial              stringset.StringSet
	BuiltinFirmwareCerts FirmwareBuiltinFlags
	Export               stringset.StringSet
}

var (
	systemEventlog       = "/sys/kernel/security/tpm0/binary_bios_measurements"
	enrollKeysCmdOptions = EnrollKeysCmdOptions{
		Partial: stringset.StringSet{Allowed: []string{"PK", "KEK", "db", "dbx"}},
		Export:  stringset.StringSet{Allowed: []string{"esl", "auth"}},
	}
	enrollKeysCmd = &cobra.Command{
		Use:   "enroll-keys",
		Short: "Enroll the current keys to EFI",
		RunE:  RunEnrollKeys,
	}
	ErrSetupModeDisabled = errors.New("setup mode is disabled")
)

// Sync keys from a key directory into efivarfs
func KeySync(guid util.EFIGUID, keydir string, oems []string) error {
	// Prepare all the keys we need
	PKKey, err := fs.ReadFile(filepath.Join(keydir, "PK", "PK.key"))
	if err != nil {
		return err
	}

	PKPem, err := fs.ReadFile(filepath.Join(keydir, "PK", "PK.pem"))
	if err != nil {
		return err
	}

	KEKKey, err := fs.ReadFile(filepath.Join(keydir, "KEK", "KEK.key"))
	if err != nil {
		return err
	}

	KEKPem, err := fs.ReadFile(filepath.Join(keydir, "KEK", "KEK.pem"))
	if err != nil {
		return err
	}

	dbPem, err := fs.ReadFile(filepath.Join(keydir, "db", "db.pem"))
	if err != nil {
		return err
	}

	dbxPem, err := fs.ReadFile(filepath.Join(keydir, "dbx", "dbx.pem"))
	if err != nil {
		return err
	}

	// Create the signature databases
	var sigdb, sigdbx, sigkek, sigpk *signature.SignatureDatabase

	if !enrollKeysCmdOptions.Append {
		sigdb = signature.NewSignatureDatabase()

		sigdbx = signature.NewSignatureDatabase()

		sigkek = signature.NewSignatureDatabase()

		sigpk = signature.NewSignatureDatabase()
		// on append use the existing signature db
	} else {
		sigdb, err = efi.Getdb()
		if err != nil {
			return err
		}

		sigdbx, err = efi.Getdbx()
		if err != nil {
			return err
		}

		sigkek, err = efi.GetKEK()
		if err != nil {
			return err
		}

		sigpk, err = efi.GetPK()
		if err != nil {
			return err
		}
	}

	if err = sigdb.Append(signature.CERT_X509_GUID, guid, dbPem); err != nil {
		return err
	}

	if err = sigdbx.Append(signature.CERT_X509_GUID, guid, dbxPem); err != nil {
		return err
	}

	if err = sigkek.Append(signature.CERT_X509_GUID, guid, KEKPem); err != nil {
		return err
	}

	if err = sigpk.Append(signature.CERT_X509_GUID, guid, PKPem); err != nil {
		return err
	}

	// If we want OEM certs, we do that here
	for _, oem := range oems {
		switch oem {
		case "tpm-eventlog":
			logging.Print("\nWith checksums from the TPM Eventlog...")
			eventlogDB, err := sbctl.GetEventlogChecksums(systemEventlog)
			if err != nil {
				return fmt.Errorf("could not enroll db keys: %w", err)
			}
			if len((*eventlogDB)) == 0 {
				return fmt.Errorf("could not find any OpROM entries in the TPM eventlog")
			}
			sigdb.AppendDatabase(eventlogDB)
		case "microsoft":
			logging.Print("\nWith vendor keys from microsoft...")

			// db
			oemSigDb, err := certs.GetOEMCerts(oem, "db")
			if err != nil {
				return fmt.Errorf("could not enroll db keys: %w", err)
			}
			sigdb.AppendDatabase(oemSigDb)

			// dbx
			oemSigDbx, err := certs.GetOEMCerts(oem, "dbx")
			if err != nil {
				return fmt.Errorf("could not enroll db keys: %w", err)
			}
			sigdbx.AppendDatabase(oemSigDbx)

			// KEK
			oemSigKEK, err := certs.GetOEMCerts(oem, "KEK")
			if err != nil {
				return fmt.Errorf("could not enroll KEK keys: %w", err)
			}
			sigkek.AppendDatabase(oemSigKEK)

			// We are not enrolling PK keys from Microsoft
		case "custom":
			logging.Print("\nWith custom keys...")

			// db
			customSigDb, err := certs.GetCustomCerts(keydir, "db")
			if err != nil {
				return fmt.Errorf("could not enroll custom db keys: %w", err)
			}
			sigdb.AppendDatabase(customSigDb)

			// dbx
			customSigDbx, err := certs.GetCustomCerts(keydir, "dbx")
			if err != nil {
				return fmt.Errorf("could not enroll custom dbx keys: %w", err)
			}
			sigdbx.AppendDatabase(customSigDbx)

			// KEK
			customSigKEK, err := certs.GetCustomCerts(keydir, "KEK")
			if err != nil {
				return fmt.Errorf("could not enroll custom KEK keys: %w", err)
			}
			sigkek.AppendDatabase(customSigKEK)
		case "firmware-builtin":
			logging.Print("\nWith vendor certificates built into the firmware...")

			for _, cert := range enrollKeysCmdOptions.BuiltinFirmwareCerts {
				builtinSigDb, err := certs.GetBuiltinCertificates(cert)
				if err != nil {
					return fmt.Errorf("could not enroll built-in firmware keys: %w", err)
				}
				switch cert {
				case "db":
					sigdb.AppendDatabase(builtinSigDb)
				case "dbx":
					sigdbx.AppendDatabase(builtinSigDb)
				case "KEK":
					sigkek.AppendDatabase(builtinSigDb)
				case "PK":
					sigpk.AppendDatabase(builtinSigDb)
				}
			}
		}
	}

	if enrollKeysCmdOptions.Export.Value != "" {
		if enrollKeysCmdOptions.Export.Value == "auth" {
			logging.Print("\nExporting as auth files...")
			sigdb, err := sbctl.SignDatabase(sigdb, KEKKey, KEKPem, "db")
			if err != nil {
				return err
			}

			sigdbx, err := sbctl.SignDatabase(sigdbx, KEKKey, KEKPem, "dbx")
			if err != nil {
				return err
			}

			sigkek, err := sbctl.SignDatabase(sigkek, PKKey, PKPem, "KEK")
			if err != nil {
				return err
			}
			sigpk, err := sbctl.SignDatabase(sigpk, PKKey, PKPem, "PK")
			if err != nil {
				return err
			}
			if err := fs.WriteFile("db.auth", sigdb, 0o644); err != nil {
				return err
			}
			if err := fs.WriteFile("dbx.auth", sigdbx, 0o644); err != nil {
				return err
			}
			if err := fs.WriteFile("KEK.auth", sigkek, 0o644); err != nil {
				return err
			}
			if err := fs.WriteFile("PK.auth", sigpk, 0o644); err != nil {
				return err
			}
		} else if enrollKeysCmdOptions.Export.Value == "esl" {
			logging.Print("\nExporting as esl files...")
			if err := fs.WriteFile("db.esl", sigdb.Bytes(), 0o644); err != nil {
				return err
			}
			if err := fs.WriteFile("dbx.esl", sigdbx.Bytes(), 0o644); err != nil {
				return err
			}
			if err := fs.WriteFile("KEK.esl", sigkek.Bytes(), 0o644); err != nil {
				return err
			}
			if err := fs.WriteFile("PK.esl", sigpk.Bytes(), 0o644); err != nil {
				return err
			}
		}
		return nil
	}

	if enrollKeysCmdOptions.Partial.Value != "" {
		switch value := enrollKeysCmdOptions.Partial.Value; value {
		case "db":
			if err := sbctl.Enroll(sigdb, KEKKey, KEKPem, value); err != nil {
				return err
			}
		case "dbx":
			if err := sbctl.Enroll(sigdbx, KEKKey, KEKPem, value); err != nil {
				return err
			}
		case "KEK":
			if err := sbctl.Enroll(sigkek, PKKey, PKPem, value); err != nil {
				return err
			}
		case "PK":
			if err := sbctl.Enroll(sigpk, PKKey, PKPem, value); err != nil {
				return err
			}
		default:
			return fmt.Errorf("unsupported key type to enroll: %s, allowed values are: %s", value, enrollKeysCmdOptions.Partial.Type())
		}

		return nil
	}

	if err := sbctl.Enroll(sigdb, KEKKey, KEKPem, "db"); err != nil {
		return err
	}
	if err := sbctl.Enroll(sigdbx, KEKKey, KEKPem, "dbx"); err != nil {
		return err
	}
	if err := sbctl.Enroll(sigkek, PKKey, PKPem, "KEK"); err != nil {
		return err
	}
	if err := sbctl.Enroll(sigpk, PKKey, PKPem, "PK"); err != nil {
		return err
	}

	return nil
}

func RunEnrollKeys(cmd *cobra.Command, args []string) error {
	// SetupMode is not necessarily required on a partial enrollment
	if !efi.GetSetupMode() && enrollKeysCmdOptions.Partial.Value == "" {
		return ErrSetupModeDisabled
	}

	if enrollKeysCmdOptions.CustomBytes != "" {
		if enrollKeysCmdOptions.Partial.Value == "" {
			logging.NotOk("")

			return fmt.Errorf("missing hierarchy to enroll custom bytes to (use --partial)")

		}
		logging.Print("Enrolling custom bytes to EFI variables...")

		if err := customKey(enrollKeysCmdOptions.Partial.Value, enrollKeysCmdOptions.CustomBytes); err != nil {
			logging.NotOk("")

			return fmt.Errorf("couldn't roll out custom bytes from %s for hierarchy %s: %w", enrollKeysCmdOptions.CustomBytes, enrollKeysCmdOptions.Partial, err)
		}

		logging.Ok("\nEnrolled custom bytes to the EFI variables!")

		return nil
	}

	oems := []string{}
	if enrollKeysCmdOptions.MicrosoftKeys {
		oems = append(oems, "microsoft")
	}
	if enrollKeysCmdOptions.TPMEventlogChecksums {
		oems = append(oems, "tpm-eventlog")
	}
	if enrollKeysCmdOptions.Custom {
		oems = append(oems, "custom")
	}
	if len(enrollKeysCmdOptions.BuiltinFirmwareCerts) >= 1 {
		oems = append(oems, "firmware-builtin")
	}
	if !enrollKeysCmdOptions.IgnoreImmutable {
		if err := sbctl.CheckImmutable(); err != nil {
			return err
		}
	}
	if !enrollKeysCmdOptions.Force && !enrollKeysCmdOptions.TPMEventlogChecksums && !enrollKeysCmdOptions.MicrosoftKeys {
		if err := sbctl.CheckEventlogOprom(systemEventlog); err != nil {
			return err
		}
	}
	uuid, err := sbctl.GetGUID()
	if err != nil {
		return err
	}
	guid := util.StringToGUID(uuid.String())
	if enrollKeysCmdOptions.Export.Value != "" {
		logging.Print("Exporting keys to EFI files...")
	} else {
		logging.Print("Enrolling keys to EFI variables...")
	}
	if err := KeySync(*guid, sbctl.KeysPath, oems); err != nil {
		logging.NotOk("")
		return fmt.Errorf("couldn't sync keys: %w", err)
	}
	if enrollKeysCmdOptions.Export.Value != "" {
		logging.Ok("\nExported files!")
	} else {
		logging.Ok("\nEnrolled keys to the EFI variables!")
	}
	return nil
}

// write custom key from a filePath into an efivar
func customKey(hierarchy string, filePath string) error {
	customBytes, err := fs.ReadFile(filePath)
	if err != nil {
		return err
	}

	switch hierarchy {
	case "db":
		fallthrough
	case "dbx":
		fallthrough
	case "KEK":
		fallthrough
	case "PK":
		if err := sbctl.EnrollCustom(customBytes, hierarchy); err != nil {
			return err
		}
	default:
		return fmt.Errorf("unsupported key type to enroll: %s, allowed values are: %s", hierarchy, enrollKeysCmdOptions.Partial.Type())
	}

	return nil
}

func vendorFlags(cmd *cobra.Command) {
	f := cmd.Flags()
	f.BoolVarP(&enrollKeysCmdOptions.MicrosoftKeys, "microsoft", "m", false, "include microsoft keys into key enrollment")
	f.BoolVarP(&enrollKeysCmdOptions.TPMEventlogChecksums, "tpm-eventlog", "t", false, "include TPM eventlog checksums into the db database")
	f.BoolVarP(&enrollKeysCmdOptions.Custom, "custom", "c", false, "include custom db and KEK")
	// f.BoolVarP(&enrollKeysCmdOptions.BuiltinFirmwareCerts, "firmware-builtin", "f", false, "include keys indicated by the firmware as being part of the default database")
	l := f.VarPF(&enrollKeysCmdOptions.BuiltinFirmwareCerts, "firmware-builtin", "f", "include keys indicated by the firmware as being part of the default database")
	l.NoOptDefVal = "db,KEK"
}

func enrollKeysCmdFlags(cmd *cobra.Command) {
	f := cmd.Flags()
	f.BoolVarP(&enrollKeysCmdOptions.Force, "yes-this-might-brick-my-machine", "", false, "ignore any errors and enroll keys")
	f.BoolVarP(&enrollKeysCmdOptions.Force, "yolo", "", false, "yolo")
	f.MarkHidden("yolo")
	f.BoolVarP(&enrollKeysCmdOptions.IgnoreImmutable, "ignore-immutable", "i", false, "ignore checking for immutable efivarfs files")
	f.VarPF(&enrollKeysCmdOptions.Export, "export", "", "export the EFI database values to current directory instead of enrolling")
	f.VarPF(&enrollKeysCmdOptions.Partial, "partial", "p", "enroll a partial set of keys")
	f.StringVarP(&enrollKeysCmdOptions.CustomBytes, "custom-bytes", "", "", "path to the bytefile to be enrolled to efivar")
	f.BoolVarP(&enrollKeysCmdOptions.Append, "append", "a", false, "append the key to the existing ones")
}

func init() {
	enrollKeysCmdFlags(enrollKeysCmd)
	vendorFlags(enrollKeysCmd)
	CliCommands = append(CliCommands, cliCommand{
		Cmd: enrollKeysCmd,
	})
}
