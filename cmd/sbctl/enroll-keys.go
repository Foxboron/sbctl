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
	"github.com/spf13/cobra"
	"golang.org/x/exp/slices"
)

type StringSet struct {
	Allowed []string
	Value   string
}

func NewStringSet(allowed []string, d string) *StringSet {
	return &StringSet{
		Allowed: allowed,
		Value:   d,
	}
}

func (s StringSet) String() string {
	return s.Value
}

func (s *StringSet) Set(p string) error {
	if !slices.Contains(s.Allowed, p) {
		return fmt.Errorf("%s is not included in %s", p, strings.Join(s.Allowed, ","))
	}
	s.Value = p
	return nil
}

func (s *StringSet) Type() string {
	return "[auth, esl]"
}

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
	MicrosoftKeys        bool
	IgnoreImmutable      bool
	Force                bool
	TPMEventlogChecksums bool
	Custom               bool
	BuiltinFirmwareCerts FirmwareBuiltinFlags
	Export               StringSet
}

var (
	systemEventlog       = "/sys/kernel/security/tpm0/binary_bios_measurements"
	enrollKeysCmdOptions = EnrollKeysCmdOptions{
		Export: StringSet{Allowed: []string{"esl", "auth"}},
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

	// Create the signature databases
	sigdb := signature.NewSignatureDatabase()
	if err = sigdb.Append(signature.CERT_X509_GUID, guid, dbPem); err != nil {
		return err
	}

	sigkek := signature.NewSignatureDatabase()
	if err = sigkek.Append(signature.CERT_X509_GUID, guid, KEKPem); err != nil {
		return err
	}

	sigpk := signature.NewSignatureDatabase()
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
			sigkek, err := sbctl.SignDatabase(sigkek, PKKey, PKPem, "KEK")
			if err != nil {
				return err
			}
			sigpk, err := sbctl.SignDatabase(sigpk, PKKey, PKPem, "PK")
			if err != nil {
				return err
			}
			if err := fs.WriteFile("db.auth", sigdb, 0644); err != nil {
				return err
			}
			if err := fs.WriteFile("KEK.auth", sigkek, 0644); err != nil {
				return err
			}
			if err := fs.WriteFile("PK.auth", sigpk, 0644); err != nil {
				return err
			}
		} else if enrollKeysCmdOptions.Export.Value == "esl" {
			logging.Print("\nExporting as esl files...")
			if err := fs.WriteFile("db.esl", sigdb.Bytes(), 0644); err != nil {
				return err
			}
			if err := fs.WriteFile("KEK.esl", sigkek.Bytes(), 0644); err != nil {
				return err
			}
			if err := fs.WriteFile("PK.esl", sigpk.Bytes(), 0644); err != nil {
				return err
			}
		}
		return nil
	}
	if err := sbctl.Enroll(sigdb, KEKKey, KEKPem, "db"); err != nil {
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

	if !efi.GetSetupMode() {
		return ErrSetupModeDisabled
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
}

func init() {
	enrollKeysCmdFlags(enrollKeysCmd)
	vendorFlags(enrollKeysCmd)
	CliCommands = append(CliCommands, cliCommand{
		Cmd: enrollKeysCmd,
	})
}
