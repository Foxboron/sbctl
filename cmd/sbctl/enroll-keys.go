package main

import (
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"

	"github.com/foxboron/go-uefi/efi/signature"
	"github.com/foxboron/go-uefi/efivar"
	"github.com/foxboron/sbctl"
	"github.com/foxboron/sbctl/backend"
	"github.com/foxboron/sbctl/certs"
	"github.com/foxboron/sbctl/config"
	"github.com/foxboron/sbctl/fs"
	"github.com/foxboron/sbctl/logging"
	"github.com/foxboron/sbctl/lsm"
	"github.com/foxboron/sbctl/stringset"
	"github.com/landlock-lsm/go-landlock/landlock"
	"github.com/spf13/afero"
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
		Partial: stringset.StringSet{Allowed: []string{"PK", "KEK", "db"}},
		Export:  stringset.StringSet{Allowed: []string{"esl", "auth"}},
	}
	enrollKeysCmd = &cobra.Command{
		Use:   "enroll-keys",
		Short: "Enroll the current keys to EFI",
		RunE: func(cmd *cobra.Command, args []string) error {
			state := cmd.Context().Value(stateDataKey{}).(*config.State)
			if state.Config.Landlock {
				if enrollKeysCmdOptions.Export.Value != "" {
					wd, err := os.Getwd()
					if err != nil {
						return err
					}
					lsm.RestrictAdditionalPaths(
						landlock.RWDirs(wd),
					)
				}
				if err := lsm.Restrict(); err != nil {
					return err
				}
			}
			return RunEnrollKeys(state)
		},
	}
	ErrSetupModeDisabled = errors.New("setup mode is disabled")
)

func SignSiglist(k *backend.KeyHierarchy, e efivar.Efivar, sigdb efivar.Marshallable) ([]byte, error) {
	signer := k.GetKeyBackend(e)
	_, em, err := signature.SignEFIVariable(e, sigdb, signer.Signer(), signer.Certificate())
	if err != nil {
		return nil, err
	}
	return em.Bytes(), nil
}

// Sync keys from a key directory into efivarfs
func KeySync(state *config.State, oems []string) error {
	kh, err := backend.GetKeyHierarchy(state.Fs, state)
	if err != nil {
		return err
	}

	guid, err := state.Config.GetGUID(state.Fs)
	if err != nil {
		return err
	}

	var efistate *sbctl.EFIVariables

	if !enrollKeysCmdOptions.Append {
		efistate = sbctl.NewEFIVariables(state.Efivarfs)
	} else {
		efistate, err = sbctl.SystemEFIVariables(state.Efivarfs)
		if err != nil {
			return fmt.Errorf("can't read efivariables: %v", err)
		}
	}

	if err = efistate.Db.Append(signature.CERT_X509_GUID, *guid, kh.Db.CertificateBytes()); err != nil {
		return err
	}

	if err = efistate.KEK.Append(signature.CERT_X509_GUID, *guid, kh.KEK.CertificateBytes()); err != nil {
		return err
	}

	if err = efistate.PK.Append(signature.CERT_X509_GUID, *guid, kh.PK.CertificateBytes()); err != nil {
		return err
	}

	// If we want OEM certs, we do that here
	for _, oem := range oems {
		switch oem {
		case "tpm-eventlog":
			logging.Print("\nWith checksums from the TPM Eventlog...")
			eventlogDB, err := sbctl.GetEventlogChecksums(state.Fs, systemEventlog)
			if err != nil {
				return fmt.Errorf("could not enroll db keys: %w", err)
			}
			if len((*eventlogDB)) == 0 {
				return fmt.Errorf("could not find any OpROM entries in the TPM eventlog")
			}
			efistate.Db.AppendDatabase(eventlogDB)
		case "microsoft":
			logging.Print("\nWith vendor keys from microsoft...")

			// db
			oemSigDb, err := certs.GetOEMCerts(oem, "db")
			if err != nil {
				return fmt.Errorf("could not enroll db keys: %w", err)
			}
			efistate.Db.AppendDatabase(oemSigDb)

			// KEK
			oemSigKEK, err := certs.GetOEMCerts(oem, "KEK")
			if err != nil {
				return fmt.Errorf("could not enroll KEK keys: %w", err)
			}
			efistate.KEK.AppendDatabase(oemSigKEK)

			// We are not enrolling PK keys from Microsoft
		case "custom":
			logging.Print("\nWith custom keys...")

			// db
			customSigDb, err := certs.GetCustomCerts(state.Config.Keydir, "db")
			if err != nil {
				return fmt.Errorf("could not enroll custom db keys: %w", err)
			}
			efistate.Db.AppendDatabase(customSigDb)

			// KEK
			customSigKEK, err := certs.GetCustomCerts(state.Config.Keydir, "KEK")
			if err != nil {
				return fmt.Errorf("could not enroll custom KEK keys: %w", err)
			}
			efistate.KEK.AppendDatabase(customSigKEK)
		case "firmware-builtin":
			logging.Print("\nWith vendor certificates built into the firmware...")

			for _, cert := range enrollKeysCmdOptions.BuiltinFirmwareCerts {
				builtinSigDb, err := certs.GetBuiltinCertificates(cert)
				if err != nil {
					return fmt.Errorf("could not enroll built-in firmware keys: %w", err)
				}
				switch cert {
				case "db":
					efistate.Db.AppendDatabase(builtinSigDb)
				case "KEK":
					efistate.KEK.AppendDatabase(builtinSigDb)
				case "PK":
					efistate.PK.AppendDatabase(builtinSigDb)
				}
			}
		}
	}

	if enrollKeysCmdOptions.Export.Value != "" {
		if enrollKeysCmdOptions.Export.Value == "auth" {
			logging.Print("\nExporting as auth files...")
			sigdb, err := SignSiglist(kh, efivar.Db, efistate.Db)
			if err != nil {
				return err
			}

			sigkek, err := SignSiglist(kh, efivar.KEK, efistate.KEK)
			if err != nil {
				return err
			}
			sigpk, err := SignSiglist(kh, efivar.PK, efistate.PK)
			if err != nil {
				return err
			}
			if err := fs.WriteFile(state.Fs, "db.auth", sigdb, 0o644); err != nil {
				return err
			}
			if err := fs.WriteFile(state.Fs, "KEK.auth", sigkek, 0o644); err != nil {
				return err
			}
			if err := fs.WriteFile(state.Fs, "PK.auth", sigpk, 0o644); err != nil {
				return err
			}
		} else if enrollKeysCmdOptions.Export.Value == "esl" {
			logging.Print("\nExporting as esl files...")
			if err := fs.WriteFile(state.Fs, "db.esl", efistate.Db.Bytes(), 0o644); err != nil {
				return err
			}
			if err := fs.WriteFile(state.Fs, "KEK.esl", efistate.KEK.Bytes(), 0o644); err != nil {
				return err
			}
			if err := fs.WriteFile(state.Fs, "PK.esl", efistate.PK.Bytes(), 0o644); err != nil {
				return err
			}
		}
		return nil
	}

	if enrollKeysCmdOptions.Partial.Value != "" {
		switch value := enrollKeysCmdOptions.Partial.Value; value {
		case "db":
			if err := efistate.EnrollKey(efivar.Db, kh); err != nil {
				return err
			}
		case "KEK":
			if err := efistate.EnrollKey(efivar.KEK, kh); err != nil {
				return err
			}
		case "PK":
			if err := efistate.EnrollKey(efivar.PK, kh); err != nil {
				return err
			}
		default:
			return fmt.Errorf("unsupported key type to enroll: %s, allowed values are: %s", value, enrollKeysCmdOptions.Partial.Type())
		}

		return nil
	}

	if err := efistate.EnrollAllKeys(kh); err != nil {
		return err
	}

	return nil
}

func RunEnrollKeys(state *config.State) error {
	ok, err := state.Efivarfs.GetSetupMode()
	// EFI variables are missing in some CI / build environments and setup mode is not needed for exporting keys
	if err != nil && enrollKeysCmdOptions.Export.Value == "" {
		return err
	}
	// SetupMode is not necessarily required for a partial enrollment and not needed for exporting keys
	if !ok && enrollKeysCmdOptions.Partial.Value == "" && enrollKeysCmdOptions.Export.Value == "" {
		return ErrSetupModeDisabled
	}

	if enrollKeysCmdOptions.CustomBytes != "" {
		if enrollKeysCmdOptions.Partial.Value == "" {
			logging.NotOk("")

			return fmt.Errorf("missing hierarchy to enroll custom bytes to (use --partial)")

		}
		logging.Print("Enrolling custom bytes to EFI variables...")

		if err := customKey(state.Fs, enrollKeysCmdOptions.Partial.Value, enrollKeysCmdOptions.CustomBytes); err != nil {
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

	if len(state.Config.DbAdditions) != 0 {
		for _, k := range state.Config.DbAdditions {
			if !slices.Contains(oems, k) {
				oems = append(oems, k)
			}
		}
	}

	if !enrollKeysCmdOptions.IgnoreImmutable && enrollKeysCmdOptions.Export.Value == "" {
		if err := sbctl.CheckImmutable(state.Fs); err != nil {
			return err
		}
	}
	if !enrollKeysCmdOptions.Force && !enrollKeysCmdOptions.TPMEventlogChecksums && !enrollKeysCmdOptions.MicrosoftKeys && !enrollKeysCmdOptions.Append {
		if err := sbctl.CheckEventlogOprom(state.Fs, systemEventlog); err != nil {
			return err
		}
	}

	if enrollKeysCmdOptions.Export.Value != "" {
		logging.Print("Exporting keys to EFI files...")
	} else {
		logging.Print("Enrolling keys to EFI variables...")
	}
	if err := KeySync(state, oems); err != nil {
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
func customKey(vfs afero.Fs, hierarchy string, filePath string) error {
	customBytes, err := fs.ReadFile(vfs, filePath)
	if err != nil {
		return err
	}

	switch hierarchy {
	case "db":
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
