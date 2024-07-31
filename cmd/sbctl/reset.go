package main

import (
	"fmt"
	"strings"

	"github.com/foxboron/go-uefi/efi/signature"
	"github.com/foxboron/go-uefi/efi/util"
	"github.com/foxboron/go-uefi/efivar"
	"github.com/foxboron/sbctl"
	"github.com/foxboron/sbctl/backend"
	"github.com/foxboron/sbctl/config"
	"github.com/foxboron/sbctl/fs"
	"github.com/foxboron/sbctl/logging"
	"github.com/foxboron/sbctl/lsm"
	"github.com/foxboron/sbctl/stringset"
	"github.com/spf13/cobra"
)

type resetCmdOptions struct {
	Partial   stringset.StringSet
	CertFiles string
}

var (
	resetCmdOpts = resetCmdOptions{
		Partial: stringset.StringSet{Allowed: []string{"PK", "KEK", "db"}},
	}
	resetCmd = &cobra.Command{
		Use:   "reset",
		Short: "Reset Secure Boot Keys",
		RunE:  RunReset,
	}
)

func resetKeys(state *config.State) error {
	if resetCmdOpts.Partial.Value == "" {
		if err := resetPK(state); err != nil {
			return fmt.Errorf("could not reset PK: %v", err)
		}

		return nil
	}

	var paths []string

	if resetCmdOpts.CertFiles != "" {
		paths = strings.Split(resetCmdOpts.CertFiles, ";")
	}

	switch partial := resetCmdOpts.Partial.Value; partial {
	case "db":
		if err := resetDB(state, paths...); err != nil {
			return err
		}
	case "KEK":
		if err := resetKEK(state, paths...); err != nil {
			return err
		}
	case "PK":
		if err := resetPK(state, paths...); err != nil {
			return err
		}
	default:
		return fmt.Errorf("unsupported type to reset: %s, allowed values are: %s", partial, enrollKeysCmdOptions.Partial.Type())
	}

	return nil
}

func resetDB(state *config.State, certPaths ...string) error {
	if err := resetDatabase(state, efivar.Db, certPaths...); err != nil {
		return err
	}

	logging.Ok("Removed Signature Database!")
	logging.Println("Use `sbctl enroll-keys` to enroll the Signature Database again.")
	return nil
}

func resetKEK(state *config.State, certPaths ...string) error {
	if err := resetDatabase(state, efivar.KEK, certPaths...); err != nil {
		return err
	}

	logging.Ok("Removed Key Exchange Keys!")
	logging.Println("Use `sbctl enroll-keys` to enroll a Key Exchange Key again.")
	return nil
}

func resetPK(state *config.State, certPaths ...string) error {
	if err := resetDatabase(state, efivar.PK, certPaths...); err != nil {
		return err
	}

	logging.Ok("Removed Platform Key!")
	logging.Println("Use `sbctl enroll-keys` to enroll the Platform Key again.")
	return nil
}

func resetDatabase(state *config.State, ev efivar.Efivar, certPaths ...string) error {
	efistate, err := sbctl.SystemEFIVariables(state.Efivarfs)
	if err != nil {
		return err
	}

	db := signature.NewSignatureDatabase()

	if len(certPaths) != 0 {
		var (
			err error
		)

		db = efistate.GetSiglist(ev)

		guid, err := state.Config.GetGUID(state.Fs)
		if err != nil {
			return err
		}

		for _, certPath := range certPaths {
			buf, err := fs.ReadFile(state.Fs, certPath)
			if err != nil {
				return fmt.Errorf("can't read new certificate from path %s: %v", certPath, err)
			}

			cert, err := util.ReadCert(buf)
			if err != nil {
				return err
			}
			if err := db.Remove(signature.CERT_X509_GUID, *guid, cert.Raw); err != nil {
				return err
			}

		}
	}

	kh, err := backend.GetKeyHierarchy(state.Fs, state)
	if err != nil {
		return err
	}

	switch ev {
	case efivar.PK:
		efistate.PK = db
	case efivar.KEK:
		efistate.KEK = db
	case efivar.Db:
		efistate.Db = db
	}

	if err := efistate.EnrollKey(ev, kh); err != nil {
		return err
	}

	return nil
}

func RunReset(cmd *cobra.Command, args []string) error {
	state := cmd.Context().Value(stateDataKey{}).(*config.State)
	if state.Config.Landlock {
		if err := lsm.Restrict(); err != nil {
			return err
		}
	}
	if err := resetKeys(state); err != nil {
		return err
	}
	return nil
}

func resetKeysCmdFlags(cmd *cobra.Command) {
	f := cmd.Flags()
	f.VarPF(&resetCmdOpts.Partial, "partial", "p", "reset a partial set of keys")
	f.StringVarP(&resetCmdOpts.CertFiles, "cert-files", "c", "", "optional paths to certificate file to remove from the hierachy (seperate individual paths by ';')")
}

func init() {
	resetKeysCmdFlags(resetCmd)
	CliCommands = append(CliCommands, cliCommand{
		Cmd: resetCmd,
	})
}
