package main

import (
	"errors"
	"fmt"
	"path/filepath"
	"syscall"

	"github.com/foxboron/go-uefi/efi"
	"github.com/foxboron/go-uefi/efi/util"
	"github.com/foxboron/sbctl"
	"github.com/foxboron/sbctl/logging"
	"github.com/foxboron/sbctl/stringset"
	"github.com/spf13/cobra"
)

type resetCmdOptions struct {
	Partial stringset.StringSet
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

func resetKeys() error {
	if resetCmdOpts.Partial.Value == "" {
		if err := resetPK(); err != nil {
			return fmt.Errorf("could not reset PK: %v", err)
		}

		return nil
	}

	switch partial := resetCmdOpts.Partial.Value; partial {
	case "db":
		if err := resetDB(); err != nil {
			return err
		}
	case "KEK":
		if err := resetKEK(); err != nil {
			return err
		}
	case "PK":
		if err := resetPK(); err != nil {
			return err
		}
	default:
		return fmt.Errorf("unsupported type to reset: %s, allowed values are: %s", partial, enrollKeysCmdOptions.Partial.Type())
	}

	return nil
}

func resetDB() error {
	KEKKey := filepath.Join(sbctl.KeysPath, "KEK", "KEK.key")
	KEKPem := filepath.Join(sbctl.KeysPath, "KEK", "KEK.pem")

	if err := resetDatabase(KEKKey, KEKPem, "db"); err != nil {
		return err
	}

	logging.Ok("Removed Signature Database!")
	logging.Println("Use `sbctl enroll-keys` to enroll the Signature Database again.")
	return nil
}

func resetKEK() error {
	PKKey := filepath.Join(sbctl.KeysPath, "PK", "PK.key")
	PKPem := filepath.Join(sbctl.KeysPath, "PK", "PK.pem")

	if err := resetDatabase(PKKey, PKPem, "KEK"); err != nil {
		return err
	}

	logging.Ok("Removed Key Exchange Keys!")
	logging.Println("Use `sbctl enroll-keys` to enroll a Key Exchange Key again.")
	return nil
}

func resetPK() error {
	PKKey := filepath.Join(sbctl.KeysPath, "PK", "PK.key")
	PKPem := filepath.Join(sbctl.KeysPath, "PK", "PK.pem")

	if err := resetDatabase(PKKey, PKPem, "PK"); err != nil {
		return err
	}

	logging.Ok("Removed Platform Key!")
	logging.Println("Use `sbctl enroll-keys` to enroll the Platform Key again.")
	return nil
}

func resetDatabase(signerKey, signerPem string, efivar string) error {
	key, err := util.ReadKeyFromFile(signerKey)
	if err != nil {
		return err
	}

	crt, err := util.ReadCertFromFile(signerPem)
	if err != nil {
		return err
	}

	signedBuf, err := efi.SignEFIVariable(key, crt, efivar, []byte{})
	if err != nil {
		return err
	}

	if err := efi.WriteEFIVariable(efivar, signedBuf); err != nil {
		if errors.Is(err, syscall.EIO) {
			return fmt.Errorf("%s already reset or not enrolled", efivar)
		}
		return err
	}

	return nil
}

func RunReset(cmd *cobra.Command, args []string) error {
	if err := resetKeys(); err != nil {
		return err
	}
	return nil
}

func resetKeysCmdFlags(cmd *cobra.Command) {
	f := cmd.Flags()
	f.VarPF(&resetCmdOpts.Partial, "partial", "p", "reset a partial set of keys")
}

func init() {
	resetKeysCmdFlags(resetCmd)
	CliCommands = append(CliCommands, cliCommand{
		Cmd: resetCmd,
	})
}
