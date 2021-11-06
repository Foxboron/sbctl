package main

import (
	"errors"
	"fmt"

	"github.com/foxboron/go-uefi/efi/util"
	"github.com/foxboron/sbctl"
	"github.com/foxboron/sbctl/logging"
	"github.com/spf13/cobra"
)

type EnrollKeysCmdOptions struct {
	MicrosoftKeys bool
}

var (
	enrollKeysCmdOptions = EnrollKeysCmdOptions{}
	enrollKeysCmd        = &cobra.Command{
		Use:   "enroll-keys",
		Short: "Enroll the current keys to EFI",
		RunE:  RunEnrollKeys,
	}
)

func RunEnrollKeys(cmd *cobra.Command, args []string) error {
	var oems []string
	if enrollKeysCmdOptions.MicrosoftKeys {
		oems = append(oems, "microsoft")
	}
	if err := CheckImmutable(); err != nil {
		return err
	}
	uuid, err := sbctl.GetGUID()
	if err != nil {
		return err
	}
	guid := util.StringToGUID(uuid.String())
	logging.Print("Enrolling keys to EFI variables...")
	if err := sbctl.KeySync(*guid, sbctl.KeysPath, oems); err != nil {
		logging.NotOk("")
		return fmt.Errorf("couldn't sync keys: %w", err)
	}
	logging.Ok("\nEnrolled keys to the EFI variables!")
	return nil
}

func CheckImmutable() error {
	var isImmutable bool
	for _, file := range sbctl.EfivarFSFiles {
		err := sbctl.IsImmutable(file)
		if errors.Is(err, sbctl.ErrImmutable) {
			isImmutable = true
			logging.Warn("File is immutable: %s", file)
		} else if errors.Is(err, sbctl.ErrNotImmutable) {
			continue
		} else if err != nil {
			return fmt.Errorf("couldn't read file: %s", file)
		}
	}
	if isImmutable {
		return sbctl.ErrImmutable
	}
	return nil
}

func enrollKeysCmdFlags(cmd *cobra.Command) {
	f := cmd.Flags()
	f.BoolVarP(&enrollKeysCmdOptions.MicrosoftKeys, "microsoft", "m", false, "include microsoft keys into key enrollment")
}

func init() {
	enrollKeysCmdFlags(enrollKeysCmd)
	CliCommands = append(CliCommands, cliCommand{
		Cmd: enrollKeysCmd,
	})
}
