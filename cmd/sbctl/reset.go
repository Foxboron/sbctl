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
	"github.com/spf13/cobra"
)

var resetCmd = &cobra.Command{
	Use:   "reset",
	Short: "Reset Platform Key (PK)",
	RunE:  RunReset,
}

func RunReset(cmd *cobra.Command, args []string) error {
	PKKey := filepath.Join(sbctl.KeysPath, "PK", "PK.key")
	PKPem := filepath.Join(sbctl.KeysPath, "PK", "PK.pem")
	key, err := util.ReadKeyFromFile(PKKey)
	if err != nil {
		return err
	}
	crt, err := util.ReadCertFromFile(PKPem)
	if err != nil {
		return err
	}
	signedBuf, err := efi.SignEFIVariable(key, crt, "PK", []byte{})
	if err != nil {
		return err
	}
	if err := efi.WriteEFIVariable("PK", signedBuf); err != nil {
		if errors.Is(err, syscall.EIO) {
			return fmt.Errorf("platform key already reset or not enrolled")
		}
		return err
	}

	logging.Ok("Removed Platform Key!")
	logging.Println("Use `sbctl enroll-keys` to enroll the Platform Key again.")
	return nil
}

func init() {
	CliCommands = append(CliCommands, cliCommand{
		Cmd: resetCmd,
	})
}
