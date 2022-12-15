package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/foxboron/sbctl"
	"github.com/foxboron/sbctl/logging"
	"github.com/spf13/cobra"
)

var (
	ErrInvalidHeader = errors.New("invalid pe header")
	verifyCmd        = &cobra.Command{
		Use:   "verify",
		Short: "Find and check if files in the ESP are signed or not",
		RunE:  RunVerify,
	}
)

func VerifyOneFile(f string) error {
	o, err := os.Open(f)
	if errors.Is(err, os.ErrNotExist) {
		logging.Warn("%s does not exist", f)
		return nil
	} else if errors.Is(err, os.ErrPermission) {
		logging.Warn("%s permission denied. Can't read file\n", f)
		return nil
	}
	defer o.Close()
	ok, err := sbctl.CheckMSDos(o)
	if err != nil {
		logging.Error(fmt.Errorf("failed to read file %s: %s", f, err))
	}
	if !ok {
		return ErrInvalidHeader
	}
	ok, err = sbctl.VerifyFile(sbctl.DBCert, f)
	if err != nil {
		return err
	}
	if ok {
		logging.Ok("%s is signed", f)
	} else {
		logging.NotOk("%s is not signed", f)
	}
	return nil
}

func RunVerify(cmd *cobra.Command, args []string) error {
	// Exit early if we can't verify files
	if err := sbctl.CanVerifyFiles(); err != nil {
		return err
	}
	espPath, err := sbctl.GetESP()
	if err != nil {
		return err
	}
	if len(args) > 0 {
		for _, file := range args {
			if err := VerifyOneFile(file); err != nil {
				if errors.Is(ErrInvalidHeader, err) {
					logging.Error(fmt.Errorf("%s is not a valid EFI binary", file))
					return nil
				}
				return err
			}
		}
		return nil
	}
	logging.Print("Verifying file database and EFI images in %s...\n", espPath)
	if err := sbctl.SigningEntryIter(func(file *sbctl.SigningEntry) error {
		sbctl.AddChecked(file.OutputFile)
		if err := VerifyOneFile(file.OutputFile); err != nil {
			return err
		}
		return nil
	}); err != nil {
		return err
	}

	if err := filepath.Walk(espPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			logging.Error(fmt.Errorf("failed to read path %s: %s", path, err))
		}
		if fi, _ := os.Stat(path); fi.IsDir() {
			return nil
		}
		if sbctl.InChecked(path) {
			return nil
		}
		if err = VerifyOneFile(path); err != nil {
			// We are scanning the ESP, so ignore invalid files
			if errors.Is(ErrInvalidHeader, err) {
				return nil
			}
			logging.Error(fmt.Errorf("failed to verify file %s: %s", path, err))
		}
		return nil
	}); err != nil {
		return err
	}
	return nil
}

func init() {
	CliCommands = append(CliCommands, cliCommand{
		Cmd: verifyCmd,
	})
}
