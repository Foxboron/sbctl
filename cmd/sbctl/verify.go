package main

import (
	"errors"
	"os"
	"path/filepath"

	"github.com/foxboron/sbctl"
	"github.com/foxboron/sbctl/logging"
	"github.com/spf13/cobra"
)

var verifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Find and check if files in the ESP are signed or not",
	RunE: func(cmd *cobra.Command, args []string) error {
		// Exit early if we can't verify files
		if err := sbctl.CanVerifyFiles(); err != nil {
			return err
		}
		espPath, err := sbctl.GetESP()
		if err != nil {
			return err
		}
		logging.Print("Verifying file database and EFI images in %s...\n", espPath)
		if err := sbctl.SigningEntryIter(func(file *sbctl.SigningEntry) error {
			sbctl.AddChecked(file.OutputFile)
			// Check output file exists before checking if it's signed
			if _, err := os.Open(file.OutputFile); errors.Is(err, os.ErrNotExist) {
				logging.Warn("%s does not exist", file.OutputFile)
				return nil
			} else if errors.Is(err, os.ErrPermission) {
				logging.Warn("%s permission denied. Can't read file\n", file.OutputFile)
				return nil
			}
			ok, err := sbctl.VerifyFile(sbctl.DBCert, file.OutputFile)
			if err != nil {
				return err
			}
			if ok {
				logging.Ok("%s is signed", file.OutputFile)
			} else {
				logging.NotOk("%s is not signed", file.OutputFile)
			}
			return nil
		}); err != nil {
			return err
		}

		if err := filepath.Walk(espPath, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if fi, _ := os.Stat(path); fi.IsDir() {
				return nil
			}

			if sbctl.InChecked(path) {
				return nil
			}

			ok, err := sbctl.CheckMSDos(path)
			if err != nil {
				return err
			}
			if !ok {
				return nil
			}
			ok, err = sbctl.VerifyFile(sbctl.DBCert, path)
			if err != nil {
				return err
			}
			if ok {
				logging.Ok("%s is signed", path)
			} else {
				logging.NotOk("%s is not signed", path)
			}
			return nil
		}); err != nil {
			return err
		}
		return nil
	},
}

func init() {
	CliCommands = append(CliCommands, cliCommand{
		Cmd: verifyCmd,
	})
}
