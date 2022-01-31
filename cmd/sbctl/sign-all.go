package main

import (
	"errors"
	"fmt"

	"github.com/foxboron/sbctl"
	"github.com/foxboron/sbctl/logging"
	"github.com/spf13/cobra"
)

var (
	generate bool
)

var signAllCmd = &cobra.Command{
	Use:   "sign-all",
	Short: "Sign all enrolled files with secure boot keys",
	RunE: func(cmd *cobra.Command, args []string) error {
		if generate {
			sign = true
			if err := generateBundlesCmd.RunE(cmd, args); err != nil {
				logging.Error(err)
			}
		}

		files, err := sbctl.ReadFileDatabase(sbctl.DBPath)
		if err != nil {
			return err
		}
		for _, entry := range files {

			err := sbctl.SignFile(sbctl.DBKey, sbctl.DBCert, entry.File, entry.OutputFile, entry.Checksum)
			if errors.Is(err, sbctl.ErrAlreadySigned) {
				logging.Print("File has already been signed %s\n", entry.OutputFile)
			} else if err != nil {
				return fmt.Errorf("failed signing %s: %w", entry.File, err)
			} else {
				logging.Ok("Signed %s", entry.OutputFile)
			}

			// Update checksum after we signed it
			checksum, err := sbctl.ChecksumFile(entry.File)
			if err != nil {
				return err
			}
			entry.Checksum = checksum
			files[entry.File] = entry
			if err := sbctl.WriteFileDatabase(sbctl.DBPath, files); err != nil {
				return err
			}

		}
		return nil
	},
}

func signAllCmdFlags(cmd *cobra.Command) {
	f := cmd.Flags()
	f.BoolVarP(&generate, "generate", "g", false, "run all generate-* sub-commands before signing")
}

func init() {
	signAllCmdFlags(signAllCmd)
	CliCommands = append(CliCommands, cliCommand{
		Cmd: signAllCmd,
	})
}
