package main

import (
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
			if err := sbctl.GenerateAllBundles(true); err != nil {
				logging.Fatal(err)
			}
		}

		files, err := sbctl.ReadFileDatabase(sbctl.DBPath)
		if err != nil {
			return err
		}
		for _, entry := range files {

			if err := sbctl.SignFile(sbctl.DBKey, sbctl.DBCert, entry.File, entry.OutputFile, entry.Checksum); err != nil {
				logging.Fatal(err)
				continue
			}

			// Update checksum after we signed it
			checksum := sbctl.ChecksumFile(entry.File)
			entry.Checksum = checksum
			files[entry.File] = entry
			sbctl.WriteFileDatabase(sbctl.DBPath, files)

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
