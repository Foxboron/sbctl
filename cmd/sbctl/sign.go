package main

import (
	"os"
	"path/filepath"

	"github.com/foxboron/sbctl"
	"github.com/foxboron/sbctl/logging"
	"github.com/spf13/cobra"
)

var (
	save   bool
	output string
)

var signCmd = &cobra.Command{
	Use:   "sign",
	Short: "Sign a file with secure boot keys",
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) < 1 {
			logging.Print("Requires a file to sign\n")
			os.Exit(1)
		}

		// Ensure we have absolute paths
		file, err := filepath.Abs(args[0])
		if err != nil {
			return err
		}
		if output == "" {
			output = file
		} else {
			output, err = filepath.Abs(output)
			if err != nil {
				return err
			}
		}

		if err := sbctl.Sign(file, output, save); err != nil {
			return err
		}
		return nil
	},
}

func signCmdFlags(cmd *cobra.Command) {
	f := cmd.Flags()
	f.BoolVarP(&save, "save", "s", false, "save file to the database")
	f.StringVarP(&output, "output", "o", "", "output filename. Default replaces the file")
}

func init() {
	signCmdFlags(signCmd)
	CliCommands = append(CliCommands, cliCommand{
		Cmd: signCmd,
	})
}
