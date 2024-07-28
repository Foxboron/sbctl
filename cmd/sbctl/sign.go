package main

import (
	"errors"
	"os"
	"path/filepath"

	"github.com/foxboron/sbctl"
	"github.com/foxboron/sbctl/backend"
	"github.com/foxboron/sbctl/config"
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

		state := cmd.Context().Value(stateDataKey{}).(*config.State)

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

		kh, err := backend.GetKeyHierarchy(state.Fs, state.Config)
		if err != nil {
			return err
		}

		err = sbctl.Sign(state, kh, file, output, save)
		if errors.Is(err, sbctl.ErrAlreadySigned) {
			logging.Print("File has already been signed %s\n", output)
		} else if err != nil {
			return err
		} else {
			logging.Ok("Signed %s", output)
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
