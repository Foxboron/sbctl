package main

import (
	"errors"
	"os"
	"path/filepath"

	"github.com/foxboron/sbctl"
	"github.com/foxboron/sbctl/backend"
	"github.com/foxboron/sbctl/config"
	"github.com/foxboron/sbctl/logging"
	"github.com/foxboron/sbctl/lsm"
	"github.com/landlock-lsm/go-landlock/landlock"
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
		state := cmd.Context().Value(stateDataKey{}).(*config.State)

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

		if state.Config.Landlock {
			lsm.RestrictAdditionalPaths(
				// TODO: This doesn't work quite how I want it to
				// setting RWFiles to the path gets EACCES
				// but setting RWDirs on the dir is fine
				landlock.RWDirs(filepath.Dir(output)),
			)
			if err := lsm.Restrict(); err != nil {
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
