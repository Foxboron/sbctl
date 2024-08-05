package main

import (
	"errors"
	"fmt"

	"github.com/foxboron/sbctl"
	"github.com/foxboron/sbctl/backend"
	"github.com/foxboron/sbctl/config"
	"github.com/foxboron/sbctl/hierarchy"
	"github.com/foxboron/sbctl/logging"
	"github.com/foxboron/sbctl/lsm"
	"github.com/spf13/cobra"
)

var (
	generate bool
)

var signAllCmd = &cobra.Command{
	Use:   "sign-all",
	Short: "Sign all enrolled files with secure boot keys",
	RunE: func(cmd *cobra.Command, args []string) error {
		var gerr error
		state := cmd.Context().Value(stateDataKey{}).(*config.State)
		// Don't run landlock if we are making UKIs
		if state.Config.Landlock && !generate {
			if err := sbctl.LandlockFromFileDatabase(state); err != nil {
				return err
			}
			if err := lsm.Restrict(); err != nil {
				return err
			}
		}

		if generate {
			sign = true
			if err := generateBundlesCmd.RunE(cmd, args); err != nil {
				gerr = ErrSilent
				logging.Error(err)
			}
		}
		serr := SignAll(state)
		if serr != nil || gerr != nil {
			return ErrSilent
		}
		return nil
	},
}

func SignAll(state *config.State) error {
	var signerr error
	files, err := sbctl.ReadFileDatabase(state.Fs, state.Config.FilesDb)
	if err != nil {
		return err
	}
	for _, entry := range files {

		kh, err := backend.GetKeyHierarchy(state.Fs, state)
		if err != nil {
			return err
		}

		err = sbctl.SignFile(state, kh, hierarchy.Db, entry.File, entry.OutputFile)
		if errors.Is(err, sbctl.ErrAlreadySigned) {
			logging.Print("File has already been signed %s\n", entry.OutputFile)
		} else if err != nil {
			logging.Error(fmt.Errorf("failed signing %s: %w", entry.File, err))
			// Ensure we are getting os.Exit(1)
			signerr = ErrSilent
			continue
		} else {
			logging.Ok("Signed %s", entry.OutputFile)
		}

		// Update checksum after we signed it
		files[entry.File] = entry
		if err := sbctl.WriteFileDatabase(state.Fs, state.Config.FilesDb, files); err != nil {
			return err
		}
	}
	return signerr
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
