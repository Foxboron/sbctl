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
	"github.com/spf13/afero"
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

		var rules []landlock.Rule

		// Ensure we have absolute paths
		file, err := filepath.Abs(args[0])
		if err != nil {
			return err
		}
		// Get output path from database for file if output not specified
		if output == "" {
			files, err := sbctl.ReadFileDatabase(state.Fs, state.Config.FilesDb)
			if err != nil {
				return err
			}
			for _, entry := range files {
				if entry.File == file {
					output = entry.OutputFile
					break
				}
			}
		}

		if output == "" {
			output = file
			rules = append(rules, lsm.TruncFile(file).IgnoreIfMissing())
		} else {
			output, err = filepath.Abs(output)
			if err != nil {
				return err
			}
			// Set input file to RO and output dir/file to RW
			rules = append(rules, landlock.ROFiles(file).IgnoreIfMissing())
			if ok, _ := afero.Exists(state.Fs, output); ok {
				rules = append(rules, lsm.TruncFile(output))
			} else {
				rules = append(rules, landlock.RWDirs(filepath.Dir(output)))
			}
		}

		if state.Config.Landlock {
			lsm.RestrictAdditionalPaths(rules...)
			if err := lsm.Restrict(); err != nil {
				return err
			}
		}

		kh, err := backend.GetKeyHierarchy(state.Fs, state)
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
