package main

import (
	"fmt"
	"os"
	"path"
	"path/filepath"

	"github.com/foxboron/sbctl"
	"github.com/foxboron/sbctl/backend"
	"github.com/foxboron/sbctl/config"
	"github.com/foxboron/sbctl/logging"
	"github.com/foxboron/sbctl/lsm"
	"github.com/goccy/go-yaml"
	"github.com/landlock-lsm/go-landlock/landlock"
	"github.com/spf13/afero"
	"github.com/spf13/cobra"
)

type SetupCmdOptions struct {
	PrintConfig bool
	PrintState  bool
	Migrate     bool
	Setup       bool
}

var (
	setupCmdOptions = SetupCmdOptions{}
	setupCmd        = &cobra.Command{
		Use:   "setup",
		Short: "Setup sbctl",
		RunE:  RunSetup,
	}
)

func PrintConfig(state *config.State) error {
	if state.Config.Landlock {
		if err := lsm.Restrict(); err != nil {
			return err
		}
	}
	var ser any
	if cmdOptions.Config != "" {
		b, err := os.ReadFile(cmdOptions.Config)
		if err != nil {
			return err
		}
		state.Config, err = config.NewConfig(b)
		if err != nil {
			return err
		}
	} else {
		kh, err := backend.GetKeyHierarchy(state.Fs, state)
		if err != nil {
			return err
		}
		state.Config.Keys = kh.GetConfig(state.Config.Keydir)
		state.Config.DbAdditions = sbctl.GetEnrolledVendorCerts()
	}

	// Setup the files
	if ok, _ := afero.Exists(state.Fs, state.Config.FilesDb); ok {
		var files []*config.FileConfig
		if err := sbctl.SigningEntryIter(state,
			func(s *sbctl.SigningEntry) error {
				files = append(files, &config.FileConfig{
					Path:   s.File,
					Output: s.OutputFile,
				})
				return nil
			}); err != nil {
			return err
		}
		state.Config.Files = files
	}

	ser = state.Config
	if setupCmdOptions.PrintState && !cmdOptions.JsonOutput {
		return fmt.Errorf("can only use --print-state with --json")
	}

	if setupCmdOptions.PrintState {
		ser = state
	} else {
		ser = state.Config
	}

	if cmdOptions.JsonOutput {
		if err := JsonOut(ser); err != nil {
			return err
		}
		return nil
	}
	b, err := yaml.Marshal(ser)
	if err != nil {
		return err
	}

	fmt.Print(string(b))
	return nil
}

func SetupInstallation(state *config.State) error {
	if state.Config.Landlock {
		if err := sbctl.LandlockFromFileDatabase(state); err != nil {
			return err
		}
		if err := lsm.Restrict(); err != nil {
			return err
		}
	}

	if ok, _ := state.Efivarfs.GetSetupMode(); !ok {
		return ErrSetupModeDisabled
	}
	if state.IsInstalled() {
		return fmt.Errorf("sbctl is already installed")
	}

	if err := RunCreateKeys(state); err != nil {
		return err
	}

	if err := RunEnrollKeys(state); err != nil {
		return err
	}

	if len(state.Config.Files) == 0 {
		return nil
	}

	files, err := sbctl.ReadFileDatabase(state.Fs, state.Config.FilesDb)
	if err != nil {
		return err
	}

	for _, f := range state.Config.Files {
		if f.Output == "" {
			f.Output = f.Path
		}
		files[f.Path] = &sbctl.SigningEntry{File: f.Path, OutputFile: f.Output}
	}

	if err := sbctl.WriteFileDatabase(state.Fs, state.Config.FilesDb, files); err != nil {
		return err
	}

	if err := SignAll(state); err != nil {
		return err
	}

	return nil
}

func MigrateSetup(state *config.State) error {
	if !state.IsInstalled() {
		return fmt.Errorf("sbctl is not installed")
	}

	newConf := config.DefaultConfig()
	p := path.Dir(newConf.Keydir)

	// abort early if it exists
	if ok, _ := afero.DirExists(state.Fs, newConf.Keydir); ok {
		logging.Println("sbctl has already been migrated!")
		return nil
	}

	if err := state.Fs.MkdirAll(p, os.ModePerm); err != nil {
		return err
	}

	if state.Config.Landlock {
		lsm.RestrictAdditionalPaths(
			landlock.RWDirs(filepath.Dir(filepath.Clean(sbctl.DatabasePath))),
			landlock.RWDirs(p),
		)
		if err := lsm.Restrict(); err != nil {
			return err
		}
	}

	// If state.Config.Keydir is the same as sbctl.DatabasePath
	// we dont need to do anything
	if sbctl.DatabasePath == p {
		logging.Println("Nothing to be done!")
		return nil
	}

	logging.Print("Moving files...")
	if err := sbctl.CopyDirectory(state.Fs, sbctl.DatabasePath, p); err != nil {
		logging.NotOk("")
		return err
	}

	if err := state.Fs.Rename(path.Join(p, "files.db"), newConf.FilesDb); err != nil {
		return err
	}
	if ok, _ := afero.Exists(state.Fs, path.Join(p, "bundles.db")); ok {
		if err := state.Fs.Rename(path.Join(p, "bundles.db"), newConf.BundlesDb); err != nil {
			return err
		}
	}
	logging.Ok("")

	if err := state.Fs.RemoveAll(sbctl.DatabasePath); err != nil {
		return err
	}
	return nil
}

func RunSetup(cmd *cobra.Command, args []string) error {
	state := cmd.Context().Value(stateDataKey{}).(*config.State)

	if setupCmdOptions.Setup {
		if err := SetupInstallation(state); err != nil {
			return err
		}
	}

	if setupCmdOptions.Migrate {
		if err := MigrateSetup(state); err != nil {
			return err
		}
	}

	if setupCmdOptions.PrintConfig || setupCmdOptions.PrintState {
		return PrintConfig(state)
	}

	return nil
}

func setupCmdFlags(cmd *cobra.Command) {
	f := cmd.Flags()
	f.BoolVarP(&setupCmdOptions.PrintConfig, "print-config", "", false, "print config file")
	f.BoolVarP(&setupCmdOptions.PrintState, "print-state", "", false, "print the state of sbctl")
	f.BoolVarP(&setupCmdOptions.Migrate, "migrate", "", false, "migrate the sbctl installation")
	f.BoolVarP(&setupCmdOptions.Setup, "setup", "", false, "setup the sbctl installation")
	cmd.MarkFlagsOneRequired("print-config", "print-state", "migrate", "setup")
	cmd.MarkFlagsMutuallyExclusive("print-config", "print-state", "migrate", "setup")
}

func init() {
	setupCmdFlags(setupCmd)
	CliCommands = append(CliCommands, cliCommand{
		Cmd: setupCmd,
	})
}
