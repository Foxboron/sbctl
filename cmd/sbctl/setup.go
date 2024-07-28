package main

import (
	"fmt"
	"os"
	"path"

	"github.com/foxboron/sbctl"
	"github.com/foxboron/sbctl/config"
	"github.com/foxboron/sbctl/logging"
	"github.com/goccy/go-yaml"
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
	newConf := config.DefaultConfig()
	p := path.Dir(newConf.Keydir)

	// If state.Config.Keydir is the same as sbctl.DatabasePath
	// we dont need to do anything
	if sbctl.DatabasePath == p {
		logging.Println("Nothing to be done!")
		return nil
	}

	if ok, _ := afero.DirExists(state.Fs, p); ok {
		logging.Print("%s already exists!\n", p)
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
	if err := state.Fs.Rename(path.Join(p, "bundles.db"), newConf.FilesDb); err != nil {
		return err
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
}

func init() {
	setupCmdFlags(setupCmd)
	CliCommands = append(CliCommands, cliCommand{
		Cmd: setupCmd,
	})
}
