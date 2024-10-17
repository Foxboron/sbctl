package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"os"
	"strings"

	"github.com/foxboron/go-uefi/efivarfs"
	"github.com/foxboron/sbctl"
	"github.com/foxboron/sbctl/config"
	"github.com/foxboron/sbctl/logging"
	"github.com/foxboron/sbctl/lsm"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/spf13/afero"
	"github.com/spf13/cobra"
)

type CmdOptions struct {
	JsonOutput      bool
	QuietOutput     bool
	Config          string
	DisableLandlock bool
	Debug           bool
}

type cliCommand struct {
	Cmd *cobra.Command
}

type stateDataKey struct{}

var (
	cmdOptions  = CmdOptions{}
	CliCommands = []cliCommand{}
	ErrSilent   = errors.New("SilentErr")
	rootCmd     = &cobra.Command{
		Use:           "sbctl",
		Short:         "Secure Boot Key Manager",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	baseErrorMsg = `

There are three flags that can be used:
    --microsoft: Enroll the Microsoft OEM certificates into the signature database.
    --tpm-eventlog: Enroll OpRom checksums into the signature database (experimental!).
    --yes-this-might-brick-my-machine: Ignore this warning and continue regardless.

Please read the FAQ for more information: https://github.com/Foxboron/sbctl/wiki/FAQ#option-rom`
	opromErrorMsg      = `Found OptionROM in the bootchain. This means we should not enroll keys into UEFI without some precautions.` + baseErrorMsg
	noEventlogErrorMsg = `Could not find any TPM Eventlog in the system. This means we do not know if there is any OptionROM present on the system.` + baseErrorMsg
	setupModeDisabled  = `Your system is not in Setup Mode! Please reboot your machine and reset secure boot keys before attempting to enroll the keys.`
)

func baseFlags(cmd *cobra.Command) {
	flags := cmd.PersistentFlags()
	flags.BoolVar(&cmdOptions.JsonOutput, "json", false, "Output as json")
	flags.BoolVar(&cmdOptions.QuietOutput, "quiet", false, "Mute info from logging")
	flags.BoolVar(&cmdOptions.DisableLandlock, "disable-landlock", false, "Disable landlock sandboxing")
	flags.BoolVar(&cmdOptions.Debug, "debug", false, "Enable verbose debug logging")
	flags.StringVarP(&cmdOptions.Config, "config", "", "", "Path to configuration file")
}

func JsonOut(v interface{}) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("could not marshal json: %w", err)
	}
	logging.PrintOn()
	logging.Println(string(b))
	// Json should always be the last print call, but lets safe it :)
	logging.PrintOff()
	return nil
}

func main() {
	for _, cmd := range CliCommands {
		rootCmd.AddCommand(cmd.Cmd)
	}

	fs := afero.NewOsFs()

	baseFlags(rootCmd)

	// We save tpmerr and print it when we can print debug messages
	rwc, tpmerr := transport.OpenTPM()
	if tpmerr == nil {
		defer rwc.Close()
	}

	// We need to set this after we have parsed stuff
	rootCmd.PersistentPreRunE = func(cmd *cobra.Command, _ []string) error {
		state := &config.State{
			Fs: fs,
			TPM: func() transport.TPMCloser {
				return rwc
			},
			Efivarfs: efivarfs.NewFS().
				CheckImmutable().
				UnsetImmutable().
				Open(),
		}

		var conf *config.Config

		if cmdOptions.Config != "" {
			b, err := os.ReadFile(cmdOptions.Config)
			if err != nil {
				return err
			}
			conf, err = config.NewConfig(b)
			if err != nil {
				return err
			}

			state.Config = conf

			// TODO: Do we want to overwrite the provided configuration with out existing keys?
			// something to figure out
			// kh, err := backend.GetKeyHierarchy(fs, state)
			// if err != nil {
			// 	return err
			// }
			// state.Config.Keys = kh.GetConfig(state.Config.Keydir)
			// state.Config.DbAdditions = sbctl.GetEnrolledVendorCerts()
		} else {
			if config.HasOldConfig(fs, sbctl.DatabasePath) && !config.HasConfigurationFile(fs, "/etc/sbctl/sbctl.conf") {
				logging.Error(fmt.Errorf("old configuration detected. Please use `sbctl setup --migrate`"))
				conf = config.OldConfig(sbctl.DatabasePath)
				state.Config = conf
			} else if ok, _ := afero.Exists(fs, "/etc/sbctl/sbctl.conf"); ok {
				b, err := os.ReadFile("/etc/sbctl/sbctl.conf")
				if err != nil {
					log.Fatal(err)
				}
				conf, err = config.NewConfig(b)
				if err != nil {
					log.Fatal(err)
				}
				state.Config = conf
			} else {
				conf = config.DefaultConfig()
				state.Config = conf
			}
		}

		if cmdOptions.JsonOutput {
			logging.PrintOff()
		}
		if cmdOptions.QuietOutput {
			logging.DisableInfo = true
		}
		if cmdOptions.DisableLandlock {
			state.Config.Landlock = false
		}

		// Setup debug logging
		opts := &slog.HandlerOptions{
			Level: slog.LevelInfo,
		}
		if cmdOptions.Debug {
			opts.Level = slog.LevelDebug
		}
		logger := slog.New(slog.NewTextHandler(os.Stdout, opts))
		slog.SetDefault(logger)

		if !state.HasTPM() {
			slog.Debug("can't open tpm", slog.Any("err", tpmerr))
		}

		if state.Config.Landlock {
			lsm.LandlockRulesFromConfig(state.Config)
		}
		ctx := context.WithValue(cmd.Context(), stateDataKey{}, state)
		cmd.SetContext(ctx)
		return nil
	}

	// This returns i the flag is not found with a specific error
	rootCmd.SetFlagErrorFunc(func(cmd *cobra.Command, err error) error {
		cmd.Println(err)
		cmd.Println(cmd.UsageString())
		return ErrSilent
	})

	if err := rootCmd.Execute(); err != nil {
		if strings.HasPrefix(err.Error(), "unknown command") {
			logging.Println(err.Error())
		} else if errors.Is(err, os.ErrPermission) {
			logging.Error(fmt.Errorf("sbctl requires root to run: %w", err))
		} else if errors.Is(err, sbctl.ErrImmutable) {
			logging.Println("You need to chattr -i files in efivarfs")
		} else if errors.Is(err, sbctl.ErrOprom) {
			logging.Error(errors.New(opromErrorMsg))
		} else if errors.Is(err, sbctl.ErrNoEventlog) {
			logging.Error(errors.New(noEventlogErrorMsg))
		} else if errors.Is(err, ErrSetupModeDisabled) {
			logging.Error(errors.New(setupModeDisabled))
		} else if !errors.Is(err, ErrSilent) {
			logging.Error(err)
		}
		os.Exit(1)
	}
}
