package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/foxboron/sbctl"
	"github.com/foxboron/sbctl/logging"
	"github.com/spf13/cobra"
)

type CmdOptions struct {
	JsonOutput bool
}

type cliCommand struct {
	Cmd *cobra.Command
}

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
)

func baseFlags(cmd *cobra.Command) {
	flags := cmd.PersistentFlags()
	flags.BoolVar(&cmdOptions.JsonOutput, "json", false, "Output as json")

	cmd.PersistentPreRun = func(cmd *cobra.Command, args []string) {
		if cmdOptions.JsonOutput {
			logging.PrintOff()
		}
	}
}

func JsonOut(v interface{}) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("could not marshal json: %w", err)
	}
	fmt.Fprint(os.Stdout, string(b))
	return nil
}

func main() {
	for _, cmd := range CliCommands {
		rootCmd.AddCommand(cmd.Cmd)
	}

	baseFlags(rootCmd)

	// This returns i the flag is not found with a specific error
	rootCmd.SetFlagErrorFunc(func(cmd *cobra.Command, err error) error {
		cmd.Println(err)
		cmd.Println(cmd.UsageString())
		return ErrSilent
	})

	if err := rootCmd.Execute(); err != nil {
		if strings.HasPrefix(err.Error(), "unknown comman") {
			logging.Println(err.Error())
		} else if errors.Is(err, os.ErrPermission) {
			logging.Error(fmt.Errorf("sbctl requires root to run: %w", err))
		} else if errors.Is(err, sbctl.ErrImmutable) {
			logging.Println("You need to chattr -i files in efivarfs")
		} else if !errors.Is(err, ErrSilent) {
			logging.Error(err)
		}
		os.Exit(1)
	}
}
