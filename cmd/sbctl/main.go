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
	JsonOutput  bool
	QuietOutput bool
}

type cliCommand struct {
	Cmd *cobra.Command
}

var (
	cmdOptions  = CmdOptions{}
	CliCommands = []cliCommand{}
	ErrSilent   = errors.New("SilentErr")
	rootCmd     = &cobra.Command{
		Use:   "sbctl",
		Short: "Secure Boot Key Manager",
		Long: `'sbctl' aims to provide a full integrated secure boot experience.

All commands that take path arguments convert them into absolute paths when
saving them to the database.

ENVIRONMENT VARIABLES
---------------------

**SYSTEMD_ESP_PATH**, **ESP_PATH**::
        Defines the EFI system partition (ESP) location. This overrides the
        behaviour from **sbctl** where we query for the correct partition with
        **lsblk**. No checks are performed on this path and can be usefull for testing
        purposes.

**SBCTL_UNICODE**::
       If this value is "0" sbctl will replace the unicode symbols to equivalent
       ascii ones. The default value is assumed to be 1.


FILES
----
**/usr/share/secureboot**::
        Default storage directory.

**/usr/share/secureboot/GUID**::
        Owner identification. This is a randomly generated UUID.

**/usr/share/secureboot/files.db**::
        Contains a list of EFI binaries to be signed by the generated key.

**/usr/share/secureboot/bundles.db**::
        Contains a list of EFI bundles to be generated.

**/usr/share/secureboot/keys/db/db.{auth,der,pem,der.esl,key}**::
        Contains the Signature Database key used for signing EFI binaries.

**/usr/share/secureboot/keys/KEK/KEK.{auth,der,pem,der.esl,key}**::
        Contains the Key Exchange Key.

**/usr/share/secureboot/keys/PK/PK.{auth,der,pem,der.esl,key}**::
        Contains the Platform Key.`,
		SilenceUsage:     true,
		SilenceErrors:    true,
		TraverseChildren: true,
	}
	baseErrorMsg = `

There are three flags that can be used:
    --microsoft: Enroll the Microsoft OEM certificates into the signature database.
    --tpm-eventlog: Enroll OpRom checksums into the signature database (experimental!).
    --yes-this-might-brick-my-machine: Ignore this warning and continue regardless.

Please read the FAQ for more information: https://github.com/Foxboron/sbctl/wiki/FAQ#option-rom`
	opromErrorMsg      = `Found OptionROM in the bootchain. This means we should not enroll keys into UEFI without some precautions.` + baseErrorMsg
	noEventlogErrorMsg = `Could not find any TPM Eventlog in the system. This means we do not know if there is any OptionROM present on the system.` + baseErrorMsg
)

func baseFlags(cmd *cobra.Command) {
	flags := cmd.PersistentFlags()
	flags.BoolVar(&cmdOptions.JsonOutput, "json", false, "Output as json")
	flags.BoolVar(&cmdOptions.QuietOutput, "quiet", false, "Mute info from logging")

	cmd.PersistentPreRun = func(cmd *cobra.Command, args []string) {
		if cmdOptions.JsonOutput {
			logging.PrintOff()
		}
		if cmdOptions.QuietOutput {
			logging.DisableInfo = true
		}
	}
}

func JsonOut(v interface{}) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("could not marshal json: %w", err)
	}
	logging.Print(string(b))
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
		if strings.HasPrefix(err.Error(), "unknown command") {
			logging.Println(err.Error())
		} else if errors.Is(err, os.ErrPermission) {
			logging.Error(fmt.Errorf("sbctl requires root to run: %w", err))
		} else if errors.Is(err, sbctl.ErrImmutable) {
			logging.Println("You need to chattr -i files in efivarfs")
		} else if errors.Is(err, sbctl.ErrOprom) {
			logging.Error(fmt.Errorf(opromErrorMsg))
		} else if errors.Is(err, sbctl.ErrNoEventlog) {
			logging.Error(fmt.Errorf(noEventlogErrorMsg))
		} else if !errors.Is(err, ErrSilent) {
			logging.Error(err)
		}
		os.Exit(1)
	}
}
