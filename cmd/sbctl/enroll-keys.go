package main

import (
	"errors"
	"fmt"

	"github.com/foxboron/sbctl"
	"github.com/foxboron/sbctl/logging"
	"github.com/spf13/cobra"
)

var enrollKeysCmd = &cobra.Command{
	Use:   "enroll-keys",
	Short: "Enroll the current keys to EFI",
	RunE: func(cmd *cobra.Command, args []string) error {
		var isImmutable bool
		for _, file := range sbctl.EfivarFSFiles {
			err := sbctl.IsImmutable(file)
			if errors.Is(err, sbctl.ErrImmutable) {
				isImmutable = true
				logging.Warn("File is immutable: %s", file)
			} else if errors.Is(err, sbctl.ErrNotImmutable) {
				continue
			} else if err != nil {
				return fmt.Errorf("couldn't read file: %s", file)
			}
		}
		if isImmutable {
			return sbctl.ErrImmutable
		}
		logging.Print("Syncing keys to EFI variables...")
		synced := sbctl.SBKeySync(sbctl.KeysPath)
		if !synced {
			return errors.New("couldn't sync keys")
		}
		logging.Println("")
		logging.Ok("Synced keys!")
		return nil
	},
}

func init() {
	CliCommands = append(CliCommands, cliCommand{
		Cmd: enrollKeysCmd,
	})
}
