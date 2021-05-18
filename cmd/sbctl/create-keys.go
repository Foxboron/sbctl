package main

import (
	"github.com/foxboron/sbctl"
	"github.com/spf13/cobra"
)

var createKeysCmd = &cobra.Command{
	Use:   "create-keys",
	Short: "Create a set of secure boot signing keys",
	RunE: func(cmd *cobra.Command, args []string) error {
		return sbctl.CreateKeys()
	},
}

func init() {
	CliCommands = append(CliCommands, cliCommand{
		Cmd: createKeysCmd,
	})
}
