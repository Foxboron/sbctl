package main

import (
	"github.com/foxboron/sbctl"
	"github.com/spf13/cobra"
)

var verifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Find and check if files in the ESP are signed or not",
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := sbctl.VerifyESP(); err != nil {
			// Really need to sort out the low level error handling
			return err
		}
		return nil
	},
}

func init() {
	CliCommands = append(CliCommands, cliCommand{
		Cmd: verifyCmd,
	})
}
