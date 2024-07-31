package main

import (
	"fmt"

	"github.com/foxboron/sbctl"
	"github.com/spf13/cobra"
)

var (
	versionCmd = &cobra.Command{
		Use:    "version",
		Short:  "Print sbctl version",
		Hidden: true,
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println(sbctl.Version)
		},
	}
)

func init() {
	CliCommands = append(CliCommands, cliCommand{
		Cmd: versionCmd,
	})
}
