package main

import (
	"os"

	"github.com/foxboron/sbctl"
	"github.com/foxboron/sbctl/logging"
	"github.com/spf13/cobra"
)

var removeBundleCmd = &cobra.Command{
	Use:   "remove-bundle",
	Short: "Remove bundle from database",
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) < 1 {
			logging.Print("Need to specify file\n")
			os.Exit(1)
		}
		bundles, err := sbctl.ReadBundleDatabase(sbctl.BundleDBPath)
		if err != nil {
			return err
		}

		if _, ok := bundles[args[0]]; !ok {
			logging.Print("Bundle %s doesn't exist in database!\n", args[0])
			os.Exit(1)
		}
		delete(bundles, args[0])
		sbctl.WriteBundleDatabase(sbctl.BundleDBPath, bundles)
		return nil
	},
}

func init() {
	CliCommands = append(CliCommands, cliCommand{
		Cmd: removeBundleCmd,
	})
}
