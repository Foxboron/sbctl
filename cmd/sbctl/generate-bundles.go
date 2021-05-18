package main

import (
	"github.com/foxboron/sbctl"
	"github.com/spf13/cobra"
)

var (
	sign bool
)

var generateBundlesCmd = &cobra.Command{
	Use:   "generate-bundles",
	Short: "Generate all EFI stub bundles",
	RunE: func(cmd *cobra.Command, args []string) error {
		return sbctl.GenerateAllBundles(sign)
	},
}

func generateBundlesCmdFlags(cmd *cobra.Command) {
	f := cmd.Flags()
	f.BoolVarP(&sign, "sign", "s", false, "Sign all the generated bundles")
}

func init() {
	generateBundlesCmdFlags(generateBundlesCmd)
	CliCommands = append(CliCommands, cliCommand{
		Cmd: generateBundlesCmd,
	})
}
