package main

import (
	"errors"
	"fmt"

	"github.com/foxboron/sbctl"
	"github.com/foxboron/sbctl/backend"
	"github.com/foxboron/sbctl/config"
	"github.com/foxboron/sbctl/hierarchy"
	"github.com/foxboron/sbctl/logging"
	"github.com/spf13/cobra"
)

var (
	sign bool
)

var generateBundlesCmd = &cobra.Command{
	Use:   "generate-bundles",
	Short: "Generate all EFI stub bundles",
	RunE: func(cmd *cobra.Command, args []string) error {
		state := cmd.Context().Value(stateDataKey{}).(*config.State)

		logging.Errorf("The bundle/uki support in sbctl is deprecated. Please move to dracut/mkinitcpio/ukify.")

		logging.Println("Generating EFI bundles....")
		out_create := true
		out_sign := true
		var out_err error
		err := sbctl.BundleIter(state, func(bundle *sbctl.Bundle) error {
			err := sbctl.CreateBundle(state, *bundle)
			if err != nil {
				out_create = false
				out_err = fmt.Errorf("failed creating bundle %s: %w", bundle.Output, err)
				return nil
			}
			logging.Print("Wrote EFI bundle %s\n", bundle.Output)
			if sign {
				file := bundle.Output
				kh, err := backend.GetKeyHierarchy(state.Fs, state)
				if err != nil {
					return err
				}
				err = sbctl.SignFile(state, kh, hierarchy.Db, file, file)
				if errors.Is(err, sbctl.ErrAlreadySigned) {
					logging.Unknown("Bundle has already been signed")
				} else if err != nil {
					out_sign = false
					out_err = fmt.Errorf("failed signing bundle %s: %w", bundle.Output, err)
				} else {
					logging.Ok("Signed %s", file)
				}
			}
			return nil
		})
		if !out_create || !out_sign {
			return out_err
		}
		if err != nil {
			return err
		}
		return nil
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
