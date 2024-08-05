package main

import (
	"fmt"
	"strings"

	"github.com/foxboron/sbctl"
	"github.com/foxboron/sbctl/backend"
	"github.com/foxboron/sbctl/config"
	"github.com/foxboron/sbctl/hierarchy"
	"github.com/foxboron/sbctl/logging"
	"github.com/spf13/cobra"
)

type JsonBundle struct {
	sbctl.Bundle
	IsSigned bool `json:"is_signed"`
}

var listBundlesCmd = &cobra.Command{
	Use: "list-bundles",
	Aliases: []string{
		"ls-bundles",
	},
	Short: "List stored bundles",
	RunE: func(cmd *cobra.Command, args []string) error {
		state := cmd.Context().Value(stateDataKey{}).(*config.State)

		logging.Errorf("The bundle/uki support in sbctl is deprecated. Please move to dracut/mkinitcpio/ukify.")

		// if state.Config.Landlock {
		// 	if err := lsm.Restrict(); err != nil {
		// 		return err
		// 	}
		// }

		bundles := []JsonBundle{}
		var isSigned bool
		err := sbctl.BundleIter(state,
			func(s *sbctl.Bundle) error {
				kh, err := backend.GetKeyHierarchy(state.Fs, state)
				if err != nil {
					return err
				}
				ok, err := sbctl.VerifyFile(state, kh, hierarchy.Db, s.Output)
				if err != nil {
					logging.Error(fmt.Errorf("%s: %w", s.Output, err))
					logging.Error(fmt.Errorf(""))
					return nil
				}
				logging.Println("Enrolled bundles:\n")
				logging.Println(s.Output)
				logging.Print("\tSigned:\t\t")
				if ok {
					isSigned = true
					logging.Ok("Signed")
				} else {
					isSigned = false
					logging.NotOk("Not Signed")
				}
				esp, err := sbctl.GetESP(state.Fs)
				if err != nil {
					return err
				}
				logging.Print("\tESP Location:\t%s\n", esp)
				logging.Print("\tOutput:\t\t└─%s\n", strings.TrimPrefix(s.Output, esp))
				logging.Print("\tEFI Stub Image:\t  └─%s\n", s.EFIStub)
				if s.Splash != "" {
					logging.Print("\tSplash Image:\t    ├─%s\n", s.Splash)
				}
				logging.Print("\tCmdline:\t    ├─%s\n", s.Cmdline)
				logging.Print("\tOS Release:\t    ├─%s\n", s.OSRelease)
				logging.Print("\tKernel Image:\t    ├─%s\n", s.KernelImage)
				logging.Print("\tInitramfs Image:    └─%s\n", s.Initramfs)
				if s.AMDMicrocode != "" {
					logging.Print("\tAMD Microcode:        └─%s\n", s.AMDMicrocode)
				}
				if s.IntelMicrocode != "" {
					logging.Print("\tIntel Microcode:      └─%s\n", s.IntelMicrocode)
				}
				bundles = append(bundles, JsonBundle{*s, isSigned})
				logging.Println("")
				return nil
			})
		if err != nil {
			return err
		}
		if cmdOptions.JsonOutput {
			return JsonOut(bundles)
		}
		return nil
	},
}

func init() {
	CliCommands = append(CliCommands, cliCommand{
		Cmd: listBundlesCmd,
	})
}
