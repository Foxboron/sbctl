package main

import (
	"fmt"
	"strings"

	"github.com/foxboron/sbctl"
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
		bundles := []JsonBundle{}
		var isSigned bool
		err := sbctl.BundleIter(
			func(s *sbctl.Bundle) error {
				ok, err := sbctl.VerifyFile(sbctl.DBCert, s.Output)
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
				esp, err := sbctl.GetESP()
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
			JsonOut(bundles)
		}
		return nil
	},
}

func init() {
	CliCommands = append(CliCommands, cliCommand{
		Cmd: listBundlesCmd,
	})
}
