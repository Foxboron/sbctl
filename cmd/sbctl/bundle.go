package main

import (
	"os"
	"path/filepath"

	"github.com/foxboron/sbctl"
	"github.com/foxboron/sbctl/config"
	"github.com/foxboron/sbctl/logging"
	"github.com/spf13/afero"
	"github.com/spf13/cobra"
)

var (
	amducode   string
	intelucode string
	splashImg  string
	osRelease  string
	efiStub    string
	kernelImg  string
	cmdline    string
	initramfs  string
	espPath    string
	saveBundle bool
)

var bundleCmd = &cobra.Command{
	Use:   "bundle",
	Short: "Bundle the needed files for an EFI stub image",
	RunE: func(cmd *cobra.Command, args []string) error {
		state := cmd.Context().Value(stateDataKey{}).(*config.State)

		logging.Errorf("The bundle/uki support in sbctl is deprecated. Please move to dracut/mkinitcpio/ukify.")

		if len(args) < 1 {
			logging.Print("Requires a file to sign...\n")
			os.Exit(1)
		}
		checkFiles := []string{amducode, intelucode, splashImg, osRelease, efiStub, kernelImg, cmdline, initramfs}
		for _, path := range checkFiles {
			if path == "" {
				continue
			}
			if _, err := state.Fs.Stat(path); os.IsNotExist(err) {
				logging.Print("%s does not exist!\n", path)
				os.Exit(1)
			}
		}
		bundle, err := sbctl.NewBundle(state.Fs)
		if err != nil {
			return err
		}
		output, err := filepath.Abs(args[0])
		if err != nil {
			return err
		}
		// Fail early if user wants to save bundle but doesn't have permissions
		var bundles sbctl.Bundles
		if saveBundle {
			// "err" needs to have been declared before this, otherwise it's necessary
			// to use ":=", which shadows the "bundles" variable
			bundles, err = sbctl.ReadBundleDatabase(state.Fs, state.Config.BundlesDb)
			if err != nil {
				return err
			}
		}
		bundle.Output = output
		bundle.IntelMicrocode = intelucode
		bundle.AMDMicrocode = amducode
		bundle.KernelImage = kernelImg
		bundle.Initramfs = initramfs
		bundle.Cmdline = cmdline
		bundle.Splash = splashImg
		bundle.OSRelease = osRelease
		bundle.EFIStub = efiStub
		bundle.ESP = espPath
		if err = sbctl.CreateBundle(state, *bundle); err != nil {
			return err
		}
		logging.Print("Wrote EFI bundle %s\n", bundle.Output)
		if saveBundle {
			bundles[bundle.Output] = bundle
			err := sbctl.WriteBundleDatabase(state.Fs, state.Config.BundlesDb, bundles)
			if err != nil {
				return err
			}
		}
		return nil
	},
}

func bundleCmdFlags(cmd *cobra.Command) {
	esp, _ := sbctl.GetESP(afero.NewOsFs())
	f := cmd.Flags()
	f.StringVarP(&amducode, "amducode", "a", "", "AMD microcode location")
	f.StringVarP(&intelucode, "intelucode", "i", "", "Intel microcode location")
	f.StringVarP(&splashImg, "splash-img", "l", "", "Boot splash image location")
	f.StringVarP(&osRelease, "os-release", "o", "/usr/lib/os-release", "OS Release file location")
	f.StringVarP(&efiStub, "efi-stub", "e", "/usr/lib/systemd/boot/efi/linuxx64.efi.stub", "EFI Stub location")
	f.StringVarP(&kernelImg, "kernel-img", "k", "/boot/vmlinuz-linux", "Kernel image location")
	f.StringVarP(&cmdline, "cmdline", "c", "/etc/kernel/cmdline", "Cmdline location")
	f.StringVarP(&initramfs, "initramfs", "f", "/boot/initramfs-linux.img", "Initramfs location")
	f.StringVarP(&espPath, "esp", "p", esp, "ESP location")
	f.BoolVarP(&saveBundle, "save", "s", false, "save bundle to the database")
}

func init() {
	bundleCmdFlags(bundleCmd)
	CliCommands = append(CliCommands, cliCommand{
		Cmd: bundleCmd,
	})
}
