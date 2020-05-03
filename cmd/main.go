package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/foxboron/sbctl"
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "sbctl",
	Short: "Secure Boot key manager",
}

func createKeysCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "create-keys",
		Short: "Create a set of secure boot signing keys",
		Run: func(cmd *cobra.Command, args []string) {
			sbctl.CreateKeys()
		},
	}
}

func enrollKeysCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "enroll-keys",
		Short: "Enroll the current keys to EFI",
		Run: func(cmd *cobra.Command, args []string) {
			sbctl.SyncKeys()
		},
	}
}

func signCmd() *cobra.Command {
	var save bool
	var output string

	cmd := &cobra.Command{
		Use:   "sign",
		Short: "Sign a file with secure boot keys",
		Run: func(cmd *cobra.Command, args []string) {
			if len(args) < 1 {
				log.Fatalf("Requires a file to sign...\n")
			}
			sbctl.Sign(args[0], output, save)
		},
	}
	f := cmd.Flags()
	f.BoolVarP(&save, "save", "s", false, "save file to the database")
	f.StringVarP(&output, "output", "o", "", "output filename. Default replaces the file")
	return cmd
}

func signAllCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "sign-all",
		Short: "Sign all enrolled files with secure boot keys",
		Run: func(cmd *cobra.Command, args []string) {
			files := sbctl.ReadFileDatabase(sbctl.DBPath)
			for _, entry := range files {
				sbctl.SignFile(sbctl.DBKey, sbctl.DBCert, entry.File, entry.OutputFile)
			}
		},
	}
}

func removeFileCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "remove-file",
		Short: "Remove file from database",
		Run: func(cmd *cobra.Command, args []string) {
			if len(args) < 1 {
				log.Fatal("Need to specify file")
			}
			files := sbctl.ReadFileDatabase(sbctl.DBPath)
			delete(files, args[0])
			sbctl.WriteFileDatabase(sbctl.DBPath, files)
		},
	}
}

func statusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show current boot status",
		Run: func(cmd *cobra.Command, args []string) {
			sbctl.CheckStatus()
		},
	}
}

func verifyCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "verify",
		Short: "Find and check if files in the ESP are signed or not",
		Run: func(cmd *cobra.Command, args []string) {
			sbctl.VerifyESP()
		},
	}
}

func listFilesCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list-files",
		Short: "List enrolled files",
		Run: func(cmd *cobra.Command, args []string) {
			sbctl.ListFiles()
		},
	}
}

func bundleCmd() *cobra.Command {
	var amducode string
	var intelucode string
	var splashImg string
	var osRelease string
	var efiStub string
	var kernelImg string
	var cmdline string
	var initramfs string
	var espPath string
	var save bool
	cmd := &cobra.Command{
		Use:   "bundle",
		Short: "Bundle the needed files for an EFI stub image",
		Run: func(cmd *cobra.Command, args []string) {
			if len(args) < 1 {
				log.Fatalf("Requires a file to sign...\n")
			}
			checkFiles := []string{amducode, intelucode, splashImg, osRelease, efiStub, kernelImg, cmdline, initramfs}
			for _, path := range checkFiles {
				if path == "" {
					continue
				}
				if _, err := os.Stat(path); os.IsNotExist(err) {
					log.Fatalf("%s does not exist!", path)
					os.Exit(1)
				}
			}
			bundle := sbctl.NewBundle()
			bundle.Output = args[0]
			bundle.IntelMicrocode = intelucode
			bundle.AMDMicrocode = amducode
			bundle.KernelImage = kernelImg
			bundle.Initramfs = initramfs
			bundle.Cmdline = cmdline
			bundle.Splash = splashImg
			bundle.OSRelease = osRelease
			bundle.EFIStub = efiStub
			bundle.ESP = espPath
			sbctl.CreateBundle(*bundle)
			if save {
				bundles := sbctl.ReadBundleDatabase(sbctl.BundleDBPath)
				bundles[bundle.Output] = bundle
				sbctl.WriteBundleDatabase(sbctl.BundleDBPath, bundles)
				sbctl.FormatBundle(bundle.Output, bundle)
			}
		},
	}
	esp := sbctl.GetESP()
	f := cmd.Flags()
	f.StringVarP(&amducode, "amducode", "a", "", "AMD microcode location")
	f.StringVarP(&intelucode, "intelucode", "i", "", "Intel microcode location")
	f.StringVarP(&splashImg, "splash-img", "l", "", "Boot splash image location")
	f.StringVarP(&osRelease, "os-release", "o", "/usr/lib/os-release", "OS Release file location")
	f.StringVarP(&efiStub, "efi-stub", "e", "/usr/lib/systemd/boot/efi/linuxx64.efi.stub", "EFI Stub location")
	f.StringVarP(&kernelImg, "kernel-img", "k", filepath.Join(esp, "vmlinuz-linux"), "Kernel image location")
	f.StringVarP(&cmdline, "cmdline", "c", "/proc/cmdline", "Cmdline location")
	f.StringVarP(&initramfs, "initramfs", "f", filepath.Join(esp, "initramfs-linux.img"), "Initramfs location")
	f.StringVarP(&espPath, "esp", "p", esp, "ESP location")
	f.BoolVarP(&save, "save", "s", false, "save bundle to the database")
	return cmd
}

func generateBundlesCmd() *cobra.Command {
	var sign bool
	cmd := &cobra.Command{
		Use:   "generate-bundles",
		Short: "Generate all EFI stub bundles",
		Run: func(cmd *cobra.Command, args []string) {
			sbctl.GenerateAllBundles()
		},
	}
	f := cmd.Flags()
	f.BoolVarP(&sign, "sign", "s", false, "Sign all the generated bundles")
	return cmd
}

func listBundlesCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list-bundles",
		Short: "List stored bundles",
		Run: func(cmd *cobra.Command, args []string) {
			sbctl.ListBundles()
		},
	}
}

func removeBundleCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "remove-bundle",
		Short: "Remove bundle from database",
		Run: func(cmd *cobra.Command, args []string) {
			if len(args) < 1 {
				log.Fatal("Need to specify file")
			}
			bundles := sbctl.ReadBundleDatabase(sbctl.BundleDBPath)
			delete(bundles, args[0])
			sbctl.WriteBundleDatabase(sbctl.BundleDBPath, bundles)
		},
	}
}

func main() {
	rootCmd.PersistentPreRun = func(_ *cobra.Command, args []string) {
		if os.Geteuid() != 0 {
			fmt.Println("Needs to be executed as root")
			os.Exit(1)
		}
	}
	rootCmd.AddCommand(createKeysCmd())
	rootCmd.AddCommand(enrollKeysCmd())
	rootCmd.AddCommand(signCmd())
	rootCmd.AddCommand(signAllCmd())
	rootCmd.AddCommand(statusCmd())
	rootCmd.AddCommand(verifyCmd())
	rootCmd.AddCommand(listFilesCmd())
	rootCmd.AddCommand(bundleCmd())
	rootCmd.AddCommand(generateBundlesCmd())
	rootCmd.AddCommand(removeBundleCmd())
	rootCmd.AddCommand(listBundlesCmd())
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
