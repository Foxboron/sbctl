package main

import (
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

			// Ensure we have absolute paths
			file, err := filepath.Abs(args[0])
			if err != nil {
				log.Fatal(err)
			}
			if output == "" {
				output = file
			} else {
				output, err = filepath.Abs(output)
				if err != nil {
					log.Fatal(err)
				}
			}

			if err := sbctl.Sign(file, output, save); err != nil {
				log.Fatalln(err)
			}
		},
	}
	f := cmd.Flags()
	f.BoolVarP(&save, "save", "s", false, "save file to the database")
	f.StringVarP(&output, "output", "o", "", "output filename. Default replaces the file")
	return cmd
}

func signAllCmd() *cobra.Command {
	var generate bool
	cmd := &cobra.Command{
		Use:   "sign-all",
		Short: "Sign all enrolled files with secure boot keys",
		Run: func(cmd *cobra.Command, args []string) {
			var outBundle error
			outSign := false

			if generate {
				outBundle = sbctl.GenerateAllBundles(true)
			}

			files, err := sbctl.ReadFileDatabase(sbctl.DBPath)
			if err != nil {
				log.Fatalln(err)
			}
			for _, entry := range files {

				if sbctl.SignFile(sbctl.DBKey, sbctl.DBCert, entry.File, entry.OutputFile, entry.Checksum) != nil {
					outSign = true
					continue
				}

				// Update checksum after we signed it
				checksum := sbctl.ChecksumFile(entry.File)
				entry.Checksum = checksum
				files[entry.File] = entry
				sbctl.WriteFileDatabase(sbctl.DBPath, files)

			}

			if outBundle != nil || outSign {
				log.Fatalln("Errors were encountered, see above")
			}
		},
	}
	f := cmd.Flags()
	f.BoolVarP(&generate, "generate", "g", false, "run all generate-* sub-commands before signing")
	return cmd
}

func removeFileCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "remove-file",
		Short: "Remove file from database",
		Run: func(cmd *cobra.Command, args []string) {
			if len(args) < 1 {
				log.Fatal("Need to specify file")
			}
			files, err := sbctl.ReadFileDatabase(sbctl.DBPath)
			if err != nil {
				log.Fatalln(err)
			}
			if _, ok := files[args[0]]; !ok {
				log.Printf("File %s doesn't exist in database!\n", args[0])
				os.Exit(1)
			}
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
			if err := sbctl.VerifyESP(); err != nil {
				// Really need to sort out the low level error handling
				os.Exit(1)
			}
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
			output, err := filepath.Abs(args[0])
			if err != nil {
				log.Fatal(err)
			}
			// Fail early if user wants to save bundle but doesn't have permissions
			var bundles sbctl.Bundles
			if save {
				// "err" needs to have been declared before this, otherwise it's necessary
				// to use ":=", which shadows the "bundles" variable
				bundles, err = sbctl.ReadBundleDatabase(sbctl.BundleDBPath)
				if err != nil {
					log.Fatalln(err)
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
			if err = sbctl.CreateBundle(*bundle); err != nil {
				log.Fatalln(err)
				os.Exit(1)
			}
			if save {
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
	f.StringVarP(&cmdline, "cmdline", "c", "/etc/kernel/cmdline", "Cmdline location")
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
			sbctl.GenerateAllBundles(sign)
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
			bundles, err := sbctl.ReadBundleDatabase(sbctl.BundleDBPath)
			if err != nil {
				log.Fatalln(err)
			}

			if _, ok := bundles[args[0]]; !ok {
				log.Printf("Bundle %s doesn't exist in database!\n", args[0])
				os.Exit(1)
			}
			delete(bundles, args[0])
			sbctl.WriteBundleDatabase(sbctl.BundleDBPath, bundles)
		},
	}
}

func completionBashCmd() *cobra.Command {
	var completionCmd = &cobra.Command{
		Use:    "bash",
		Hidden: true,
		Run: func(cmd *cobra.Command, args []string) {
			rootCmd.GenBashCompletion(os.Stdout)
		},
	}
	return completionCmd
}

func completionZshCmd() *cobra.Command {
	var completionCmd = &cobra.Command{
		Use:    "zsh",
		Hidden: true,
		Run: func(cmd *cobra.Command, args []string) {
			rootCmd.GenZshCompletion(os.Stdout)
		},
	}
	return completionCmd
}

func completionFishCmd() *cobra.Command {
	var completionCmd = &cobra.Command{
		Use:    "fish",
		Hidden: true,
		Run: func(cmd *cobra.Command, args []string) {
			rootCmd.GenFishCompletion(os.Stdout, true)
		},
	}
	return completionCmd
}

func main() {
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
	rootCmd.AddCommand(removeFileCmd())

	completionCmd := &cobra.Command{Use: "completion"}
	completionCmd.AddCommand(completionBashCmd())
	completionCmd.AddCommand(completionZshCmd())
	completionCmd.AddCommand(completionFishCmd())
	rootCmd.AddCommand(completionCmd)
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
	sbctl.ColorsOff()
}
