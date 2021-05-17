package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/foxboron/sbctl"
	"github.com/foxboron/sbctl/logging"
	"github.com/spf13/cobra"
)

type CmdOptions struct {
	JsonOutput bool
}

type cliCommand struct {
	Cmd *cobra.Command
}

var (
	cmdOptions  = CmdOptions{}
	CliCommands = []cliCommand{}
	ErrSilent   = errors.New("SilentErr")
	rootCmd     = &cobra.Command{
		Use:           "sbctl",
		Short:         "Secure Boot Key Manager",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
)

func baseFlags(cmd *cobra.Command) {
	flags := cmd.Flags()
	flags.BoolVar(&cmdOptions.JsonOutput, "json", false, "Output as json")

	cmd.PreRun = func(cmd *cobra.Command, args []string) {
		if cmdOptions.JsonOutput {
			logging.PrintOff()
		}
	}
}

func JsonOut(v interface{}) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("could not marshal json: %w", err)
	}
	fmt.Fprintf(os.Stdout, string(b))
	return nil
}

func createKeysCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "create-keys",
		Short: "Create a set of secure boot signing keys",
		RunE: func(cmd *cobra.Command, args []string) error {
			return sbctl.CreateKeys()
		},
	}
}

func enrollKeysCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "enroll-keys",
		Short: "Enroll the current keys to EFI",
		RunE: func(cmd *cobra.Command, args []string) error {
			return sbctl.SyncKeys()
		},
	}
}

func signCmd() *cobra.Command {
	var save bool
	var output string

	cmd := &cobra.Command{
		Use:   "sign",
		Short: "Sign a file with secure boot keys",
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) < 1 {
				logging.Print("Requires a file to sign\n")
				os.Exit(1)
			}

			// Ensure we have absolute paths
			file, err := filepath.Abs(args[0])
			if err != nil {
				return err
			}
			if output == "" {
				output = file
			} else {
				output, err = filepath.Abs(output)
				if err != nil {
					return err
				}
			}

			if err := sbctl.Sign(file, output, save); err != nil {
				return err
			}
			return nil
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
		RunE: func(cmd *cobra.Command, args []string) error {
			if generate {
				if err := sbctl.GenerateAllBundles(true); err != nil {
					logging.Fatal(err)
				}
			}

			files, err := sbctl.ReadFileDatabase(sbctl.DBPath)
			if err != nil {
				return err
			}
			for _, entry := range files {

				if err := sbctl.SignFile(sbctl.DBKey, sbctl.DBCert, entry.File, entry.OutputFile, entry.Checksum); err != nil {
					logging.Fatal(err)
					continue
				}

				// Update checksum after we signed it
				checksum := sbctl.ChecksumFile(entry.File)
				entry.Checksum = checksum
				files[entry.File] = entry
				sbctl.WriteFileDatabase(sbctl.DBPath, files)

			}
			return nil
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
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) < 1 {
				logging.Println("Need to specify file")
				os.Exit(1)
			}
			files, err := sbctl.ReadFileDatabase(sbctl.DBPath)
			if err != nil {
				return err
			}
			if _, ok := files[args[0]]; !ok {
				logging.Print("File %s doesn't exist in database!\n", args[0])
				os.Exit(1)
			}
			delete(files, args[0])
			sbctl.WriteFileDatabase(sbctl.DBPath, files)
			return nil
		},
	}
}

func verifyCmd() *cobra.Command {
	return &cobra.Command{
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
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) < 1 {
				logging.Print("Requires a file to sign...\n")
				os.Exit(1)
			}
			checkFiles := []string{amducode, intelucode, splashImg, osRelease, efiStub, kernelImg, cmdline, initramfs}
			for _, path := range checkFiles {
				if path == "" {
					continue
				}
				if _, err := os.Stat(path); os.IsNotExist(err) {
					logging.Print("%s does not exist!\n", path)
					os.Exit(1)
				}
			}
			bundle := sbctl.NewBundle()
			output, err := filepath.Abs(args[0])
			if err != nil {
				return err
			}
			// Fail early if user wants to save bundle but doesn't have permissions
			var bundles sbctl.Bundles
			if save {
				// "err" needs to have been declared before this, otherwise it's necessary
				// to use ":=", which shadows the "bundles" variable
				bundles, err = sbctl.ReadBundleDatabase(sbctl.BundleDBPath)
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
			if err = sbctl.CreateBundle(*bundle); err != nil {
				return err
			}
			if save {
				bundles[bundle.Output] = bundle
				sbctl.WriteBundleDatabase(sbctl.BundleDBPath, bundles)
				sbctl.FormatBundle(bundle.Output, bundle)
			}
			return nil
		},
	}
	esp := sbctl.GetESP()
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
	f.BoolVarP(&save, "save", "s", false, "save bundle to the database")
	return cmd
}

func generateBundlesCmd() *cobra.Command {
	var sign bool
	cmd := &cobra.Command{
		Use:   "generate-bundles",
		Short: "Generate all EFI stub bundles",
		RunE: func(cmd *cobra.Command, args []string) error {
			return sbctl.GenerateAllBundles(sign)
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
		RunE: func(cmd *cobra.Command, args []string) error {
			_, err := sbctl.ListBundles()
			if err != nil {
				return err
			}
			return nil
		},
	}
}

func removeBundleCmd() *cobra.Command {
	return &cobra.Command{
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
	cmds := []*cobra.Command{
		createKeysCmd(),
		enrollKeysCmd(),
		signCmd(),
		signAllCmd(),
		verifyCmd(),
		bundleCmd(),
		generateBundlesCmd(),
		removeBundleCmd(),
		listBundlesCmd(),
		removeFileCmd(),
	}
	for _, c := range cmds {
		rootCmd.AddCommand(c)
	}

	completionCmd := &cobra.Command{Use: "completion"}
	completionCmd.AddCommand(completionBashCmd())
	completionCmd.AddCommand(completionZshCmd())
	completionCmd.AddCommand(completionFishCmd())
	rootCmd.AddCommand(completionCmd)

	for _, cmd := range CliCommands {
		baseFlags(cmd.Cmd)
		rootCmd.AddCommand(cmd.Cmd)
	}

	rootCmd.SetFlagErrorFunc(func(cmd *cobra.Command, err error) error {
		cmd.Println(err)
		cmd.Println(cmd.UsageString())
		return ErrSilent
	})
	if err := rootCmd.Execute(); err != nil {
		if strings.HasPrefix(err.Error(), "unknown comman") {
			logging.Println(err.Error())
		} else if errors.Is(err, os.ErrPermission) {
			logging.Error(fmt.Errorf("sbtl requires root to run: %w", err))
		} else if !errors.Is(err, ErrSilent) {
			logging.Fatal(err)
		}
		os.Exit(1)
	}
}
