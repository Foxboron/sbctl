package main

import (
	"fmt"

	"github.com/foxboron/sbctl"
	"github.com/foxboron/sbctl/fs"
	"github.com/foxboron/sbctl/logging"
	"github.com/foxboron/sbctl/stringset"
	"github.com/spf13/cobra"
)

type CustomKeyCmdOptions struct {
	Partial     stringset.StringSet
	CustomBytes string
}

var (
	customKeyCmdOptions = CustomKeyCmdOptions{
		Partial: stringset.StringSet{Allowed: []string{"PK", "KEK", "db", "dbx"}},
	}

	customKeyCmd = &cobra.Command{
		Use:   "custom-key",
		Short: "Enroll custom key to EFI",
		RunE:  RunCustomKey,
	}
)

// write custom key from a filePath into an efivar
func customKey(hierarchy string, filePath string) error {
	customBytes, err := fs.ReadFile(filePath)
	if err != nil {
		return err
	}

	switch hierarchy {
	case "db":
		fallthrough
	case "dbx":
		fallthrough
	case "KEK":
		fallthrough
	case "PK":
		if err := sbctl.EnrollCustom(customBytes, hierarchy); err != nil {
			return err
		}
	default:
		return fmt.Errorf("unsupported key type to enroll: %s, allowed values are: %s", hierarchy, customKeyCmdOptions.Partial.Type())
	}

	return nil
}

func RunCustomKey(cmd *cobra.Command, args []string) error {
	if customKeyCmdOptions.Partial.Value == "" {
		return fmt.Errorf("missing hierarchy to enroll bytes to (use --partial)")
	}

	if customKeyCmdOptions.CustomBytes == "" {
		return fmt.Errorf("missing path to custom bytes (use --custom-bytes)")
	}

	logging.Print("Enrolling custom key to EFI variables...")

	if err := customKey(customKeyCmdOptions.Partial.Value, customKeyCmdOptions.CustomBytes); err != nil {
		logging.NotOk("")

		return fmt.Errorf("couldn't roll out custom bytes from %s for hierarchy %s: %w", customKeyCmdOptions.CustomBytes, customKeyCmdOptions.Partial, err)
	}

	logging.Ok("\nEnrolled key to the EFI variables!")

	return nil
}

func customKeyCmdFlags(cmd *cobra.Command) {
	f := cmd.Flags()
	f.VarPF(&customKeyCmdOptions.Partial, "partial", "p", "enroll a partial key")
	f.StringVarP(&customKeyCmdOptions.CustomBytes, "custom-bytes", "c", "", "path to the bytefile to be enrolled to efi")
}

func init() {
	customKeyCmdFlags(customKeyCmd)
	CliCommands = append(CliCommands, cliCommand{
		Cmd: customKeyCmd,
	})
}
