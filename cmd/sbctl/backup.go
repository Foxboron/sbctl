package main

import (
	"fmt"
	"io"
	"os"
	"path"
	"strings"

	"github.com/foxboron/go-uefi/efi"
	"github.com/foxboron/sbctl"
	"github.com/foxboron/sbctl/logging"
	"github.com/spf13/cobra"
)

var backupCmd = &cobra.Command{
	Use:   "backup",
	Short: "Back up currently booted entry.",
	RunE:  RunBackup,
}

func CopyFile(sourcePath string, destPath string) error {
	srcFile, err := os.Open(sourcePath)
	if err != nil {
		return err
	}
	defer srcFile.Close()

	destFile, err := os.Create(destPath)
	if err != nil {
		return err
	}
	defer destFile.Close()

	_, err = io.Copy(destFile, srcFile)
	if err != nil {
		return err
	}

	err = destFile.Sync()
	if err != nil {
		return err
	}

	return nil
}

func GenerateBackupFilename(original string) string {
	extension := path.Ext(original)
	name := strings.TrimSuffix(original, path.Ext(original))

	return fmt.Sprintf("%s_backup%s", name, extension)
}

func RunBackup(cmd *cobra.Command, args []string) error {
	if _, err := os.Stat("/sys/firmware/efi/efivars"); os.IsNotExist(err) {
		return fmt.Errorf("system is not booted with UEFI")
	}

	name, err := efi.GetCurrentlyBootedEntry()
	if err != nil {
		return fmt.Errorf("error reading currently booted entry: %v", err)
	}

	current := fmt.Sprintf("%s/EFI/Linux/%s", sbctl.GetESP(), name)
	backup := GenerateBackupFilename(current)

	logging.Print("Backing up: %s -> %s.\n", current, backup)

	err = CopyFile(current, backup)
	if err != nil {
		return fmt.Errorf("error creating backup file: %v", err)
	}

	if !cmdOptions.JsonOutput {
		logging.Ok("Backup done.")
	}
	return nil
}

func init() {
	CliCommands = append(CliCommands, cliCommand{
		Cmd: backupCmd,
	})
}
