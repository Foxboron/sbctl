package main

import (
	"fmt"

	"github.com/foxboron/sbctl"
	"github.com/foxboron/sbctl/logging"
	"github.com/spf13/cobra"
)

var listFilesCmd = &cobra.Command{
	Use: "list-files",
	Aliases: []string{
		"ls-files",
		"ls",
	},
	Short: "List enrolled files",
	RunE:  RunList,
}

type JsonFile struct {
	sbctl.SigningEntry
	IsSigned bool `json:"is_signed"`
}

func RunList(_ *cobra.Command, args []string) error {
	files := []JsonFile{}
	var isSigned bool
	err := sbctl.SigningEntryIter(
		func(s *sbctl.SigningEntry) error {
			ok, err := sbctl.VerifyFile(sbctl.DBCert, s.OutputFile)
			if err != nil {
				logging.Error(fmt.Errorf("%s: %w", s.OutputFile, err))
				logging.Error(fmt.Errorf(""))
				return nil
			}
			logging.Println(s.File)
			logging.Print("Signed:\t\t")
			if ok {
				isSigned = true
				logging.Ok("Signed")
			} else if !ok {
				isSigned = false
				logging.NotOk("Not Signed")
			}
			if s.File != s.OutputFile {
				logging.Print("Output File:\t%s\n", s.OutputFile)
			}
			logging.Println("")
			files = append(files, JsonFile{*s, isSigned})
			return nil
		},
	)
	if err != nil {
		return err
	}
	if cmdOptions.JsonOutput {
		JsonOut(files)
	}
	return nil
}

func init() {
	CliCommands = append(CliCommands, cliCommand{
		Cmd: listFilesCmd,
	})
}
