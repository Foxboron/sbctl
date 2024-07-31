package main

import (
	"fmt"

	"github.com/foxboron/sbctl"
	"github.com/foxboron/sbctl/backend"
	"github.com/foxboron/sbctl/config"
	"github.com/foxboron/sbctl/hierarchy"
	"github.com/foxboron/sbctl/logging"
	"github.com/foxboron/sbctl/lsm"
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

func RunList(cmd *cobra.Command, args []string) error {
	state := cmd.Context().Value(stateDataKey{}).(*config.State)

	if state.Config.Landlock {
		if err := sbctl.LandlockFromFileDatabase(state); err != nil {
			return err
		}
		if err := lsm.Restrict(); err != nil {
			return err
		}
	}

	files := []JsonFile{}
	var isSigned bool
	err := sbctl.SigningEntryIter(state,
		func(s *sbctl.SigningEntry) error {
			kh, err := backend.GetKeyHierarchy(state.Fs, state)
			if err != nil {
				return err
			}
			ok, err := sbctl.VerifyFile(state, kh, hierarchy.Db, s.OutputFile)
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
		return JsonOut(files)
	}
	return nil
}

func init() {
	CliCommands = append(CliCommands, cliCommand{
		Cmd: listFilesCmd,
	})
}
