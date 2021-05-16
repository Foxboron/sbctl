package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/foxboron/sbctl"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
)

var listFilesCmd = &cobra.Command{
	Use:   "list-files",
	Short: "List enrolled files",
	RunE:  RunList,
}

func ListJsonOut(v interface{}) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return errors.Wrapf(err, "could not marshal json")
	}
	fmt.Fprintf(os.Stdout, string(b))
	return nil
}

func RunList(_ *cobra.Command, args []string) error {
	files, _ := sbctl.ListFiles()
	if cmdOptions.JsonOutput {
		ListJsonOut(files)
	}
	return nil
}

func init() {
	CliCommands = append(CliCommands, cliCommand{
		Cmd: listFilesCmd,
	})
}
