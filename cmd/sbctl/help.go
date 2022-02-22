package main

import (
	"log"
	// "os"

	"github.com/spf13/cobra"
	"github.com/spf13/cobra/doc"
)

var helpCmd = &cobra.Command{
	Use:   "help",
	Short: "TODO",
	RunE:  RunHelp,
}

func RunHelp(cmd *cobra.Command, args []string) error {
	header := &doc.GenManHeader{
		Title:   "sbctl",
		Section: "8",
	}
	err := doc.GenManTree(rootCmd, header, "/tmp/sbctl")
	if err != nil {
		log.Fatal(err)
	}

	// err = doc.GenMan(rootCmd, header, os.Stdout)
	// if err != nil {
	// 	log.Fatal(err)
	// }
	return nil
}

func init() {
	CliCommands = append(CliCommands, cliCommand{
		Cmd: helpCmd,
	})
}
