package main

import (
	"os"

	"github.com/spf13/cobra"
)

var completionCmd = &cobra.Command{Use: "completion"}

func completionBashCmd() *cobra.Command {
	var completionCmd = &cobra.Command{
		Use:    "bash",
		Hidden: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return rootCmd.GenBashCompletion(os.Stdout)
		},
	}
	return completionCmd
}

func completionZshCmd() *cobra.Command {
	var completionCmd = &cobra.Command{
		Use:    "zsh",
		Hidden: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return rootCmd.GenZshCompletion(os.Stdout)
		},
	}
	return completionCmd
}

func completionFishCmd() *cobra.Command {
	var completionCmd = &cobra.Command{
		Use:    "fish",
		Hidden: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return rootCmd.GenFishCompletion(os.Stdout, true)
		},
	}
	return completionCmd
}

func init() {
	completionCmd.AddCommand(completionBashCmd())
	completionCmd.AddCommand(completionZshCmd())
	completionCmd.AddCommand(completionFishCmd())
	CliCommands = append(CliCommands, cliCommand{
		Cmd: completionCmd,
	})
}
