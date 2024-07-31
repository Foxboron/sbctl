package main

import (
	"archive/tar"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/foxboron/sbctl"
	"github.com/foxboron/sbctl/config"
	"github.com/foxboron/sbctl/logging"
	"github.com/goccy/go-yaml"
	"github.com/spf13/cobra"
)

type DebugCmdOptions struct {
	Output string
}

var (
	debugCmdOptions = DebugCmdOptions{}
	debugCmd        = &cobra.Command{
		Use:    "debug",
		Short:  "Produce debug information for sbctl",
		Hidden: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			state := cmd.Context().Value(stateDataKey{}).(*config.State)
			return ProduceDebugInformation(state)
		},
	}
)

func ProduceDebugInformation(state *config.State) error {
	output, err := filepath.Abs(debugCmdOptions.Output)
	if err != nil {
		return err
	}
	logging.Print("Creating a debug dump to %s...\n", output)
	file, err := os.Create(output)
	if err != nil {
		return fmt.Errorf("could not produce debug tarball: %v", err)
	}

	defer file.Close()
	gzipWriter := gzip.NewWriter(file)
	defer gzipWriter.Close()

	tw := tar.NewWriter(gzipWriter)
	defer tw.Close()

	writeTw := func(n string, b []byte) error {
		hdr := &tar.Header{
			Name: filepath.Base(n),
			Mode: 0600,
			Size: int64(len(b)),
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		if _, err := tw.Write(b); err != nil {
			return err
		}
		return nil
	}

	efifiles, err := filepath.Glob("/sys/firmware/efi/efivars/*-8be4df61-93ca-11d2-aa0d-00e098032b8c")
	if err != nil {
		return err
	}
	efifiles = append(efifiles,
		"/sys/firmware/efi/efivars/dbx-d719b2cb-3d3a-4596-a3bc-dad00e67656f",
		"/sys/firmware/efi/efivars/db-d719b2cb-3d3a-4596-a3bc-dad00e67656f",
	)

	for _, f := range efifiles {
		b, err := os.ReadFile(f)
		if err != nil {
			log.Print(err)
			continue
		}

		if err := writeTw(f, b); err != nil {
			return err
		}
	}

	stateb, err := json.Marshal(state)
	if err != nil {
		return err
	}
	if err := writeTw("state.json", stateb); err != nil {
		return err
	}

	configby, err := yaml.Marshal(state.Config)
	if err != nil {
		return err
	}
	if err := writeTw("config.yaml", configby); err != nil {
		return err
	}

	configbj, err := json.Marshal(state.Config)
	if err != nil {
		return err
	}
	if err := writeTw("config.json", configbj); err != nil {
		return err
	}

	if err := writeTw("VERSION", []byte(sbctl.Version)); err != nil {
		return err
	}
	return nil
}

func debugCmdFlags(cmd *cobra.Command) {
	f := cmd.Flags()
	f.StringVarP(&debugCmdOptions.Output, "output", "o", "sbctl_debug.tar.gz", "debug output")
}

func init() {
	debugCmdFlags(debugCmd)
	CliCommands = append(CliCommands, cliCommand{
		Cmd: debugCmd,
	})
}
