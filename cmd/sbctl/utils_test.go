package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"

	"testing/fstest"

	"github.com/foxboron/go-uefi/efi/efitest"
	efs "github.com/foxboron/go-uefi/efi/fs"
	"github.com/foxboron/go-uefi/efivarfs/testfs"
	"github.com/foxboron/sbctl/config"
	"github.com/foxboron/sbctl/logging"
	"github.com/spf13/cobra"
)

func captureOutput(f func() error) ([]byte, error) {
	var buf bytes.Buffer
	logging.SetOutput(&buf)
	err := f()
	logging.SetOutput(os.Stderr)
	return buf.Bytes(), err
}

func captureJsonOutput(out any, f func() error) error {
	cmdOptions.JsonOutput = true
	output, err := captureOutput(f)
	if err != nil {
		return err
	}
	return json.Unmarshal(output, &out)
}

func SetFS(files ...fstest.MapFS) *cobra.Command {
	fs := efitest.NewFS().
		With(files...).
		ToAfero()

	// TODO: Remove and move to proper efifs implementation
	efs.SetFS(fs)

	state := &config.State{
		Fs: fs,
		Efivarfs: testfs.NewTestFS().
			With(files...).
			Open(),
		Config: config.DefaultConfig(),
	}
	cmd := &cobra.Command{}
	ctx := context.WithValue(context.Background(), stateDataKey{}, state)
	cmd.SetContext(ctx)
	return cmd
}
