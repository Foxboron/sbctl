package main

import (
	"bytes"
	"encoding/json"
	"os"

	"testing/fstest"

	"github.com/foxboron/go-uefi/efi/efitest"
	"github.com/foxboron/sbctl/fs"
	"github.com/foxboron/sbctl/logging"
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

// Set filesystems for sbctl and go-uefi
func SetFS(files ...fstest.MapFS) {
	f := efitest.NewFS().
		With(files...).
		SetFS()
	fs.SetFS(f.ToAfero())
}
