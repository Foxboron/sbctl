package sbctl

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/foxboron/go-uefi/authenticode"
	"github.com/foxboron/go-uefi/efi"
	"github.com/foxboron/sbctl/backend"
	"github.com/foxboron/sbctl/certs"
	"github.com/foxboron/sbctl/config"
	"github.com/foxboron/sbctl/fs"
	"github.com/foxboron/sbctl/hierarchy"
	"github.com/spf13/afero"
)

func EnrollCustom(customBytes []byte, efivar string) error {
	return efi.WriteEFIVariable(efivar, customBytes)
}

func VerifyFile(state *config.State, kh *backend.KeyHierarchy, ev hierarchy.Hierarchy, file string) (bool, error) {
	peFile, err := state.Fs.Open(file)
	if err != nil {
		return false, err
	}
	defer peFile.Close()
	return kh.VerifyFile(ev, peFile)
}

var ErrAlreadySigned = errors.New("already signed file")

func SignFile(state *config.State, kh *backend.KeyHierarchy, ev hierarchy.Hierarchy, file, output string) error {

	// Make sure that output is always populated by atleast the file path
	if output == "" {
		output = file
	}

	// Check file exists before we do anything
	if _, err := state.Fs.Stat(file); errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("%s does not exist", file)
	}

	// Let's check if we have signed it already AND the original file hasn't changed
	ok, err := VerifyFile(state, kh, ev, output)
	if errors.Is(err, os.ErrNotExist) && (file != output) {
		// if the file does not exist and file is not the same as output
		// then we just catch the error and continue. This is expected
		// behaviour
	} else if errors.Is(err, authenticode.ErrNoValidSignatures) {
		// If we tried to verify the file, but it has signatures but nothing signed
		// by our key, we catch the error and continue.
	} else if err != nil {
		return err
	}

	if ok {
		return ErrAlreadySigned
	}

	// We want to write the file back with correct permissions
	si, err := state.Fs.Stat(file)
	if err != nil {
		return fmt.Errorf("failed stat of file: %w", err)
	}

	peFile, err := state.Fs.Open(file)
	if err != nil {
		return err
	}
	defer peFile.Close()

	b, err := kh.SignFile(ev, peFile)
	if err != nil {
		return err
	}

	if err = fs.WriteFile(state.Fs, output, b, si.Mode()); err != nil {
		return err
	}

	return nil
}

// Map up our default keys in a struct
var SecureBootKeys = []struct {
	Key         string
	Description string
}{
	{
		Key:         "PK",
		Description: "Platform Key",
	},
	{
		Key:         "KEK",
		Description: "Key Exchange Key",
	},
	{
		Key:         "db",
		Description: "Database Key",
	},
	// {
	// 	Key:         "dbx",
	// 	Description: "Forbidden Database Key",
	// },
}

// Check if we have already intialized keys in the given output directory
func CheckIfKeysInitialized(vfs afero.Fs, output string) bool {
	for _, key := range SecureBootKeys {
		path := filepath.Join(output, key.Key)
		if _, err := vfs.Stat(path); errors.Is(err, os.ErrNotExist) {
			return false
		}
	}
	return true
}

func GetEnrolledVendorCerts() []string {
	db, err := efi.Getdb()
	if err != nil {
		return []string{}
	}
	return certs.DetectVendorCerts(db)
}
