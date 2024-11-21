package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/foxboron/sbctl"
	"github.com/foxboron/sbctl/backend"
	"github.com/foxboron/sbctl/config"
	"github.com/foxboron/sbctl/hierarchy"
	"github.com/foxboron/sbctl/logging"
	"github.com/foxboron/sbctl/lsm"
	"github.com/landlock-lsm/go-landlock/landlock"
	"github.com/spf13/afero"
	"github.com/spf13/cobra"
)

type VerifiedFile struct {
	FileName       string         `json:"file_name"`
	// IsSigned should be set to one of these values:
	//   -  0: "unsigned"
	//   -  1: "signed"
	//   - -1: "file does not exist"
	IsSigned       int8           `json:"is_signed"`
}

var (
	ErrInvalidHeader = errors.New("invalid pe header")
	verifyCmd        = &cobra.Command{
		Use:   "verify",
		Short: "Find and check if files in the ESP are signed or not",
		RunE:  RunVerify,
	}
	verifiedFiles      []VerifiedFile
)

func VerifyOneFile(state *config.State, f string) error {
	o, err := state.Fs.Open(f)
	fileentry := VerifiedFile{FileName: f, IsSigned: 0}
	if errors.Is(err, os.ErrNotExist) {
		logging.Warn("%s does not exist", f)
		fileentry.IsSigned = -1
		verifiedFiles = append(verifiedFiles, fileentry)
		return nil
	} else if errors.Is(err, os.ErrPermission) {
		logging.Warn("%s permission denied. Can't read file\n", f)
		return nil
	}
	defer o.Close()
	ok, err := sbctl.CheckMSDos(o)
	if err != nil {
		logging.Error(fmt.Errorf("failed to read file %s: %s", f, err))
	}
	if !ok {
		return ErrInvalidHeader
	}

	kh, err := backend.GetKeyHierarchy(state.Fs, state)
	if err != nil {
		return err
	}

	ok, err = sbctl.VerifyFile(state, kh, hierarchy.Db, f)
	if err != nil {
		return err
	}

	if ok {
		logging.Ok("%s is signed", f)
		fileentry.IsSigned = 1
	} else {
		logging.NotOk("%s is not signed", f)
	}
	verifiedFiles = append(verifiedFiles, fileentry)

	return nil
}

func RunVerify(cmd *cobra.Command, args []string) error {
	state := cmd.Context().Value(stateDataKey{}).(*config.State)

	// Exit early if we can't verify files
	espPath, err := sbctl.GetESP(state.Fs)
	if err != nil {
		return err
	}

	if state.Config.Landlock {
		lsm.RestrictAdditionalPaths(
			landlock.RWDirs(espPath),
		)
		if err := sbctl.LandlockFromFileDatabase(state); err != nil {
			return err
		}
		if err := lsm.Restrict(); err != nil {
			return err
		}
	}

	if len(args) > 0 {
		for _, file := range args {
			if err := VerifyOneFile(state, file); err != nil {
				if errors.Is(ErrInvalidHeader, err) {
					logging.Error(fmt.Errorf("%s is not a valid EFI binary", file))
					return nil
				}
				return err
			}
		}
		if cmdOptions.JsonOutput {
			return JsonOut(verifiedFiles)
		}
		return nil
	}
	logging.Print("Verifying file database and EFI images in %s...\n", espPath)
	if err := sbctl.SigningEntryIter(state, func(file *sbctl.SigningEntry) error {
		sbctl.AddChecked(file.OutputFile)
		if err := VerifyOneFile(state, file.OutputFile); err != nil {
			return err
		}
		return nil
	}); err != nil {
		return err
	}

	if err := afero.Walk(state.Fs, espPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			logging.Error(fmt.Errorf("failed to read path %s: %s", path, err))
		}
		if fi, _ := state.Fs.Stat(path); fi.IsDir() {
			return nil
		}
		if sbctl.InChecked(path) {
			return nil
		}
		if err = VerifyOneFile(state, path); err != nil {
			// We are scanning the ESP, so ignore invalid files
			if errors.Is(ErrInvalidHeader, err) {
				return nil
			}
			logging.Error(fmt.Errorf("failed to verify file %s: %s", path, err))
		}
		return nil
	}); err != nil {
		return err
	}
	if cmdOptions.JsonOutput {
		return JsonOut(verifiedFiles)
	}
	return nil
}

func init() {
	CliCommands = append(CliCommands, cliCommand{
		Cmd: verifyCmd,
	})
}
