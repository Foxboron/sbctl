package sbctl

import (
	"encoding/json"
	"fmt"
	"path/filepath"

	"github.com/foxboron/sbctl/config"
	"github.com/foxboron/sbctl/fs"
	"github.com/foxboron/sbctl/lsm"
	"github.com/landlock-lsm/go-landlock/landlock"

	"github.com/spf13/afero"
)

type SigningEntry struct {
	File       string `json:"file"`
	OutputFile string `json:"output_file"`
}

type SigningEntries map[string]*SigningEntry

func ReadFileDatabase(vfs afero.Fs, dbpath string) (SigningEntries, error) {
	f, err := ReadOrCreateFile(vfs, dbpath)
	if err != nil {
		return nil, err
	}

	files := make(SigningEntries)
	if len(f) == 0 {
		return files, nil
	}
	if err = json.Unmarshal(f, &files); err != nil {
		return nil, fmt.Errorf("failed to parse json: %v", err)
	}

	return files, nil
}

func WriteFileDatabase(vfs afero.Fs, dbpath string, files SigningEntries) error {
	data, err := json.MarshalIndent(files, "", "    ")
	if err != nil {
		return err
	}
	err = fs.WriteFile(vfs, dbpath, data, 0644)
	if err != nil {
		return err
	}
	return nil
}

func SigningEntryIter(state *config.State, fn func(s *SigningEntry) error) error {
	files, err := ReadFileDatabase(state.Fs, state.Config.FilesDb)
	if err != nil {
		return fmt.Errorf("couldn't open database %v: %w", state.Config.FilesDb, err)
	}
	for _, s := range files {
		if err := fn(s); err != nil {
			return err
		}
	}
	return nil
}

func LandlockFromFileDatabase(state *config.State) error {
	var llrules []landlock.Rule
	files, err := ReadFileDatabase(state.Fs, state.Config.FilesDb)
	if err != nil {
		return err
	}
	for _, entry := range files {
		if entry.File == entry.OutputFile {
			// If file is the same as output, set RW+Trunc on file
			llrules = append(llrules,
				lsm.TruncFile(entry.File).IgnoreIfMissing(),
			)
		}
		if entry.File != entry.OutputFile {
			// Set input file to RO, ignore if missing so we can bubble a useable
			// error to the user
			llrules = append(llrules, landlock.ROFiles(entry.File).IgnoreIfMissing())

			// Check if output file exists
			// if it does we set RW on the file directly
			// if it doesnt, we set RW on the directory
			if ok, _ := afero.Exists(state.Fs, entry.OutputFile); ok {
				llrules = append(llrules, lsm.TruncFile(entry.OutputFile))
			} else {
				llrules = append(llrules, landlock.RWDirs(filepath.Dir(entry.OutputFile)))
			}
		}
	}
	lsm.RestrictAdditionalPaths(llrules...)
	return nil
}
