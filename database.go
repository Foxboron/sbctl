package sbctl

import (
	"encoding/json"
	"fmt"

	"github.com/foxboron/sbctl/config"
	"github.com/foxboron/sbctl/fs"
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
