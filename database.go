package sbctl

import (
	"encoding/json"
	"fmt"
	"os"
)

type SigningEntry struct {
	File       string `json:"file"`
	OutputFile string `json:"output_file"`
	Checksum   string `json:"checksum"`
}

type SigningEntries map[string]*SigningEntry

func ReadFileDatabase(dbpath string) (SigningEntries, error) {
	f, err := ReadOrCreateFile(dbpath)
	if err != nil {
		return nil, err
	}

	files := make(SigningEntries)
	if err = json.Unmarshal(f, &files); err != nil {
		return nil, fmt.Errorf("failed to parse json: %v", err)
	}

	return files, nil
}

func WriteFileDatabase(dbpath string, files SigningEntries) error {
	data, err := json.MarshalIndent(files, "", "    ")
	if err != nil {
		return err
	}
	err = os.WriteFile(dbpath, data, 0644)
	if err != nil {
		return err
	}
	return nil
}

func SigningEntryIter(fn func(s *SigningEntry) error) error {
	files, err := ReadFileDatabase(DBPath)
	if err != nil {
		return fmt.Errorf("couldn't open database %v: %w", DBPath, err)
	}
	for _, s := range files {
		if err := fn(s); err != nil {
			return err
		}
	}
	return nil
}
