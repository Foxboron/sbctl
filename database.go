package sbctl

import (
	"encoding/json"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
)

type SigningEntry struct {
	File       string `json:"file"`
	OutputFile string `json:"output_file"`
	Checksum   string `json:"checksum"`
}

type SigningEntries map[string]*SigningEntry

func ReadFileDatabase(dbpath string) (SigningEntries, error) {
	// Try to access or create dbpath itself
	f, err := ioutil.ReadFile(dbpath)
	if err != nil {
		// Errors will mainly happen due to permissions or non-existing file
		if os.IsNotExist(err) {
			// First, guarantee the directory's existence
			// os.MkdirAll simply returns nil if the directory already exists
			dbpathDir := filepath.Dir(dbpath)
			if err = os.MkdirAll(dbpathDir, os.ModePerm); err != nil {
				if os.IsPermission(err) {
					warning.Printf(rootMsg)
				}
				return nil, err
			}

			file, err := os.Create(dbpath)
			if err != nil {
				if os.IsPermission(err) {
					warning.Printf(rootMsg)
				}
				return nil, err
			}
			file.Close()

			// Create zero-length f, which is equivalent to what would be read from empty file
			f = make([]byte, 0)
		} else {
			if os.IsPermission(err) {
				warning.Printf(rootMsg)
			}

			return nil, err
		}
	}

	files := make(SigningEntries)
	json.Unmarshal(f, &files)

	return files, nil
}

func WriteFileDatabase(dbpath string, files SigningEntries) {
	data, err := json.MarshalIndent(files, "", "    ")
	if err != nil {
		log.Fatal(err)
	}
	err = ioutil.WriteFile(dbpath, data, 0644)
	if err != nil {
		log.Fatal(err)
	}
}
