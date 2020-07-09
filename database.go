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

var DBPath = filepath.Join(DatabasePath, "files.db")

func ReadFileDatabase(dbpath string) SigningEntries {
	files := make(SigningEntries)
	os.MkdirAll(DatabasePath, os.ModePerm)
	if _, err := os.Stat(DBPath); os.IsNotExist(err) {
		file, err := os.Create(DBPath)
		if err != nil {
			log.Fatal(err)
		}
		file.Close()
	}
	f, err := ioutil.ReadFile(dbpath)
	if err != nil {
		log.Fatal(err)
	}
	json.Unmarshal(f, &files)
	return files
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
