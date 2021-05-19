package sbctl

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
)

func ChecksumFile(file string) string {
	hasher := sha256.New()
	s, err := os.ReadFile(file)
	if err != nil {
		log.Fatal(err)
	}
	hasher.Write(s)

	return hex.EncodeToString(hasher.Sum(nil))
}

func ReadOrCreateFile(filePath string) ([]byte, error) {
	// Try to access or create the file itself
	f, err := os.ReadFile(filePath)
	if err != nil {
		// Errors will mainly happen due to permissions or non-existing file
		if os.IsNotExist(err) {
			// First, guarantee the directory's existence
			// os.MkdirAll simply returns nil if the directory already exists
			fileDir := filepath.Dir(filePath)
			if err = os.MkdirAll(fileDir, os.ModePerm); err != nil {
				return nil, err
			}

			file, err := os.Create(filePath)
			if err != nil {
				return nil, err
			}
			file.Close()

			// Create zero-length f, which is equivalent to what would be read from empty file
			f = make([]byte, 0)
		} else {
			if os.IsPermission(err) {
				return nil, err
			}
			return nil, err
		}
	}

	return f, nil
}

var EfivarFSFiles = []string{
	"/sys/firmware/efi/efivars/PK-8be4df61-93ca-11d2-aa0d-00e098032b8c",
	"/sys/firmware/efi/efivars/KEK-8be4df61-93ca-11d2-aa0d-00e098032b8c",
	"/sys/firmware/efi/efivars/db-d719b2cb-3d3a-4596-a3bc-dad00e67656f",
}

var ErrImmutable = errors.New("file is immutable")
var ErrNotImmutable = errors.New("file is not immutable")

func IsImmutable(file string) error {
	f, err := os.Open(file)
	if err != nil {
		return err
	}
	attr, err := GetAttr(f)
	if err != nil {
		return err
	}
	if (attr & FS_IMMUTABLE_FL) != 0 {
		return ErrImmutable
	}
	return ErrNotImmutable
}

func CheckMSDos(path string) (bool, error) {
	r, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer r.Close()

	// We are looking for MS-DOS executables.
	// They contain "MZ" as the two first bytes
	var header [2]byte
	if _, err = io.ReadFull(r, header[:]); err != nil {
		return false, err
	}
	if !bytes.Equal(header[:], []byte{0x4d, 0x5a}) {
		return false, nil
	}
	return true, nil
}

var (
	checked = make(map[string]bool)
)

func AddChecked(path string) {
	normalized := strings.Join(strings.Split(path, "/")[2:], "/")
	checked[normalized] = true
}

func InChecked(path string) bool {
	normalized := strings.Join(strings.Split(path, "/")[2:], "/")
	return checked[normalized]
}
