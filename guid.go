package sbctl

import (
	"os"

	"github.com/foxboron/sbctl/fs"
	"github.com/google/uuid"
	"github.com/spf13/afero"
)

func CreateUUID() []byte {
	id, _ := uuid.NewRandom()
	return []byte(id.String())
}

func CreateGUID(vfs afero.Fs, guidPath string) ([]byte, error) {
	var uuid []byte
	if _, err := vfs.Stat(guidPath); os.IsNotExist(err) {
		uuid = CreateUUID()
		err := fs.WriteFile(vfs, guidPath, uuid, 0644)
		if err != nil {
			return nil, err
		}
	} else {
		uuid, err = fs.ReadFile(vfs, guidPath)
		if err != nil {
			return nil, err
		}
	}
	return uuid, nil
}
