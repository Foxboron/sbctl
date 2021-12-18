package sbctl

import (
	"os"
	"path/filepath"

	"github.com/google/uuid"
)

func CreateUUID() []byte {
	id, _ := uuid.NewRandom()
	return []byte(id.String())
}

func CreateGUID(output string) ([]byte, error) {
	var uuid []byte
	guidPath := filepath.Join(output, "GUID")
	if _, err := os.Stat(guidPath); os.IsNotExist(err) {
		uuid = CreateUUID()
		err := os.WriteFile(guidPath, uuid, 0644)
		if err != nil {
			return nil, err
		}
	} else {
		uuid, err = os.ReadFile(guidPath)
		if err != nil {
			return nil, err
		}
	}
	return uuid, nil
}

func GetGUID() (uuid.UUID, error) {
	b, err := os.ReadFile(GUIDPath)
	if err != nil {
		return [16]byte{}, err
	}
	u, err := uuid.ParseBytes(b)
	if err != nil {
		return [16]byte{}, err
	}
	return u, err
}
