package sbctl

import (
	"io/ioutil"
	"log"
	"os"
	"path/filepath"

	"github.com/foxboron/sbctl/logging"
	"github.com/google/uuid"
)

func CreateUUID() []byte {
	id, err := uuid.NewRandom()
	if err != nil {
		log.Fatal(err)
	}
	return []byte(id.String())
}

func CreateGUID(output string) ([]byte, error) {
	var uuid []byte
	guidPath := filepath.Join(output, "GUID")
	if _, err := os.Stat(guidPath); os.IsNotExist(err) {
		logging.Print("Created UUID %s...", uuid)
		uuid = CreateUUID()
		err := ioutil.WriteFile(guidPath, uuid, 0600)
		if err != nil {
			return nil, err
		}
		logging.Ok("")
	} else {
		uuid, err = ioutil.ReadFile(guidPath)
		if err != nil {
			return nil, err
		}
		logging.Print("Using UUID %s...", uuid)
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
