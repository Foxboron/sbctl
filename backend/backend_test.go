package backend

import (
	"fmt"
	"log"
	"testing"

	"github.com/foxboron/sbctl/config"
	"github.com/foxboron/sbctl/hierarchy"
	"github.com/spf13/afero"
)

func TestCreateKeys(t *testing.T) {
	c := &config.Config{
		Keydir: t.TempDir(),
		Keys: &config.Keys{
			PK: &config.KeyConfig{
				Type: "file",
			},
			KEK: &config.KeyConfig{},
			Db:  &config.KeyConfig{},
		},
	}
	state := &config.State{
		Fs:     afero.NewOsFs(),
		Config: c,
	}
	hier, err := CreateKeys(state)
	if err != nil {
		t.Fatalf("%v", err)
	}

	err = hier.SaveKeys(afero.NewOsFs(), c.Keydir)
	if err != nil {
		t.Fatalf("%v", err)
	}

	key, err := GetKeyBackend(state, hierarchy.PK)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(key.Certificate().Subject.CommonName)
}
