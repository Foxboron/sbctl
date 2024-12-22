package backend

import (
	"fmt"
	"github.com/foxboron/sbctl/hierarchy"
	"log"
	"testing"

	"github.com/foxboron/sbctl/config"
	"github.com/spf13/afero"
)

func TestCreateKeys(t *testing.T) {
	t.Logf("Testing create keys\n")
	c := &config.Config{
		Keydir: t.TempDir(),
		Keys: &config.Keys{
			PK: &config.KeyConfig{
				Type: "yubikey",
			},
			KEK: &config.KeyConfig{
				Type: "yubikey",
			},
			Db: &config.KeyConfig{
				Type: "yubikey",
			},
		},
	}
	state := &config.State{
		Fs: afero.NewOsFs(),
		YubikeySigKeys: &config.YubiConfig{
			Pub:  nil,
			Priv: nil,
		},
		Config: c,
	}
	hier, err := CreateKeys(state)
	if err != nil {
		t.Fatalf("%v", err)
	}
	t.Logf("Created keys: %v\n", hier)

	err = hier.SaveKeys(afero.NewOsFs(), c.Keydir)
	if err != nil {
		t.Fatalf("%v", err)
	}

	key, err := GetKeyBackend(state, hierarchy.PK)
	if err != nil {
		log.Fatal(err)
	}
	signer := key.Signer()
	fmt.Printf("%v\n", signer)
	fmt.Println(key.Certificate().Subject.CommonName)
}
