package config

import (
	"encoding/json"
	"errors"
	"os"
	"path"
	"strings"

	"github.com/foxboron/sbctl/fs"

	"github.com/foxboron/go-uefi/efi/util"
	"github.com/foxboron/go-uefi/efivarfs"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/uuid"
	"github.com/spf13/afero"

	yaml "github.com/goccy/go-yaml"
)

var (
	DatabasePath string
)

type FileConfig struct {
	Path   string `json:"path"`
	Output string `json:"output,omitempty"`
}

type KeyConfig struct {
	Privkey     string `json:"privkey"`
	Pubkey      string `json:"pubkey"`
	Type        string `json:"type"`
	Description string `json:"description,omitempty"`
}

type Keys struct {
	PK  *KeyConfig `json:"pk"`
	KEK *KeyConfig `json:"kek"`
	Db  *KeyConfig `json:"db"`
}

func (k *Keys) GetKeysConfigs() []*KeyConfig {
	return []*KeyConfig{
		k.PK,
		k.KEK,
		k.Db,
	}
}

type Config struct {
	Keydir     string        `json:"keydir"`
	GUID       string        `json:"guid"`
	FilesDb    string        `json:"files_db"`
	BundlesDb  string        `json:"bundles_db"`
	VendorKeys []string      `json:"vendor_keys,omitempty"`
	Files      []*FileConfig `json:"files,omitempty"`
	Keys       *Keys         `json:"keys"`
}

func (c *Config) GetGUID(vfs afero.Fs) (*util.EFIGUID, error) {
	b, err := fs.ReadFile(vfs, c.GUID)
	if err != nil {
		return nil, err
	}
	u, err := uuid.ParseBytes(b)
	if err != nil {
		return nil, err
	}
	guid := util.StringToGUID(u.String())
	return guid, err
}

func DefaultConfig() *Config {
	conf := &Config{
		GUID:      "/var/lib/sbctl/GUID",
		Keydir:    "/var/lib/sbctl/keys",
		FilesDb:   "/var/lib/sbctl/files.db",
		BundlesDb: "/var/lib/sbctl/bundles.db",
	}
	conf.Keys = &Keys{
		PK: &KeyConfig{
			Privkey: path.Join(conf.Keydir, "PK", "PK.key"),
			Pubkey:  path.Join(conf.Keydir, "PK", "PK.pem"),
			Type:    "file",
		},
		KEK: &KeyConfig{
			Privkey: path.Join(conf.Keydir, "KEK", "KEK.key"),
			Pubkey:  path.Join(conf.Keydir, "KEK", "KEK.pem"),
			Type:    "file",
		},
		Db: &KeyConfig{
			Privkey: path.Join(conf.Keydir, "db", "db.key"),
			Pubkey:  path.Join(conf.Keydir, "db", "db.pem"),
			Type:    "file",
		},
	}
	return conf
}

func NewConfig(b []byte) (*Config, error) {
	conf := DefaultConfig()
	if err := yaml.Unmarshal(b, conf); err != nil {
		return nil, err
	}
	return conf, nil
}

// Key creation is going to require differen callbacks to we abstract them away
type State struct {
	Fs       afero.Fs
	TPM      func() transport.TPMCloser
	Config   *Config
	Efivarfs *efivarfs.Efivarfs
}

func (s *State) IsInstalled() bool {
	if _, err := s.Fs.Stat(s.Config.Keydir); errors.Is(err, os.ErrNotExist) {
		return false
	}
	return true
}

func (s *State) MarshalJSON() ([]byte, error) {
	return json.Marshal(
		map[string]any{
			"installed": s.IsInstalled(),
			// We don't want the config embedded probably
			// "landlock": s.HasLandlock(),
			// "config":    s.Config,
		},
	)
}
