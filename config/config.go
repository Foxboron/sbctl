package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path"
	"strings"

	"github.com/foxboron/sbctl/fs"
	"github.com/landlock-lsm/go-landlock/landlock"

	"github.com/foxboron/go-uefi/efi/util"
	"github.com/foxboron/go-uefi/efivarfs"
	"github.com/go-piv/piv-go/v2/piv"
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

// Note: Anything serialized as part of this struct will end up in a public
// debug dump at some point, probably.
type Config struct {
	Landlock    bool          `json:"landlock"`
	Datadir     string        `json:"datadir"`
	Keydir      string        `json:"keydir"`
	GUID        string        `json:"guid"`
	FilesDb     string        `json:"files_db"`
	BundlesDb   string        `json:"bundles_db"`
	DbAdditions []string      `json:"db_additions,omitempty"`
	Files       []*FileConfig `json:"files,omitempty"`
	Keys        *Keys         `json:"keys"`
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

func MkConfig(dir string) *Config {
	conf := &Config{
		Landlock:  true,
		GUID:      path.Join(dir, "GUID"),
		Keydir:    path.Join(dir, "keys"),
		FilesDb:   path.Join(dir, "files.json"),
		BundlesDb: path.Join(dir, "bundles.json"),
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

func DefaultConfig() *Config {
	return MkConfig("/var/lib/sbctl")
}

func OldConfig(dir string) *Config {
	c := MkConfig(dir)
	// Rename databases to the old names
	c.FilesDb = strings.Replace(c.FilesDb, ".json", ".db", 1)
	c.BundlesDb = strings.Replace(c.BundlesDb, ".json", ".db", 1)
	return c
}

func HasOldConfig(fs afero.Fs, dir string) bool {
	_, err := fs.Stat(dir)
	return !os.IsNotExist(err)
}

func HasConfigurationFile(fs afero.Fs, file string) bool {
	_, err := fs.Stat(file)
	return !os.IsNotExist(err)
}

func VerifyConfig(fs afero.Fs, config *Config) error {
	// TODO more validiation?
	// TODO make directory if it doesn't exist?
	// Check that config.Keydir exists
	_, err := fs.Stat(config.Keydir)
	if os.IsNotExist(err) {
		return err
	}

	return nil
}

func NewConfig(fs afero.Fs, b []byte) (*Config, error) {
	conf := &Config{}
	if err := yaml.Unmarshal(b, conf); err != nil {
		return nil, err
	}
	var newConf = new(Config)
	if conf.Datadir != "" {
		newConf = MkConfig(conf.Datadir)
	} else {
		newConf = DefaultConfig()
	}

	if err := yaml.Unmarshal(b, newConf); err != nil {
		return nil, err
	}

	// TODO
	// Should sbctl make the directories if they do not exist?
	if err := VerifyConfig(fs, newConf); err != nil {
		return nil, fmt.Errorf("invalid sbctl config; %w", err)
	}

	return newConf, nil
}

type YubiConfig struct {
	PubKeyInfo *piv.KeyInfo
	Overwrite  bool
}

// Key creation is going to require different callbacks to we abstract them away
type State struct {
	Fs             afero.Fs
	TPM            func() transport.TPMCloser
	Config         *Config
	YubikeySigKeys *YubiConfig
	Efivarfs       *efivarfs.Efivarfs
}

func (s *State) IsInstalled() bool {
	if _, err := s.Fs.Stat(s.Config.Keydir); errors.Is(err, os.ErrNotExist) {
		return false
	}
	return true
}

func (s *State) HasTPM() bool {
	return s.TPM != nil
}

func (s *State) HasLandlock() bool {
	if !s.Config.Landlock {
		return false
	}
	// Minimal test to check if we have some form of landlock available
	// TODO: This is probably not good check.
	err := landlock.V1.Restrict(
		landlock.RWDirs("/"),
	)
	return err == nil
}

func (s *State) MarshalJSON() ([]byte, error) {
	return json.Marshal(
		map[string]any{
			"installed": s.IsInstalled(),
			// We don't want the config embedded probably
			"landlock": s.HasLandlock(),
			// "config":    s.Config,
		},
	)
}
