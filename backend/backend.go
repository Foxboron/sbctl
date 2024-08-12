package backend

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/foxboron/go-uefi/authenticode"
	"github.com/foxboron/go-uefi/efivar"
	"github.com/foxboron/sbctl/config"
	"github.com/foxboron/sbctl/fs"
	"github.com/foxboron/sbctl/hierarchy"
	"github.com/spf13/afero"
)

type BackendType string

const (
	FileBackend    BackendType = "file"
	YubikeyBackend BackendType = "yubikey"
	TPMBackend     BackendType = "tpm"
)

type KeyBackend interface {
	CertificateBytes() []byte
	PrivateKeyBytes() []byte
	Signer() crypto.Signer
	Certificate() *x509.Certificate
	Type() BackendType
	Description() string
}

type KeyHierarchy struct {
	PK  KeyBackend
	KEK KeyBackend
	Db  KeyBackend
	// We need the callbacks
	state *config.State
}

func (k *KeyHierarchy) GetConfig(keydir string) *config.Keys {
	return &config.Keys{
		PK: &config.KeyConfig{
			Privkey: filepath.Join(keydir, "PK/PK.key"),
			Pubkey:  filepath.Join(keydir, "PK/PK.pem"),
			Type:    string(k.PK.Type()),
		},
		KEK: &config.KeyConfig{
			Privkey: filepath.Join(keydir, "KEK/KEK.key"),
			Pubkey:  filepath.Join(keydir, "KEK/KEK.pem"),
			Type:    string(k.KEK.Type()),
		},
		Db: &config.KeyConfig{
			Privkey: filepath.Join(keydir, "db/db.key"),
			Pubkey:  filepath.Join(keydir, "db/db.pem"),
			Type:    string(k.Db.Type()),
		},
	}
}

func NewKeyHierarchy(state *config.State) *KeyHierarchy {
	return &KeyHierarchy{
		state: state,
	}
}

var (
	ErrAlreadySigned = errors.New("already signed file")
)

func (k *KeyHierarchy) GetKeyBackend(e efivar.Efivar) KeyBackend {
	switch e {
	case efivar.PK:
		return k.PK
	case efivar.KEK:
		return k.KEK
	case efivar.Db:
		return k.Db
		// case efivar.Dbx:
		// 	return k.Dbx
	default:
		panic("invalid key hierarchy")
	}
}

func (k *KeyHierarchy) SaveKey(vfs afero.Fs, hier hierarchy.Hierarchy, keydir string) error {
	writeFile := func(file string, b []byte) error {
		if err := vfs.MkdirAll(filepath.Dir(file), os.ModePerm); err != nil {
			return err
		}
		if err := fs.WriteFile(vfs, file, b, 0o400); err != nil {
			return err
		}
		return nil
	}
	key := k.GetKeyBackend(hier.Efivar())
	path := filepath.Join(keydir, hier.String())
	keyname := filepath.Join(path, fmt.Sprintf("%s.key", hier.String()))
	certname := filepath.Join(path, fmt.Sprintf("%s.pem", hier.String()))
	if err := writeFile(keyname, key.PrivateKeyBytes()); err != nil {
		return err
	}
	if err := writeFile(certname, key.CertificateBytes()); err != nil {
		return err
	}
	return nil
}

func (k *KeyHierarchy) SaveKeys(fs afero.Fs, keydir string) error {
	if err := k.SaveKey(fs, hierarchy.PK, keydir); err != nil {
		return err
	}
	if err := k.SaveKey(fs, hierarchy.KEK, keydir); err != nil {
		return err
	}
	if err := k.SaveKey(fs, hierarchy.Db, keydir); err != nil {
		return err
	}
	return nil
}

func (k *KeyHierarchy) RotateKeyWithBackend(hier hierarchy.Hierarchy, backend BackendType) error {
	var err error
	switch hier {
	case hierarchy.PK:
		k.PK, err = createKey(k.state, string(backend), hier, k.PK.Description())
	case hierarchy.KEK:
		k.KEK, err = createKey(k.state, string(backend), hier, k.KEK.Description())
	case hierarchy.Db:
		k.Db, err = createKey(k.state, string(backend), hier, k.Db.Description())
	}
	return err
}

func (k *KeyHierarchy) RotateKey(hier hierarchy.Hierarchy) error {
	return k.RotateKeyWithBackend(hier, k.GetKeyBackend(hier.Efivar()).Type())
}

func (k *KeyHierarchy) RotateKeys() error {
	if err := k.RotateKey(hierarchy.PK); err != nil {
		return err
	}
	if err := k.RotateKey(hierarchy.KEK); err != nil {
		return err
	}
	if err := k.RotateKey(hierarchy.Db); err != nil {
		return err
	}
	return nil
}

func (k *KeyHierarchy) VerifyFile(hier hierarchy.Hierarchy, r io.ReaderAt) (bool, error) {
	kk := k.GetKeyBackend(hier.Efivar())

	peBinary, err := authenticode.Parse(r)
	if err != nil {
		return false, err
	}

	sigs, err := peBinary.Signatures()
	if err != nil {
		return false, err
	}

	if len(sigs) == 0 {
		return false, nil
	}

	ok, err := peBinary.Verify(kk.Certificate())
	if errors.Is(err, authenticode.ErrNoValidSignatures) {
		return false, nil
	} else if err != nil {
		return false, err
	}
	return ok, nil
}

func (k *KeyHierarchy) SignFile(hier hierarchy.Hierarchy, peBinary *authenticode.PECOFFBinary) ([]byte, error) {
	kk := k.GetKeyBackend(hier.Efivar())
	signer := kk.Signer()

	_, err := peBinary.Sign(signer, kk.Certificate())
	if err != nil {
		return nil, err
	}
	return peBinary.Bytes(), nil
}

func createKey(state *config.State, backend string, hier hierarchy.Hierarchy, desc string) (KeyBackend, error) {
	if desc == "" {
		desc = hier.Description()
	}
	switch backend {
	case "file", "":
		return NewFileKey(hier, desc)
	case "tpm":
		return NewTPMKey(state.TPM, desc)
	default:
		return NewFileKey(hier, desc)
	}
}

func CreateKeys(state *config.State) (*KeyHierarchy, error) {
	var hier KeyHierarchy
	var err error

	c := state.Config
	hier.PK, err = createKey(state, c.Keys.PK.Type, hierarchy.PK, c.Keys.PK.Description)
	if err != nil {
		return nil, err
	}

	hier.KEK, err = createKey(state, c.Keys.KEK.Type, hierarchy.KEK, c.Keys.KEK.Description)
	if err != nil {
		return nil, err
	}

	hier.Db, err = createKey(state, c.Keys.Db.Type, hierarchy.Db, c.Keys.Db.Description)
	if err != nil {
		return nil, err
	}

	return &hier, nil
}

func readKey(state *config.State, keydir string, kc *config.KeyConfig, hier hierarchy.Hierarchy) (KeyBackend, error) {
	path := filepath.Join(keydir, hier.String())
	keyname := filepath.Join(path, fmt.Sprintf("%s.key", hier.String()))
	certname := filepath.Join(path, fmt.Sprintf("%s.pem", hier.String()))

	// Read privatekey
	keyb, err := fs.ReadFile(state.Fs, keyname)
	if err != nil {
		return nil, err
	}

	// Read certificate
	pemb, err := fs.ReadFile(state.Fs, certname)
	if err != nil {
		return nil, err
	}

	t, err := GetBackendType(keyb)
	if err != nil {
		return nil, err
	}

	switch t {
	case FileBackend:
		return FileKeyFromBytes(keyb, pemb)
	case TPMBackend:
		return TPMKeyFromBytes(state.TPM, keyb, pemb)
	default:
		return nil, fmt.Errorf("unknown key")
	}
}

func GetKeyBackend(state *config.State, k hierarchy.Hierarchy) (KeyBackend, error) {
	c := state.Config
	switch k {
	case hierarchy.PK:
		return readKey(state, c.Keydir, c.Keys.PK, k)
	case hierarchy.KEK:
		return readKey(state, c.Keydir, c.Keys.KEK, k)
	case hierarchy.Db:
		return readKey(state, c.Keydir, c.Keys.Db, k)
	}
	return nil, nil
}

func GetKeyHierarchy(vfs afero.Fs, state *config.State) (*KeyHierarchy, error) {
	db, err := GetKeyBackend(state, hierarchy.Db)
	if err != nil {
		return nil, err
	}
	kek, err := GetKeyBackend(state, hierarchy.KEK)
	if err != nil {
		return nil, err
	}
	pk, err := GetKeyBackend(state, hierarchy.PK)
	if err != nil {
		return nil, err
	}
	return &KeyHierarchy{
		PK:    pk,
		KEK:   kek,
		Db:    db,
		state: state,
	}, nil
}

func GetBackendType(b []byte) (BackendType, error) {
	block, _ := pem.Decode(b)
	// TODO: Add TSS2 keys
	switch block.Type {
	case "PRIVATE KEY":
		return FileBackend, nil
	case "TSS2 PRIVATE KEY":
		return TPMBackend, nil
	default:
		return "", fmt.Errorf("unknown file type: %s", block.Type)
	}
}

// TODO: fix this
func ImportKeys(keydir string) (*KeyHierarchy, error) {
	return nil, nil
}

func InitBackendFromKeys(state *config.State, priv, pem []byte, hier hierarchy.Hierarchy) (KeyBackend, error) {
	t, err := GetBackendType(priv)
	if err != nil {
		return nil, err
	}
	switch t {
	case "file":
		return FileKeyFromBytes(priv, pem)
	case "tpm":
		return TPMKeyFromBytes(state.TPM, priv, pem)
	default:
		return nil, fmt.Errorf("unknown key backend: %s", t)
	}
}
