package backend

import (
	"crypto"
	"crypto/x509"
	"encoding/json"
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
	"github.com/foxboron/sbctl/logging"
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
	pk  KeyBackend
	kek KeyBackend
	db  KeyBackend
	// We need the callbacks
	state *config.State
}

func (k *KeyHierarchy) GetConfig(keydir string) *config.Keys {
	keyType := func(key interface{ Type() BackendType }) string {
		if key == nil {
			return string(FileBackend)
		}
		return string(key.Type())
	}

	return &config.Keys{
		PK: &config.KeyConfig{
			Privkey: filepath.Join(keydir, "PK/PK.key"),
			Pubkey:  filepath.Join(keydir, "PK/PK.pem"),
			Type:    keyType(k.pk),
		},
		KEK: &config.KeyConfig{
			Privkey: filepath.Join(keydir, "KEK/KEK.key"),
			Pubkey:  filepath.Join(keydir, "KEK/KEK.pem"),
			Type:    keyType(k.kek),
		},
		Db: &config.KeyConfig{
			Privkey: filepath.Join(keydir, "db/db.key"),
			Pubkey:  filepath.Join(keydir, "db/db.pem"),
			Type:    keyType(k.db),
		},
	}
}

var (
	ErrAlreadySigned = errors.New("already signed file")
)

// GetKeyBackend returns the currently loaded KeyBackend of the given efivar,
// or attempts to load it from disk if none is currently loaded.
func (k *KeyHierarchy) GetKeyBackend(e efivar.Efivar) (KeyBackend, error) {
	var err error

	switch e {
	case efivar.PK:
		if k.pk == nil {
			if k.pk, err = k.ReadKey(hierarchy.PK); err != nil {
				return nil, err
			}
		}
		return k.pk, nil
	case efivar.KEK:
		if k.kek == nil {
			if k.kek, err = k.ReadKey(hierarchy.KEK); err != nil {
				return nil, err
			}
		}
		return k.kek, nil
	case efivar.Db:
		if k.db == nil {
			if k.db, err = k.ReadKey(hierarchy.Db); err != nil {
				return nil, err
			}
		}
		return k.db, nil
	default:
		panic("invalid key hierarchy")
	}
}

func (k *KeyHierarchy) UpdateKeyBackend(kb KeyBackend, hier hierarchy.Hierarchy) {
	switch hier {
	case hierarchy.PK:
		k.pk = kb
	case hierarchy.KEK:
		k.kek = kb
	case hierarchy.Db:
		k.db = kb
	}
}

// CreateKey generates private and public parts of the given hierarchy and updates its KeyBackend.
func (k *KeyHierarchy) CreateKey(backend BackendType, hier hierarchy.Hierarchy, desc string) error {
	var kb KeyBackend
	var err error

	if desc == "" {
		desc = hier.Description()
	}

	switch backend {
	case FileBackend:
		kb, err = NewFileKey(hier, desc)

	case TPMBackend:
		kb, err = NewTPMKey(k.state.TPM, desc)

	case YubikeyBackend:
		kb, err = NewYubikeyKey(k.state.Yubikey, hier)

	default:
		logging.Warn("backend '%s' unknown, falling back to '%s'", backend, FileBackend)
		kb, err = NewFileKey(hier, desc)
	}

	if err != nil {
		return err
	}

	k.UpdateKeyBackend(kb, hier)

	return nil
}

// CreateKeys generates private and public parts of the entire hierarchy and updates their KeyBackends.
func (k *KeyHierarchy) CreateKeys() error {
	var err error
	c := k.state.Config

	err = k.CreateKey(BackendType(c.Keys.PK.Type), hierarchy.PK, c.Keys.PK.Description)
	if err != nil {
		return err
	}

	err = k.CreateKey(BackendType(c.Keys.KEK.Type), hierarchy.KEK, c.Keys.KEK.Description)
	if err != nil {
		return err
	}

	err = k.CreateKey(BackendType(c.Keys.Db.Type), hierarchy.Db, c.Keys.Db.Description)
	if err != nil {
		return err
	}

	return nil
}

// TODO: fix this
func (k *KeyHierarchy) ImportKeys(keydir string) error {
	return fmt.Errorf("importing keys not implemented!")
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
	kb, err := k.GetKeyBackend(hier.Efivar())
	if err != nil {
		return err
	}
	path := filepath.Join(keydir, hier.String())
	keyname := filepath.Join(path, fmt.Sprintf("%s.key", hier.String()))
	certname := filepath.Join(path, fmt.Sprintf("%s.pem", hier.String()))
	if err := writeFile(keyname, kb.PrivateKeyBytes()); err != nil {
		return err
	}
	if err := writeFile(certname, kb.CertificateBytes()); err != nil {
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

// ReadKey loads the given hierarchy from disk and returns its KeyBackend.
func (k *KeyHierarchy) ReadKey(hier hierarchy.Hierarchy) (KeyBackend, error) {
	path := filepath.Join(k.state.Config.Keydir, hier.String())
	keyname := filepath.Join(path, fmt.Sprintf("%s.key", hier.String()))
	certname := filepath.Join(path, fmt.Sprintf("%s.pem", hier.String()))

	// Read privatekey
	keyb, err := fs.ReadFile(k.state.Fs, keyname)
	if err != nil {
		return nil, err
	}

	// Read certificate
	pemb, err := fs.ReadFile(k.state.Fs, certname)
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
		return TPMKeyFromBytes(k.state.TPM, keyb, pemb)
	case YubikeyBackend:
		return YubikeyFromBytes(k.state.Yubikey, keyb, pemb)
	default:
		return nil, fmt.Errorf("unknown key")
	}
}

// ReadKeys loads the entire hierarchy from disk and updates their KeyBackends.
func (k *KeyHierarchy) ReadKeys() error {
	var kb KeyBackend
	var err error

	if kb, err = k.ReadKey(hierarchy.PK); err != nil {
		return err
	}
	k.UpdateKeyBackend(kb, hierarchy.PK)

	if kb, err = k.ReadKey(hierarchy.KEK); err != nil {
		return err
	}
	k.UpdateKeyBackend(kb, hierarchy.KEK)

	if kb, err = k.ReadKey(hierarchy.Db); err != nil {
		return err
	}
	k.UpdateKeyBackend(kb, hierarchy.Db)

	return nil
}

func (k *KeyHierarchy) RotateKeyWithBackend(hier hierarchy.Hierarchy, backend BackendType) error {
	var err error
	switch hier {
	case hierarchy.PK:
		err = k.CreateKey(backend, hier, k.pk.Description())
	case hierarchy.KEK:
		err = k.CreateKey(backend, hier, k.kek.Description())
	case hierarchy.Db:
		err = k.CreateKey(backend, hier, k.db.Description())
	}
	return err
}

func (k *KeyHierarchy) RotateKey(hier hierarchy.Hierarchy) error {
	kb, err := k.GetKeyBackend(hier.Efivar())
	if err != nil {
		return err
	}
	return k.RotateKeyWithBackend(hier, kb.Type())
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
	kb, err := k.GetKeyBackend(hier.Efivar())
	if err != nil {
		return false, err
	}

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

	ok, err := peBinary.Verify(kb.Certificate())
	if errors.Is(err, authenticode.ErrNoValidSignatures) {
		return false, nil
	} else if err != nil {
		return false, err
	}
	return ok, nil
}

func (k *KeyHierarchy) SignFile(hier hierarchy.Hierarchy, peBinary *authenticode.PECOFFBinary) ([]byte, error) {
	kb, err := k.GetKeyBackend(hier.Efivar())
	if err != nil {
		return nil, err
	}
	signer := kb.Signer()

	_, err = peBinary.Sign(signer, kb.Certificate())
	if err != nil {
		return nil, err
	}
	return peBinary.Bytes(), nil
}

func NewKeyHierarchy(state *config.State) *KeyHierarchy {
	return &KeyHierarchy{
		state: state,
	}
}

func GetBackendType(b []byte) (BackendType, error) {
	if json.Valid(b) {
		if err := json.Unmarshal(b, &YubikeyData{}); err != nil {
			return "", fmt.Errorf("invalid yubikey data: %v", err)
		}
		return YubikeyBackend, nil
	}
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
	case "yubikey":
		return YubikeyFromBytes(state.Yubikey, priv, pem)
	default:
		return nil, fmt.Errorf("unknown key backend: %s", t)
	}
}
