package sbctl

import (
	"errors"
	"os"

	"github.com/foxboron/go-uefi/efi/signature"
	"github.com/foxboron/go-uefi/efivar"
	"github.com/foxboron/go-uefi/efivarfs"
	"github.com/foxboron/sbctl/backend"
)

type EFIVariables struct {
	fs  *efivarfs.Efivarfs
	PK  *signature.SignatureDatabase
	KEK *signature.SignatureDatabase
	Db  *signature.SignatureDatabase
	Dbx *signature.SignatureDatabase
}

func (e *EFIVariables) GetSiglist(ev efivar.Efivar) *signature.SignatureDatabase {
	switch ev {
	case efivar.PK:
		return e.PK
	case efivar.KEK:
		return e.KEK
	case efivar.Db:
		return e.Db
	case efivar.Dbx:
		return e.Dbx
	}
	return nil
}

func (e *EFIVariables) EnrollKey(ev efivar.Efivar, hier *backend.KeyHierarchy) error {
	// Ensure we are using the correct signer for the backend
	var signer backend.KeyBackend
	switch ev {
	case efivar.PK:
		signer = hier.GetKeyBackend(efivar.PK)
	case efivar.KEK:
		signer = hier.GetKeyBackend(efivar.PK)
	case efivar.Db:
		signer = hier.GetKeyBackend(efivar.KEK)
	}
	// fmt.Printf("%s is signed by %s\n", ev.Name, signer.Certificate().SerialNumber.String())
	return e.fs.WriteSignedUpdate(ev, e.GetSiglist(ev), signer.Signer(), signer.Certificate())
}

func (e *EFIVariables) EnrollAllKeys(hier *backend.KeyHierarchy) error {
	if err := e.EnrollKey(efivar.Db, hier); err != nil {
		return err
	}
	if err := e.EnrollKey(efivar.KEK, hier); err != nil {
		return err
	}
	if err := e.EnrollKey(efivar.PK, hier); err != nil {
		return err
	}
	return nil
}

func NewEFIVariables(fs *efivarfs.Efivarfs) *EFIVariables {
	return &EFIVariables{
		fs:  fs,
		PK:  signature.NewSignatureDatabase(),
		KEK: signature.NewSignatureDatabase(),
		Db:  signature.NewSignatureDatabase(),
		Dbx: signature.NewSignatureDatabase(),
	}
}

func SystemEFIVariables(fs *efivarfs.Efivarfs) (*EFIVariables, error) {
	var sigpk *signature.SignatureDatabase
	var sigkek *signature.SignatureDatabase
	var sigdb *signature.SignatureDatabase
	var err error

	sigdb, err = fs.Getdb()
	if errors.Is(err, os.ErrNotExist) {
		sigdb = signature.NewSignatureDatabase()
	} else if err != nil {
		return nil, err
	}

	sigkek, err = fs.GetKEK()
	if errors.Is(err, os.ErrNotExist) {
		sigkek = signature.NewSignatureDatabase()
	} else if err != nil {
		return nil, err
	}

	sigpk, err = fs.GetPK()
	if errors.Is(err, os.ErrNotExist) {
		sigpk = signature.NewSignatureDatabase()
	} else if err != nil {
		return nil, err
	}

	return &EFIVariables{
		fs:  fs,
		PK:  sigpk,
		KEK: sigkek,
		Db:  sigdb,
		Dbx: signature.NewSignatureDatabase(),
	}, nil
}
