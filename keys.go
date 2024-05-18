package sbctl

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"

	"github.com/foxboron/go-uefi/authenticode"
	"github.com/foxboron/go-uefi/efi"
	"github.com/foxboron/go-uefi/efi/signature"
	"github.com/foxboron/go-uefi/efi/util"
	"github.com/foxboron/go-uefi/efivar"
	"github.com/foxboron/sbctl/certs"
	"github.com/foxboron/sbctl/fs"
	"golang.org/x/sys/unix"
)

var RSAKeySize = 4096

var (
	DatabasePath = "/usr/share/secureboot/"
	KeysPath     = filepath.Join(DatabasePath, "keys")
	PKKey        = filepath.Join(KeysPath, "PK", "PK.key")
	PKCert       = filepath.Join(KeysPath, "PK", "PK.pem")
	KEKKey       = filepath.Join(KeysPath, "KEK", "KEK.key")
	KEKCert      = filepath.Join(KeysPath, "KEK", "KEK.pem")
	DBKey        = filepath.Join(KeysPath, "db", "db.key")
	DBCert       = filepath.Join(KeysPath, "db", "db.pem")
	DBPath       = filepath.Join(DatabasePath, "files.db")

	GUIDPath = filepath.Join(DatabasePath, "GUID")
)

// Check if we can access the db certificate to verify files
func CanVerifyFiles() error {
	if err := unix.Access(DBCert, unix.R_OK); err != nil {
		return fmt.Errorf("couldn't access %s: %w", DBCert, err)
	}
	return nil
}

func CreateKey(name string) ([]byte, []byte, error) {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, _ := rand.Int(rand.Reader, serialNumberLimit)
	c := x509.Certificate{
		SerialNumber:       serialNumber,
		PublicKeyAlgorithm: x509.RSA,
		SignatureAlgorithm: x509.SHA256WithRSA,
		NotBefore:          time.Now(),
		NotAfter:           time.Now().AddDate(5, 0, 0),
		Subject: pkix.Name{
			Country:    []string{name},
			CommonName: name,
		},
	}
	priv, err := rsa.GenerateKey(rand.Reader, RSAKeySize)
	if err != nil {
		return nil, nil, err
	}
	privateKeyBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to marshal private key: %v", err)
	}
	keyOut := new(bytes.Buffer)
	if err := pem.Encode(keyOut, &pem.Block{Type: "PRIVATE KEY", Bytes: privateKeyBytes}); err != nil {
		return nil, nil, fmt.Errorf("failed to write data to key: %v", err)
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, &c, &c, &priv.PublicKey, priv)
	if err != nil {
		return nil, nil, err
	}
	certOut := new(bytes.Buffer)
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		return nil, nil, fmt.Errorf("failed to write data to certificate: %v", err)
	}
	return keyOut.Bytes(), certOut.Bytes(), nil
}

func SaveKey(k []byte, file string) error {
	if err := fs.Fs.MkdirAll(filepath.Dir(file), os.ModePerm); err != nil {
		return err
	}
	if err := fs.WriteFile(file, k, 0o400); err != nil {
		return err
	}
	return nil
}

func SignDatabase(sigdb *signature.SignatureDatabase, signerKey, signerPem []byte, evar efivar.Efivar) ([]byte, error) {
	key, err := util.ReadKey(signerKey)
	if err != nil {
		return nil, err
	}
	crt, err := util.ReadCert(signerPem)
	if err != nil {
		return nil, err
	}
	_, em, err := signature.SignEFIVariable(evar, sigdb, key, crt)
	if err != nil {
		return nil, err
	}
	return em.Bytes(), nil
}

func Enroll(sigdb *signature.SignatureDatabase, signerKey, signerPem []byte, efivar efivar.Efivar) error {
	signedBuf, err := SignDatabase(sigdb, signerKey, signerPem, efivar)
	if err != nil {
		return err
	}
	//TODO: Remove this for the new functions
	return efi.WriteEFIVariable(efivar.Name, signedBuf)
}

func EnrollCustom(customBytes []byte, efivar string) error {
	return efi.WriteEFIVariable(efivar, customBytes)
}

func VerifyFile(cert, file string) (bool, error) {
	if err := unix.Access(cert, unix.R_OK); err != nil {
		return false, fmt.Errorf("couldn't access %s: %w", cert, err)
	}

	peFile, err := fs.Fs.Open(file)
	if err != nil {
		return false, err
	}

	x509Cert, err := util.ReadCertFromFile(cert)
	if err != nil {
		return false, err
	}

	peBinary, err := authenticode.Parse(peFile)
	if err != nil {
		return false, err
	}

	sigs, err := peBinary.Signatures()
	if err != nil {
		return false, fmt.Errorf("%s: %w", file, err)
	}

	if len(sigs) == 0 {
		return false, nil
	}

	return peBinary.Verify(x509Cert)
}

var ErrAlreadySigned = errors.New("already signed file")

func SignFile(key, cert, file, output, checksum string) error {
	// Check file exists before we do anything
	if _, err := fs.Fs.Stat(file); errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("%s does not exist", file)
	}

	// Let's check if we have signed it already AND the original file hasn't changed
	ok, err := VerifyFile(cert, output)
	if errors.Is(err, os.ErrNotExist) && (file != output) {
		// if the file does not exist and file is not the same as output
		// then we just catch the error and continue. This is expected
		// behaviour
	} else if err != nil {
		return err
	}

	chk, err := ChecksumFile(file)
	if err != nil {
		return err
	}
	if ok && chk == checksum {
		return ErrAlreadySigned
	}

	// Let's also check if we can access the key
	if err := unix.Access(key, unix.R_OK); err != nil {
		return fmt.Errorf("couldn't access %s: %w", key, err)
	}

	// We want to write the file back with correct permissions
	si, err := fs.Fs.Stat(file)
	if err != nil {
		return fmt.Errorf("failed signing file: %w", err)
	}

	peFile, err := fs.Fs.Open(file)
	if err != nil {
		return err
	}

	Cert, err := util.ReadCertFromFile(cert)
	if err != nil {
		return err
	}
	Key, err := util.ReadKeyFromFile(key)
	if err != nil {
		return err
	}

	peBinary, err := authenticode.Parse(peFile)
	if err != nil {
		return err
	}

	_, err = peBinary.Sign(Key, Cert)
	if err != nil {
		return err
	}

	if err = fs.WriteFile(output, peBinary.Bytes(), si.Mode()); err != nil {
		return err
	}

	return nil
}

// Map up our default keys in a struct
var SecureBootKeys = []struct {
	Key         string
	Description string
}{
	{
		Key:         "PK",
		Description: "Platform Key",
	},
	{
		Key:         "KEK",
		Description: "Key Exchange Key",
	},
	{
		Key:         "db",
		Description: "Database Key",
	},
	// {
	// 	Key:         "dbx",
	// 	Description: "Forbidden Database Key",
	// },
}

// Check if we have already intialized keys in the given output directory
func CheckIfKeysInitialized(output string) bool {
	for _, key := range SecureBootKeys {
		path := filepath.Join(output, key.Key)
		if _, err := fs.Fs.Stat(path); errors.Is(err, os.ErrNotExist) {
			return false
		}
	}
	return true
}

// Initialize the secure boot keys needed to setup secure boot.
// It creates the following keys:
//   - Platform Key (PK)
//   - Key Exchange Key (KEK)
//   - db (database)
//   - dbx (forbidden database)
func InitializeSecureBootKeys(output string) error {
	if CheckIfKeysInitialized(output) {
		return nil
	}
	for _, key := range SecureBootKeys {
		keyfile, cert, err := CreateKey(key.Description)
		if err != nil {
			return err
		}
		path := filepath.Join(output, key.Key)

		if err = SaveKey(keyfile, filepath.Join(path, fmt.Sprintf("%s.key", key.Key))); err != nil {
			return err
		}

		if err = SaveKey(cert, filepath.Join(path, fmt.Sprintf("%s.pem", key.Key))); err != nil {
			return err
		}
	}
	return nil
}

func GetEnrolledVendorCerts() []string {
	db, err := efi.Getdb()
	if err != nil {
		return []string{}
	}
	return certs.DetectVendorCerts(db)
}
