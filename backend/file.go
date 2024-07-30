package backend

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"path/filepath"
	"time"

	"github.com/foxboron/sbctl/fs"

	"github.com/foxboron/sbctl/hierarchy"
	"github.com/spf13/afero"
)

var RSAKeySize = 4096

type FileKey struct {
	keytype BackendType
	cert    *x509.Certificate
	privkey *rsa.PrivateKey
}

func NewFileKey(_ hierarchy.Hierarchy, desc string) (*FileKey, error) {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, _ := rand.Int(rand.Reader, serialNumberLimit)
	c := x509.Certificate{
		SerialNumber:       serialNumber,
		PublicKeyAlgorithm: x509.RSA,
		SignatureAlgorithm: x509.SHA256WithRSA,
		NotBefore:          time.Now(),
		NotAfter:           time.Now().AddDate(5, 0, 0),
		Subject: pkix.Name{
			Country:    []string{desc},
			CommonName: desc,
		},
	}
	priv, err := rsa.GenerateKey(rand.Reader, RSAKeySize)
	if err != nil {
		return nil, err
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, &c, &c, &priv.PublicKey, priv)
	if err != nil {
		return nil, err
	}

	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		return nil, err
	}
	return &FileKey{
		keytype: FileBackend,
		cert:    cert,
		privkey: priv,
	}, nil
}

func ReadFileKey(vfs afero.Fs, dir string, hier hierarchy.Hierarchy) (*FileKey, error) {
	path := filepath.Join(dir, hier.String())
	keyname := filepath.Join(path, fmt.Sprintf("%s.key", hier.String()))
	certname := filepath.Join(path, fmt.Sprintf("%s.pem", hier.String()))

	// Read privatekey
	keyb, err := fs.ReadFile(vfs, keyname)
	if err != nil {
		return nil, err
	}

	// Read certificate
	pemb, err := fs.ReadFile(vfs, certname)
	if err != nil {
		return nil, err
	}
	return FileKeyFromBytes(keyb, pemb)
}

func FileKeyFromBytes(keyb, pemb []byte) (*FileKey, error) {
	block, _ := pem.Decode(keyb)
	if block == nil {
		return nil, fmt.Errorf("failed to parse pem block")
	}
	priv, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse key: %w", err)
	}

	var key *rsa.PrivateKey
	switch priv := priv.(type) {
	case *rsa.PrivateKey:
		key = priv
	default:
		return nil, fmt.Errorf("unknown type of public key")
	}

	block, _ = pem.Decode(pemb)
	if block == nil {
		return nil, fmt.Errorf("no pem block")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse cert: %w", err)
	}
	return &FileKey{
		keytype: FileBackend,
		cert:    cert,
		privkey: key,
	}, nil
}

func (f *FileKey) Type() BackendType              { return f.keytype }
func (f *FileKey) Certificate() *x509.Certificate { return f.cert }
func (f *FileKey) Signer() crypto.Signer          { return f.privkey }
func (f *FileKey) Description() string            { return f.Certificate().Subject.SerialNumber }

func (f *FileKey) PrivateKeyBytes() []byte {
	privateKeyBytes, err := x509.MarshalPKCS8PrivateKey(f.privkey)
	if err != nil {
		panic("not a valid private key")
	}
	b := new(bytes.Buffer)
	if err := pem.Encode(b, &pem.Block{Type: "PRIVATE KEY", Bytes: privateKeyBytes}); err != nil {
		panic("failed producing PEM encoded certificate")
	}
	return b.Bytes()
}

func (f *FileKey) CertificateBytes() []byte {
	b := new(bytes.Buffer)
	if err := pem.Encode(b, &pem.Block{Type: "CERTIFICATE", Bytes: f.cert.Raw}); err != nil {
		panic("failed producing PEM encoded certificate")
	}
	return b.Bytes()
}
