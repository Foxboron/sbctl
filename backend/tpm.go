package backend

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"path/filepath"
	"time"

	keyfile "github.com/foxboron/go-tpm-keyfiles"
	"github.com/foxboron/sbctl/fs"
	"github.com/foxboron/sbctl/hierarchy"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/spf13/afero"
)

type TPMKey struct {
	*keyfile.TPMKey
	keytype BackendType
	cert    *x509.Certificate
	tpm     func() transport.TPMCloser
}

func NewTPMKey(tpmcb func() transport.TPMCloser, desc string) (*TPMKey, error) {
	rwc := tpmcb()
	key, err := keyfile.NewLoadableKey(rwc, tpm2.TPMAlgRSA, 2048, []byte(nil),
		keyfile.WithDescription(desc),
	)
	if err != nil {
		return nil, err
	}

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

	pubkey, err := key.PublicKey()
	if err != nil {
		return nil, err
	}

	signer, err := key.Signer(rwc, []byte(nil), []byte(nil))
	if err != nil {
		return nil, err
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &c, &c, pubkey, signer)
	if err != nil {
		return nil, err
	}

	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		return nil, err
	}

	return &TPMKey{
		TPMKey: key,
		cert:   cert,
		tpm:    tpmcb,
	}, nil
}

func (t *TPMKey) Type() BackendType              { return t.keytype }
func (t *TPMKey) Certificate() *x509.Certificate { return t.cert }
func (t *TPMKey) Description() string            { return t.TPMKey.Description }

func (t *TPMKey) Signer() crypto.Signer {
	s, err := t.TPMKey.Signer(t.tpm(), []byte(nil), []byte(nil))
	if err != nil {
		panic(err)
	}
	return s
}

func (t *TPMKey) PrivateKeyBytes() []byte {
	return t.TPMKey.Bytes()
}

func (t *TPMKey) CertificateBytes() []byte {
	b := new(bytes.Buffer)
	if err := pem.Encode(b, &pem.Block{Type: "CERTIFICATE", Bytes: t.cert.Raw}); err != nil {
		panic("failed producing PEM encoded certificate")
	}
	return b.Bytes()
}

func ReadTPMKey(vfs afero.Fs, tpmcb func() transport.TPMCloser, dir string, hier hierarchy.Hierarchy) (*TPMKey, error) {
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
	return TPMKeyFromBytes(tpmcb, keyb, pemb)
}

func TPMKeyFromBytes(tpmcb func() transport.TPMCloser, keyb, pemb []byte) (*TPMKey, error) {
	tpmkey, err := keyfile.Decode(keyb)
	if err != nil {
		return nil, fmt.Errorf("failed parking tpm keyfile: %v", err)
	}

	block, _ := pem.Decode(pemb)
	if block == nil {
		return nil, fmt.Errorf("no pem block")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse cert: %w", err)
	}
	return &TPMKey{
		TPMKey:  tpmkey,
		keytype: TPMBackend,
		cert:    cert,
		tpm:     tpmcb,
	}, nil
}
