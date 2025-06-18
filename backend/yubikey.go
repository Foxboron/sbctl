package backend

import (
	"bytes"
	"crypto"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"time"

	"github.com/foxboron/sbctl/config"
	"github.com/foxboron/sbctl/hierarchy"
	"github.com/foxboron/sbctl/logging"

	"github.com/go-piv/piv-go/v2/piv"
)

type YubikeyData struct {
	Algorithm   piv.Algorithm   `json:"algorithm"`
	PinPolicy   piv.PINPolicy   `json:"pinPolicy"`
	TouchPolicy piv.TouchPolicy `json:"touchPolicy"`
	Slot        string          `json:"slot"`
	PublicKey   string          `json:"publicKey"`
}

type Yubikey struct {
	keytype       BackendType
	cert          *x509.Certificate
	yubikeyReader *config.YubikeyReader
	algorithm     piv.Algorithm
	pinPolicy     piv.PINPolicy
	touchPolicy   piv.TouchPolicy
}

func NewYubikeyKey(yubikeyReader *config.YubikeyReader, hier hierarchy.Hierarchy) (*Yubikey, error) {
	cert, err := yubikeyReader.GetPIVKeyCert()
	if err != nil {
		if !errors.Is(err, piv.ErrNotFound) {
			return nil, fmt.Errorf("failed finding yubikey: %v", err)
		}
	}

	if cert != nil {
		// if there is a key and it is RSA4096 and overwrite is false, use it
		switch yubiPub := cert.PublicKey.(type) {
		case *rsa.PublicKey:
			// RSA4096 Public Key
			if yubiPub.N.BitLen() == 4096 && !yubikeyReader.Overwrite {
				logging.Println(fmt.Sprintf("Using RSA4096 Key MD5: %x in Yubikey PIV Signature Slot", md5sum(cert.PublicKey)))
			} else if !yubikeyReader.Overwrite {
				return nil, fmt.Errorf("yubikey key creation failed; %s key present in signature slot", cert.PublicKeyAlgorithm.String())
			}
		}
	}
	// if overwrite or there is no piv key create one
	if yubikeyReader.Overwrite || cert == nil {
		if yubikeyReader.Overwrite {
			logging.Warn("Overwriting existing key %s in Signature slot", cert.PublicKeyAlgorithm.String())
		}

		// Generate a private key on the YubiKey.
		key := piv.Key{
			Algorithm:   piv.AlgorithmRSA4096,
			PINPolicy:   piv.PINPolicyAlways,
			TouchPolicy: piv.TouchPolicyAlways,
		}
		logging.Println("Creating RSA4096 key...\nPlease press Yubikey to confirm presence")
		newKey, err := yubikeyReader.GenerateKey(piv.DefaultManagementKey, piv.SlotSignature, key)
		if err != nil {
			return nil, err
		}
		logging.Println(fmt.Sprintf("Created RSA4096 key MD5: %x", md5sum(newKey)))

		// we overwrote the existing signing key, do not overwrite again if there are other
		// key creation operations
		yubikeyReader.Overwrite = false
	}

	ykCert, err := yubikeyReader.GetPIVKeyCert()
	if err != nil {
		return nil, err
	}

	auth := piv.KeyAuth{PIN: piv.DefaultPIN}
	if pin, found := os.LookupEnv("SBCTL_YUBIKEY_PIN"); found {
		auth = piv.KeyAuth{PIN: pin}
	}
	priv, err := yubikeyReader.PrivateKey(piv.SlotSignature, ykCert.PublicKey, auth)
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
		NotAfter:           time.Now().AddDate(20, 0, 0),
		Subject: pkix.Name{
			Country:    []string{hier.Description()},
			CommonName: hier.Description(),
		},
	}

	logging.Println(fmt.Sprintf("Creating %s (%s) key...\nPlease press Yubikey to confirm presence for RSA4096 MD5: %x",
		hier.Description(),
		hier.String(),
		md5sum(ykCert.PublicKey)))
	derBytes, err := x509.CreateCertificate(rand.Reader, &c, &c, ykCert.PublicKey, priv)
	if err != nil {
		return nil, err
	}

	cert, err = x509.ParseCertificate(derBytes)
	if err != nil {
		return nil, err
	}

	return &Yubikey{
		keytype:       YubikeyBackend,
		cert:          cert,
		yubikeyReader: yubikeyReader,
		algorithm:     piv.AlgorithmRSA4096,
		pinPolicy:     piv.PINPolicyAlways,
		touchPolicy:   piv.TouchPolicyAlways,
	}, nil
}

func YubikeyFromBytes(yubikeyReader *config.YubikeyReader, keyb, pemb []byte) (*Yubikey, error) {
	var yubiData YubikeyData
	err := json.Unmarshal(keyb, &yubiData)
	if err != nil {
		return nil, fmt.Errorf("error unmarshalling yubikey: %v", err)
	}

	block, _ := pem.Decode(pemb)
	if block == nil {
		return nil, fmt.Errorf("no pem block")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse cert: %w", err)
	}

	return &Yubikey{
		keytype:       YubikeyBackend,
		cert:          cert,
		yubikeyReader: yubikeyReader,
		algorithm:     yubiData.Algorithm,
		pinPolicy:     yubiData.PinPolicy,
		touchPolicy:   yubiData.TouchPolicy,
	}, nil
}

func (f *Yubikey) Type() BackendType              { return f.keytype }
func (f *Yubikey) Certificate() *x509.Certificate { return f.cert }

func (f *Yubikey) Signer() crypto.Signer {
	auth := piv.KeyAuth{PIN: piv.DefaultPIN}
	if pin, found := os.LookupEnv("SBCTL_YUBIKEY_PIN"); found {
		auth = piv.KeyAuth{PIN: pin}
	}

	priv, err := f.yubikeyReader.PrivateKey(piv.SlotSignature, f.cert.PublicKey, auth)
	if err != nil {
		panic(err)
	}
	logging.Println(fmt.Sprintf("Signing operation... please press Yubikey to confirm presence for key %s MD5: %x",
		f.cert.PublicKeyAlgorithm.String(),
		md5sum(f.cert.PublicKey)))
	return priv.(crypto.Signer)
}

func (f *Yubikey) Description() string { return f.Certificate().Subject.SerialNumber }

// save YubiKey data to file
func (f *Yubikey) PrivateKeyBytes() []byte {
	yubiData := YubikeyData{
		Slot:        piv.SlotSignature.String(),
		Algorithm:   f.algorithm,
		PinPolicy:   f.pinPolicy,
		TouchPolicy: f.touchPolicy,
		PublicKey:   base64.StdEncoding.EncodeToString(x509.MarshalPKCS1PublicKey(f.cert.PublicKey.(*rsa.PublicKey))),
	}

	b, err := json.Marshal(yubiData)
	if err != nil {
		panic(err)
	}
	return b
}

func (f *Yubikey) CertificateBytes() []byte {
	b := new(bytes.Buffer)
	if err := pem.Encode(b, &pem.Block{Type: "CERTIFICATE", Bytes: f.cert.Raw}); err != nil {
		panic("failed producing PEM encoded certificate")
	}
	return b.Bytes()
}

func md5sum(key crypto.PublicKey) []byte {
	h := md5.New()
	h.Write(x509.MarshalPKCS1PublicKey(key.(*rsa.PublicKey)))
	return h.Sum(nil)
}
