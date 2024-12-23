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
	"github.com/foxboron/sbctl/config"
	"github.com/foxboron/sbctl/logging"
	"math/big"
	"strings"
	"time"

	"github.com/go-piv/piv-go/v2/piv"
)

type Yubikey struct {
	keytype BackendType
	cert    *x509.Certificate
	privkey crypto.Signer
}

func NewYubikeyKey(conf *config.YubiConfig, desc string) (*Yubikey, error) {
	var pub crypto.PublicKey
	var priv crypto.PrivateKey
	if conf.Priv == nil && conf.Pub == nil {
		// List all smartcards connected to the system.
		cards, err := piv.Cards()
		if err != nil {
			return nil, err
		}

		// Find a YubiKey and open the reader.
		var yk *piv.YubiKey
		for _, card := range cards {
			if strings.Contains(strings.ToLower(card), "yubikey") {
				if yk, err = piv.Open(card); err != nil {
					return nil, err
				}
			}
		}
		if yk == nil {
			return nil, fmt.Errorf("yubikey key not found")
		}
		conf.YK = yk

		keyInfo, err := yk.KeyInfo(piv.SlotSignature)
		if err != nil {
			return nil, err
		}
		if keyInfo.PublicKey != nil {
			if keyInfo.Algorithm == piv.AlgorithmRSA2048 {
				logging.Println("RSA 2048 Key exists in Yubikey PIV Signature Slot, using the existing key")
				pub = keyInfo.PublicKey
			} else {
				return nil, fmt.Errorf("non RSA2048 key already in the slot")
			}
		} else {
			// Generate a private key on the YubiKey.
			key := piv.Key{
				Algorithm:   piv.AlgorithmRSA2048,
				PINPolicy:   piv.PINPolicyAlways,
				TouchPolicy: piv.TouchPolicyAlways,
			}
			logging.Println("Creating key... please press Yubikey")
			pub, err = yk.GenerateKey(piv.DefaultManagementKey, piv.SlotSignature, key)
			if err != nil {
				return nil, err
			}

		}

		// TODO prompt for PIN when it's not default
		auth := piv.KeyAuth{PIN: piv.DefaultPIN}
		priv, err = yk.PrivateKey(piv.SlotSignature, pub, auth)
		if err != nil {
			return nil, err
		}

		conf.Pub = pub
		conf.Priv = priv
	} else {
		// Key already setup for sbctl
		pub = conf.Pub
		priv = conf.Priv
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

	logging.Println("Creating certificate, please press Yubikey")
	derBytes, err := x509.CreateCertificate(rand.Reader, &c, &c, pub, priv)
	if err != nil {
		return nil, err
	}

	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		return nil, err
	}

	return &Yubikey{
		keytype: YubikeyBackend,
		cert:    cert,
		privkey: priv.(crypto.Signer),
	}, nil
}

func YubikeyFromBytes(conf *config.YubiConfig, keyb, pemb []byte) (*Yubikey, error) {
	block, _ := pem.Decode(keyb)
	if block == nil {
		return nil, fmt.Errorf("failed to parse pem block")
	}
	pub, err := x509.ParsePKCS1PublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse key: %w", err)
	}
	if conf.YK == nil {
		cards, err := piv.Cards()
		if err != nil {
			return nil, err
		}

		// Find a YubiKey and open the reader.
		var yk *piv.YubiKey
		for _, card := range cards {
			if strings.Contains(strings.ToLower(card), "yubikey") {
				if yk, err = piv.Open(card); err != nil {
					return nil, err
				}
			}
		}
		if yk == nil {
			return nil, fmt.Errorf("yubikey not found")
		}
		conf.YK = yk
	}

	// List all smartcards connected to the system.
	// TODO prompt for PIN
	auth := piv.KeyAuth{PIN: piv.DefaultPIN}
	priv, err := conf.YK.PrivateKey(piv.SlotSignature, pub, auth)
	if err != nil {
		return nil, err
	}

	block, _ = pem.Decode(pemb)
	if block == nil {
		return nil, fmt.Errorf("no pem block")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse cert: %w", err)
	}
	return &Yubikey{
		keytype: YubikeyBackend,
		cert:    cert,
		privkey: priv.(crypto.Signer),
	}, nil
}

func (f *Yubikey) Type() BackendType              { return f.keytype }
func (f *Yubikey) Certificate() *x509.Certificate { return f.cert }

func (f *Yubikey) Signer() crypto.Signer {
	logging.Println("Signing operation: please press your Yubikey for confirmation\n")
	return f.privkey
}
func (f *Yubikey) Description() string { return f.Certificate().Subject.SerialNumber }

// save YubiKey Public Key Bytes as .PEM
func (f *Yubikey) PrivateKeyBytes() []byte {
	publicKeyBytes := x509.MarshalPKCS1PublicKey(f.privkey.Public().(*rsa.PublicKey))
	if publicKeyBytes == nil {
		panic("not a valid public key")
	}
	b := new(bytes.Buffer)
	if err := pem.Encode(b, &pem.Block{Type: "PUBLIC KEY", Bytes: publicKeyBytes}); err != nil {
		panic("failed producing PEM encoded certificate")
	}
	return b.Bytes()
}

func (f *Yubikey) CertificateBytes() []byte {
	b := new(bytes.Buffer)
	if err := pem.Encode(b, &pem.Block{Type: "CERTIFICATE", Bytes: f.cert.Raw}); err != nil {
		panic("failed producing PEM encoded certificate")
	}
	return b.Bytes()
}
