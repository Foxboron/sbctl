package backend

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"github.com/foxboron/sbctl/config"
	"github.com/foxboron/sbctl/logging"
	"math/big"
	"strings"
	"time"

	"github.com/go-piv/piv-go/v2/piv"
)

type YubikeyData struct {
	Info      piv.KeyInfo `json:"Info"`
	Slot      string      `json:"Slot"`
	PublicKey string      `json:"PublicKey"`
}

// TODO make this not a global variable...
var YK *piv.YubiKey

type Yubikey struct {
	keytype    BackendType
	cert       *x509.Certificate
	pubKeyInfo *piv.KeyInfo
}

func NewYubikeyKey(conf *config.YubiConfig, desc string) (*Yubikey, error) {
	var pub crypto.PublicKey
	if conf.PubKeyInfo == nil {
		// Find a YubiKey and open the reader.
		if YK == nil {
			var err error
			YK, err = connectToYubikey()
			if err != nil {
				return nil, err
			}
		}

		keyInfo, err := YK.KeyInfo(piv.SlotSignature)
		if err != nil {
			return nil, err
		}
		if keyInfo.PublicKey != nil {
			if keyInfo.Algorithm == piv.AlgorithmRSA2048 {
				logging.Println("RSA 2048 Key exists in Yubikey PIV Signature Slot, using the existing key")
				pub = keyInfo.PublicKey
				conf.PubKeyInfo = &keyInfo
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
			pub, err = YK.GenerateKey(piv.DefaultManagementKey, piv.SlotSignature, key)
			if err != nil {
				return nil, err
			}
		}
	} else {
		// Key already setup for sbctl
		pub = conf.PubKeyInfo.PublicKey
	}

	// TODO prompt for PIN when it's not default
	logging.Println("TODO... prompt for pin")
	auth := piv.KeyAuth{PIN: piv.DefaultPIN}
	priv, err := YK.PrivateKey(piv.SlotSignature, pub, auth)
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

	logging.Println("Creating new certificate with key, please press Yubikey")
	derBytes, err := x509.CreateCertificate(rand.Reader, &c, &c, pub, priv)
	if err != nil {
		return nil, err
	}

	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		return nil, err
	}

	return &Yubikey{
		keytype:    YubikeyBackend,
		cert:       cert,
		pubKeyInfo: conf.PubKeyInfo,
	}, nil
}

func YubikeyFromBytes(_ *config.YubiConfig, keyb, pemb []byte) (*Yubikey, error) {
	var yubiData YubikeyData
	err := json.Unmarshal(keyb, &yubiData)
	if err != nil {
		logging.Errorf("Error unmarshalling Yubikey: %v\n", err)
		return nil, err
	}
	pubKeyB64, err := base64.StdEncoding.DecodeString(yubiData.PublicKey)
	if err != nil {
		return nil, err
	}
	pubKey, err := x509.ParsePKCS1PublicKey(pubKeyB64)
	yubiData.Info.PublicKey = pubKey

	block, _ := pem.Decode(pemb)
	if block == nil {
		return nil, fmt.Errorf("no pem block")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse cert: %w", err)
	}
	return &Yubikey{
		keytype:    YubikeyBackend,
		cert:       cert,
		pubKeyInfo: &yubiData.Info,
	}, nil
}

func connectToYubikey() (*piv.YubiKey, error) {
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

	return yk, nil
}

func (f *Yubikey) Type() BackendType              { return f.keytype }
func (f *Yubikey) Certificate() *x509.Certificate { return f.cert }

func (f *Yubikey) Signer() crypto.Signer {
	logging.Println("TODO... prompt for pin")
	auth := piv.KeyAuth{PIN: piv.DefaultPIN}
	if YK == nil {
		var err error
		YK, err = connectToYubikey()
		if err != nil {
			panic(err)
		}
	}
	priv, err := YK.PrivateKey(piv.SlotSignature, f.pubKeyInfo.PublicKey, auth)
	if err != nil {
		panic(err)
	}
	logging.Println("Signing operation: please press your Yubikey for confirmation\n")
	return priv.(crypto.Signer)
}

func (f *Yubikey) Description() string { return f.Certificate().Subject.SerialNumber }

// save YubiKey data to file
// NOTE: save the following structure as .json
// {"type": "yubikey", "info": "SlotSignature"}
func (f *Yubikey) PrivateKeyBytes() []byte {
	yubiData := YubikeyData{
		Info:      *f.pubKeyInfo,
		Slot:      "signature",
		PublicKey: base64.StdEncoding.EncodeToString(x509.MarshalPKCS1PublicKey(f.pubKeyInfo.PublicKey.(*rsa.PublicKey))),
	}
	yubiData.Info.PublicKey = nil

	b, err := json.Marshal(yubiData)
	if err != nil {
		panic(err)
	}
	//publicKeyBytes := x509.MarshalPKCS1PublicKey(f.privkey.Public().(*rsa.PublicKey))
	//if publicKeyBytes == nil {
	//panic("not a valid public key")
	//}
	//b := new(bytes.Buffer)
	//if err := pem.Encode(b, &pem.Block{Type: "PUBLIC KEY", Bytes: publicKeyBytes}); err != nil {
	//	panic("failed producing PEM encoded certificate")
	//}
	return b
}

func (f *Yubikey) CertificateBytes() []byte {
	b := new(bytes.Buffer)
	if err := pem.Encode(b, &pem.Block{Type: "CERTIFICATE", Bytes: f.cert.Raw}); err != nil {
		panic("failed producing PEM encoded certificate")
	}
	return b.Bytes()
}
