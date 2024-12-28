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
	"github.com/foxboron/sbctl/config"
	"github.com/foxboron/sbctl/hierarchy"
	"github.com/foxboron/sbctl/logging"
	sbctlprompt "github.com/foxboron/sbctl/prompt"
	"math/big"
	"strconv"
	"strings"
	"time"

	"github.com/go-piv/piv-go/v2/piv"
)

type YubikeyData struct {
	Info      piv.KeyInfo `json:"Info"`
	Slot      string      `json:"Slot"`
	PublicKey string      `json:"PublicKey"`
}

type Yubikey struct {
	keytype    BackendType
	cert       *x509.Certificate
	pubKeyInfo *piv.KeyInfo
	yk         *piv.YubiKey
}

func PIVKeyString(algorithm piv.Algorithm) string {
	switch algorithm {
	case piv.AlgorithmRSA2048:
		return "RSA2048"
	case piv.AlgorithmRSA3072:
		return "RSA3072"
	case piv.AlgorithmRSA4096:
		return "RSA4096"
	case piv.AlgorithmEC256:
		return "EC256"
	case piv.AlgorithmEC384:
		return "EC384"
	case piv.AlgorithmEd25519:
		return "Ed25519"
	case piv.AlgorithmX25519:
		return "X25519"
	default:
		logging.Errorf("Unsupported Yubikey algorithm: %v", algorithm)
		return ""
	}
}

func PromptYubikeyPin() (string, error) {
	validate := func(input string) error {
		// Yubikey PIN is 6-8 numbers
		if len(input) < 6 || len(input) > 8 {
			return errors.New("invalid pin length")
		}
		for _, c := range input {
			if _, err := strconv.ParseInt(string(c), 10, 8); err != nil {
				return err
			}
		}
		return nil
	}
	var mask rune
	// '*'
	mask = 42
	return sbctlprompt.SBCTLPrompt(validate, "Yubikey PIV PIN: ", &mask)
}

func NewYubikeyKey(conf *config.YubiConfig, hier hierarchy.Hierarchy, desc string) (*Yubikey, error) {
	var pub crypto.PublicKey
	if conf.PubKeyInfo == nil {
		// Find a YubiKey and open the reader.
		if conf.YK == nil {
			var err error
			conf.YK, err = connectToYubikey()
			if err != nil {
				return nil, err
			}
		}

		keyInfo, err := conf.YK.KeyInfo(piv.SlotSignature)
		if err != nil {
			return nil, err
		}
		// if there is a key and overwrite is set, create a new one

		if keyInfo.PublicKey != nil {
			// if there is a key and it is RSA2048 and overwrite is false, use it
			if keyInfo.Algorithm == piv.AlgorithmRSA2048 && !conf.Overwrite {
				logging.Println("RSA2048 Key exists in Yubikey PIV Signature Slot, using the existing key")
				pub = keyInfo.PublicKey
				conf.PubKeyInfo = &keyInfo
			} else if !conf.Overwrite {
				return nil, fmt.Errorf("yubikey key creation failed; %s key present in signature slot", PIVKeyString(keyInfo.Algorithm))
			}
		}
		if keyInfo.PublicKey == nil || conf.Overwrite {
			if conf.Overwrite {
				validate := func(input string) error {
					if input != "YES" {
						return errors.New("invalid confirmation string")
					}
					return nil
				}
				prompt := fmt.Sprintf("Overwriting existing key %s in Signature slot. Type \"YES\" to proceed", PIVKeyString(keyInfo.Algorithm))
				confirmation, err := sbctlprompt.SBCTLPrompt(validate, prompt, nil)
				if confirmation != "YES" || err != nil {
					return nil, errors.Join(errors.New("invalid confirmation string"), err)
				}
			}

			// Generate a private key on the YubiKey.
			key := piv.Key{
				Algorithm:   piv.AlgorithmRSA2048,
				PINPolicy:   piv.PINPolicyAlways,
				TouchPolicy: piv.TouchPolicyAlways,
			}
			logging.Println("Creating RSA2048 key...")
			pub, err = conf.YK.GenerateKey(piv.DefaultManagementKey, piv.SlotSignature, key)
			if err != nil {
				return nil, err
			}
			newKeyInfo, err := conf.YK.KeyInfo(piv.SlotSignature)
			if err != nil {
				return nil, err
			}
			conf.PubKeyInfo = &newKeyInfo
			h := md5.New()
			h.Write(x509.MarshalPKCS1PublicKey(newKeyInfo.PublicKey.(*rsa.PublicKey)))
			logging.Println(fmt.Sprintf("Created RSA2048 key MD5: %x", h.Sum(nil)))
		}
	} else {
		// Key already setup for sbctl
		pub = conf.PubKeyInfo.PublicKey
	}

	pin, err := PromptYubikeyPin()
	if err != nil {
		return nil, err
	}
	auth := piv.KeyAuth{PIN: pin}
	priv, err := conf.YK.PrivateKey(piv.SlotSignature, pub, auth)
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

	h := md5.New()
	h.Write(x509.MarshalPKCS1PublicKey(conf.PubKeyInfo.PublicKey.(*rsa.PublicKey)))
	logging.Println(fmt.Sprintf("Creating %s key...\nPlease press Yubikey to confirm presence for key %s MD5: %x",
		hier.String(),
		PIVKeyString(conf.PubKeyInfo.Algorithm),
		h.Sum(nil)))
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
		yk:         conf.YK,
	}, nil
}

func YubikeyFromBytes(c *config.YubiConfig, keyb, pemb []byte) (*Yubikey, error) {
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
	if err != nil {
		logging.Errorf("Error parsing public key: %v\n", err)
		return nil, err
	}
	yubiData.Info.PublicKey = pubKey

	block, _ := pem.Decode(pemb)
	if block == nil {
		return nil, fmt.Errorf("no pem block")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse cert: %w", err)
	}

	c.PubKeyInfo = &yubiData.Info
	return &Yubikey{
		keytype:    YubikeyBackend,
		cert:       cert,
		pubKeyInfo: &yubiData.Info,
		yk:         nil,
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
	pin, err := PromptYubikeyPin()
	if err != nil {
		panic(err)
	}
	auth := piv.KeyAuth{PIN: pin}
	if f.yk == nil {
		var err error
		f.yk, err = connectToYubikey()
		if err != nil {
			panic(err)
		}
	}
	priv, err := f.yk.PrivateKey(piv.SlotSignature, f.pubKeyInfo.PublicKey, auth)
	if err != nil {
		panic(err)
	}
	h := md5.New()
	h.Write(x509.MarshalPKCS1PublicKey(f.pubKeyInfo.PublicKey.(*rsa.PublicKey)))
	logging.Println(fmt.Sprintf("Signing operation... please press Yubikey to confirm presence for key %s MD5: %x",
		PIVKeyString(f.pubKeyInfo.Algorithm),
		h.Sum(nil)))
	return priv.(crypto.Signer)
}

func (f *Yubikey) Description() string { return f.Certificate().Subject.SerialNumber }

// save YubiKey data to file
// the piv.pubKeyInfo.PublicKey is set to `nil` as its default marshal/unmarshal to json does not work
// the public key is instead saved in `PublicKey`
// Saves
//
//	{
//	   "Info": piv.pubKeyInfo,
//	   "Slot": "signature",
//	   "PublicKey": publicKey
//	}
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
	return b
}

func (f *Yubikey) CertificateBytes() []byte {
	b := new(bytes.Buffer)
	if err := pem.Encode(b, &pem.Block{Type: "CERTIFICATE", Bytes: f.cert.Raw}); err != nil {
		panic("failed producing PEM encoded certificate")
	}
	return b.Bytes()
}
