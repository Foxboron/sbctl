package backend

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/foxboron/sbctl/config"
	"github.com/foxboron/sbctl/logging"
	"math/big"
	"strconv"
	"strings"
	"time"

	"github.com/go-piv/piv-go/v2/piv"
	"github.com/manifoldco/promptui"
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

func PromptYubikeyPin() (string, error) {
	validate := func(input string) error {
		// Yubikey PIN is 6-8 numbers
		if len(input) < 6 || len(input) > 8 {
			return errors.New("invalid pin length")
		}
		for _, c := range input {
			_, err := strconv.ParseInt(string(c), 10, 8)
			if err != nil {
				return err
			}
		}
		return nil
	}

	prompt := promptui.Prompt{
		Label:    "Yubikey PIV PIN: ",
		Validate: validate,
	}

	result, err := prompt.Run()
	if err != nil {
		return "", err
	}

	return result, nil
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
				logging.Warn("RSA 2048 Key exists in Yubikey PIV Signature Slot, using the existing key")
				pub = keyInfo.PublicKey
				conf.PubKeyInfo = &keyInfo
			} else {
				return nil, fmt.Errorf("yubikey key creation failed; non RSA2048 key already in signature slot")
			}
		} else {
			// Generate a private key on the YubiKey.
			key := piv.Key{
				Algorithm:   piv.AlgorithmRSA2048,
				PINPolicy:   piv.PINPolicyAlways,
				TouchPolicy: piv.TouchPolicyAlways,
			}
			logging.Println("Creating key... please press Yubikey to confirm presence")
			pub, err = YK.GenerateKey(piv.DefaultManagementKey, piv.SlotSignature, key)
			if err != nil {
				return nil, err
			}
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

	logging.Println("Signing certificate with key... please press Yubikey to confirm presence")
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

	pubKey, err := x509.ParsePKCS1PublicKey([]byte(yubiData.PublicKey))
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
	pin, err := PromptYubikeyPin()
	if err != nil {
		panic(err)
	}
	auth := piv.KeyAuth{PIN: pin}
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
	logging.Println("Signing operation... please press Yubikey to confirm presence")
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
		PublicKey: string(x509.MarshalPKCS1PublicKey(f.pubKeyInfo.PublicKey.(*rsa.PublicKey))),
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
