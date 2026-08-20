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
	"strconv"
	"strings"
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
	slot          piv.Slot
	algorithm     piv.Algorithm
	pinPolicy     piv.PINPolicy
	touchPolicy   piv.TouchPolicy
}

func NewYubikeyKey(yubikeyReader *config.YubikeyReader, hier hierarchy.Hierarchy, keyType string) (*Yubikey, error) {
	var slot piv.Slot
	var slotName string
	var pivAlg piv.Algorithm

	algorithm, slotNumber := splitYubiKeyType(keyType)

	slot, slotName, err := resolvePIVSlot(slotNumber)
	if err != nil {
		return nil, err
	}

	// Load private key from slot
	priv, pub, err := yubikeyReader.PrivateKey(slot)
	if err != nil && !errors.Is(err, piv.ErrNotFound) {
		return nil, err
	}

	// If there is no key or overwrite is set, generate a new one
	if priv == nil || yubikeyReader.Overwrite {
		if priv != nil && yubikeyReader.Overwrite {
			logging.Warn("overwriting existing key in Yubikey PIV %s Slot", slotName)
		}

		switch algorithm {
		case "RSA2048":
			pivAlg = piv.AlgorithmRSA2048
		case "RSA3072":
			pivAlg = piv.AlgorithmRSA3072
		case "RSA4096":
			pivAlg = piv.AlgorithmRSA4096

		default:
			return nil, fmt.Errorf("yubikey: unsupported public key algorithm %s", algorithm)
		}

		// Get management key
		mgmtKey, err := yubikeyReader.GetManagementKey()
		if err != nil {
			return nil, err
		}

		// Generate a private keyOptions on the YubiKey.
		keyOptions := piv.Key{
			Algorithm:   pivAlg,
			PINPolicy:   piv.PINPolicyAlways,
			TouchPolicy: piv.TouchPolicyAlways,
		}
		logging.Println(fmt.Sprintf("creating %s key in Yubikey PIV %s Slot... This might take some time!", algorithm, slotName))
		newKey, err := yubikeyReader.GenerateKey(mgmtKey, slot, keyOptions)
		if err != nil {
			return nil, err
		}
		logging.Println(fmt.Sprintf("created %s key in Yubikey PIV %s Slot (MD5: %x)", algorithm, slotName, md5sum(newKey)))

		// Load newly created private key
		priv, pub, err = yubikeyReader.PrivateKey(slot)
		if err != nil {
			return nil, err
		}
	} else {
		logging.Print("re-using existing key (MD5: %x) in Yubikey PIV %s Slot\n", md5sum(pub), slotName)
	}

	// Check compatibility of private key
	switch yubiPub := pub.(type) {
	case *rsa.PublicKey:
		switch bitlen := yubiPub.N.BitLen(); bitlen {
		case 2048:
			pivAlg = piv.AlgorithmRSA2048
		case 3072:
			pivAlg = piv.AlgorithmRSA3072
		case 4096:
			pivAlg = piv.AlgorithmRSA4096
		default:
			return nil, fmt.Errorf("unsupported bitlen of existing yubikey key: %d", bitlen)
		}

	default:
		return nil, fmt.Errorf("yubikey: unsupported key type: %T", yubiPub)
	}

	// Load certificate from slot
	cert, err := yubikeyReader.GetPIVKeyCert(slot)
	if err != nil && !errors.Is(err, piv.ErrNotFound) {
		return nil, fmt.Errorf("yubikey: failed finding certificate: %v", err)
	}

	// If there is no certificate or overwrite is set, generate a new one and save it to the slot
	if cert == nil || yubikeyReader.Overwrite {
		if cert != nil && yubikeyReader.Overwrite {
			logging.Warn("Overwriting existing certificate in Yubikey PIV %s Slot\n", slotName)
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

		logging.Print("confirm presence on YubiKey to sign certificate with key (MD5: %x)\n", md5sum(pub))
		derBytes, err := x509.CreateCertificate(rand.Reader, &c, &c, pub, priv)
		if err != nil {
			return nil, err
		}

		cert, err = x509.ParseCertificate(derBytes)
		if err != nil {
			return nil, err
		}

		err = yubikeyReader.SetPIVCert(slot, cert)
		if err != nil {
			logging.Errorf("could not save cert to yubikey: %v", err)
		}
	} else {
		logging.Print("re-using existing certificate %s in Yubikey PIV %s Slot\n", cert.Subject, slotName)
	}

	// Check whether certificate was signed with matching private key, as this
	// does not have to be the case if existing keys or certs are re-used.
	pubCertBytes, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("can not marshal public key of certificate: %v", err)
	}
	pubBytes, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, fmt.Errorf("can not marshal public key: %v", err)
	}
	if !bytes.Equal(pubBytes, pubCertBytes) {
		return nil, fmt.Errorf("mismatch between key and certificate in Yubikey PIV %s Slot", slotName)
	}

	return &Yubikey{
		keytype:       YubikeyBackend,
		cert:          cert,
		yubikeyReader: yubikeyReader,
		slot:          slot,
		algorithm:     pivAlg,
		pinPolicy:     piv.PINPolicyAlways,
		touchPolicy:   piv.TouchPolicyAlways,
	}, nil
}

func YubikeyFromBytes(yubikeyReader *config.YubikeyReader, keyb, pemb []byte) (*Yubikey, error) {
	var yubiData YubikeyData
	err := json.Unmarshal(keyb, &yubiData)
	if err != nil {
		return nil, fmt.Errorf("yubikey: error unmarshalling yubikey: %v", err)
	}

	slot, slotname, err := resolvePIVSlot(yubiData.Slot)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(pemb)
	if block == nil {
		return nil, fmt.Errorf("yubikey: no pem block")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("yubikey: failed to parse cert: %w", err)
	}

	_, pub, err := yubikeyReader.PrivateKey(slot)
	if err != nil {
		return nil, fmt.Errorf("error when loading YubiKey: %v", err)
	}

	keyPubKey, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, fmt.Errorf("eror when marshalling public key of YubiKey key: %v", err)
	}

	certPubKey, err := x509.MarshalPKIXPublicKey(cert.PublicKey.(*rsa.PublicKey))
	if err != nil {
		return nil, fmt.Errorf("eror when marshalling public key of YubiKey certificate: %v", err)
	}

	if !bytes.Equal(certPubKey, keyPubKey) {
		logging.Warn("saved certificate is not signed by key in YubiKey PIV %s Slot; wrong YubiKey?", slotname)
	}

	return &Yubikey{
		keytype:       YubikeyBackend,
		cert:          cert,
		yubikeyReader: yubikeyReader,
		slot:          slot,
		algorithm:     yubiData.Algorithm,
		pinPolicy:     yubiData.PinPolicy,
		touchPolicy:   yubiData.TouchPolicy,
	}, nil
}

func (f *Yubikey) Type() BackendType              { return f.keytype }
func (f *Yubikey) Certificate() *x509.Certificate { return f.cert }

func (f *Yubikey) Signer() crypto.Signer {
	priv, pub, err := f.yubikeyReader.PrivateKey(f.slot)
	if err != nil {
		panic(fmt.Errorf("could not access private key for signing operation: %v", err))
	}
	logging.Print("Signing operation... please press Yubikey to confirm presence for key (MD5: %x)\n", md5sum(pub))
	return priv.(crypto.Signer)
}

func (f *Yubikey) Description() string { return f.Certificate().Subject.SerialNumber }

// save YubiKey data to file
func (f *Yubikey) PrivateKeyBytes() []byte {
	pubKey, _ := x509.MarshalPKIXPublicKey(f.cert.PublicKey)
	yubiData := YubikeyData{
		Slot:        f.slot.String(),
		Algorithm:   f.algorithm,
		PinPolicy:   f.pinPolicy,
		TouchPolicy: f.touchPolicy,
		PublicKey:   base64.StdEncoding.EncodeToString(pubKey),
	}

	b, err := json.Marshal(yubiData)
	if err != nil {
		panic(fmt.Errorf("could not marshal private key: %v", err))
	}
	return b
}

func (f *Yubikey) CertificateBytes() []byte {
	b := new(bytes.Buffer)
	if err := pem.Encode(b, &pem.Block{Type: "CERTIFICATE", Bytes: f.cert.Raw}); err != nil {
		panic("yubikey: failed producing PEM encoded certificate")
	}
	return b.Bytes()
}

func md5sum(key crypto.PublicKey) []byte {
	h := md5.New()
	pubKey, _ := x509.MarshalPKIXPublicKey(key)
	h.Write(pubKey)
	return h.Sum(nil)
}

func resolvePIVSlot(slot string) (piv.Slot, string, error) {
	var pivSlot piv.Slot
	var slotName string

	switch strings.ToLower(slot) {
	case "9c":
		pivSlot = piv.SlotSignature
		slotName = "Signature"
	case "9a":
		pivSlot = piv.SlotAuthentication
		slotName = "Authentication"
	case "9e":
		pivSlot = piv.SlotCardAuthentication
		slotName = "CardAuthentication"
	case "9d":
		pivSlot = piv.SlotKeyManagement
		slotName = "KeyManagement"
	default:
		// maybe one of retired slots
		var found bool = false
		slotHexVal, err := strconv.ParseUint(slot, 16, 8)
		if err == nil {
			pivSlot, found = piv.RetiredKeyManagementSlot(uint32(slotHexVal))
		}
		if !found {
			return piv.Slot{}, "", fmt.Errorf("yubikey: Invalid key slot %s", slot)
		}
		slotName = fmt.Sprintf("RetiredKeyManagementSlot:0x%s", slot)
	}
	return pivSlot, slotName, nil
}

func splitYubiKeyType(keyType string) (string, string) {
	arr := strings.SplitN(keyType, ":", 3)

	switch len(arr) {
	case 2:
		return arr[1], piv.SlotSignature.String()
	case 3:
		return arr[1], arr[2]
	default:
		return "RSA4096", piv.SlotSignature.String()
	}
}
