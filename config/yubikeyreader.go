package config

import (
	"crypto"
	"crypto/x509"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/foxboron/sbctl/logging"
	"github.com/go-piv/piv-go/v2/piv"
)

// A type to wrap piv.Yubikey to manage the yubikey handle
type YubikeyReader struct {
	key       *piv.YubiKey
	Overwrite bool
	pin       string
}

// Fetches PIN protected management key. If it is not stored, default is returned
func (y *YubikeyReader) GetManagementKey() ([]byte, error) {
	var err error
	if err = y.connectToYubikey(); err != nil {
		return nil, err
	}
	// FIXME: Should swallow error and return default key?
	metadata, err := y.key.Metadata(y.pin)
	if err != nil {
		return nil, err
	}
	if metadata.ManagementKey != nil {
		return *metadata.ManagementKey, nil
	} else {
		return piv.DefaultManagementKey, nil
	}
}

func (y *YubikeyReader) GetPIVKeyCert(slot piv.Slot) (*x509.Certificate, error) {
	if err := y.connectToYubikey(); err != nil {
		return nil, err
	}
	return y.key.Certificate(slot)
}

func (y *YubikeyReader) GetPIVAttestationCert(slot piv.Slot) (*x509.Certificate, error) {
	if err := y.connectToYubikey(); err != nil {
		return nil, err
	}
	return y.key.Attest(slot)
}

func (y *YubikeyReader) SetPIVCert(slot piv.Slot, cert *x509.Certificate) error {
	if err := y.connectToYubikey(); err != nil {
		return err
	}
	managementKey, err := y.GetManagementKey()
	if err != nil {
		return err
	}
	return y.key.SetCertificate(managementKey, slot, cert)
}

func (y *YubikeyReader) GenerateKey(key []byte, slot piv.Slot, opts piv.Key) (crypto.PublicKey, error) {
	if err := y.connectToYubikey(); err != nil {
		return nil, err
	}
	return y.key.GenerateKey(key, slot, opts)
}

func (y *YubikeyReader) PrivateKey(slot piv.Slot) (crypto.PrivateKey, crypto.PublicKey, error) {
	var pubKey crypto.PublicKey

	if err := y.connectToYubikey(); err != nil {
		return nil, nil, err
	}
	auth := piv.KeyAuth{PIN: y.pin}

	version := y.key.Version()

	if version.Major > 5 || (version.Major == 5 && version.Minor >= 3) {
		keyInfo, err := y.key.KeyInfo(slot)
		if err != nil {
			return nil, nil, err
		}
		pubKey = keyInfo.PublicKey

	} else if version.Major > 4 || (version.Major == 4 && version.Minor >= 3) {
		attestationCert, err := y.key.Attest(slot)
		if err != nil {
			return nil, nil, err
		}
		pubKey = attestationCert.PublicKey

	} else {
		return nil, nil, fmt.Errorf("Unsupported YubiKey Version, too old: %d.%d.%d", version.Major, version.Minor, version.Patch)
	}

	privKey, err := y.key.PrivateKey(slot, pubKey, auth)
	if err != nil {
		return nil, nil, err
	}

	return privKey, pubKey, err
}

func connectToYubikeyWithTimeout(waitTime time.Duration) (*piv.YubiKey, error) {
	logging.Print("Please connect yubikey! Waiting %v seconds...\n", int(waitTime.Seconds()))

	timeout := time.After(waitTime)
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			cards, err := piv.Cards()
			if err != nil {
				logging.Error(err)
				continue
			}

			if len(cards) == 0 {
				// No smartcards at all, keep waiting
				continue
			}

			// Filter out non-yubikeys for users that have other smartcard readers
			var yubicards []string
			for _, card := range cards {
				if strings.Contains(strings.ToLower(card), "yubikey") {
					yubicards = append(yubicards, card)
				}
			}

			switch len(yubicards) {
			case 0:
				// No yubikeys yet, keep waiting
				continue

			case 1:
				logging.Print("YubiKey found: %s\n", yubicards[0])

				var yk *piv.YubiKey
				if yk, err = piv.Open(yubicards[0]); err != nil || yk == nil {
					return nil, fmt.Errorf("error opening yubikey: %v", err)
				}
				return yk, nil

			default:
				return nil, fmt.Errorf("error, %d yubikeys connected", len(yubicards))

			}

		case <-timeout:
			return nil, fmt.Errorf("timeout waiting for yubikey")

		}
	}
}

func (y *YubikeyReader) connectToYubikey() error {
	if y.key != nil {
		return nil
	}

	yk, err := connectToYubikeyWithTimeout(90 * time.Second)
	if err != nil {
		return err
	}

	if pin, found := os.LookupEnv("SBCTL_YUBIKEY_PIN"); found {
		y.pin = pin
	} else {
		y.pin = piv.DefaultPIN
	}

	y.key = yk
	return nil
}

func (y *YubikeyReader) Close() error {
	if y.key != nil {
		return y.key.Close()
	}
	return nil
}
