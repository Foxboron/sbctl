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
	Pin       string
}

// Fetches PIN protected management key. If it is not stored, default is returned
func (y *YubikeyReader) GetManagementKey() ([]byte, error) {
	var err error
	if y.Pin == "" {
		if pin, found := os.LookupEnv("SBCTL_YUBIKEY_PIN"); found {
			y.Pin = pin
		} else {
			y.Pin = piv.DefaultPIN
		}
	}
	if err = y.connectToYubikey(); err != nil {
		return nil, err
	}
	// FIXME: Should swallow error and return default key?
	metadata, err := y.key.Metadata(y.Pin)
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

func (y *YubikeyReader) GenerateKey(key []byte, slot piv.Slot, opts piv.Key) (crypto.PublicKey, error) {
	if err := y.connectToYubikey(); err != nil {
		return nil, err
	}
	return y.key.GenerateKey(key, slot, opts)
}

func (y *YubikeyReader) PrivateKey(slot piv.Slot, public crypto.PublicKey) (crypto.PrivateKey, error) {
	if y.Pin == "" {
		if pin, found := os.LookupEnv("SBCTL_YUBIKEY_PIN"); found {
			y.Pin = pin
		} else {
			y.Pin = piv.DefaultPIN
		}
	}
	auth := piv.KeyAuth{PIN: y.Pin}
	if err := y.connectToYubikey(); err != nil {
		return nil, err
	}
	return y.key.PrivateKey(slot, public, auth)
}

func yubikeyWithTimeout(waitTime time.Duration) (string, error) {
	logging.Println(fmt.Sprintf("Please connect yubikey! Waiting %v seconds...", int(waitTime.Seconds())))
	c := make(chan []string, 1)
	timeout := time.After(waitTime)
	for {
		select {
		case <-time.After(500 * time.Millisecond):
			if newCards, err := piv.Cards(); err == nil && len(newCards) > 0 {
				c <- newCards
				goto end
			}
		case <-timeout:
			// time out
			goto end
		}
	}

end:
	select {
	case cards := <-c:
		// short circuit if no cards are found at all.
		if len(cards) == 0 {
			return "", fmt.Errorf("no yubikeys connected")
		}
		// Filter out non yubikeys for users that have a smartcard reader.
		var yubicards []string
		for i := range cards {
			if strings.Contains(strings.ToLower(cards[i]), "yubikey") {
				yubicards = append(yubicards, cards[i])
			}
		}
		if len(yubicards) != 1 {
			return "", fmt.Errorf("error %d yubikeys connected", len(cards))
		}
		if len(yubicards) == 0 {
			return "", fmt.Errorf("no yubikeys connected")
		}
		return yubicards[0], nil
	default:
		return "", fmt.Errorf("timeout waiting for yubikey")
	}
}

func (y *YubikeyReader) connectToYubikey() error {
	if y.key != nil {
		return nil
	}
	card, err := yubikeyWithTimeout(90 * time.Second)
	if err != nil {
		return err
	}

	var yk *piv.YubiKey
	if yk, err = piv.Open(card); err != nil || yk == nil {
		return fmt.Errorf("error opening yubikey: %v", err)
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
