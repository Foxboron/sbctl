package config

import (
	"crypto"
	"crypto/x509"
	"fmt"
	"strings"
	"time"

	"github.com/foxboron/sbctl/logging"
	"github.com/go-piv/piv-go/v2/piv"
)

// A type to wrap piv.Yubikey to manage the yubikey handle
type YubikeyReader struct {
	key       *piv.YubiKey
	Overwrite bool
}

func (y *YubikeyReader) GetPIVKeyCert() (*x509.Certificate, error) {
	if err := y.connectToYubikey(); err != nil {
		return nil, err
	}
	return y.key.Attest(piv.SlotSignature)
}

func (y *YubikeyReader) GenerateKey(key []byte, slot piv.Slot, opts piv.Key) (crypto.PublicKey, error) {
	if err := y.connectToYubikey(); err != nil {
		return nil, err
	}
	return y.key.GenerateKey(key, slot, opts)
}

func (y *YubikeyReader) PrivateKey(slot piv.Slot, public crypto.PublicKey, auth piv.KeyAuth) (crypto.PrivateKey, error) {
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
