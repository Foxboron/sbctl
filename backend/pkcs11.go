package backend

import (
	"crypto"
	"crypto/x509"
	"fmt"
	"github.com/ThalesIgnite/crypto11"
)

type PKCS11Key struct {
	keytype     BackendType
	cert        *x509.Certificate
	context     *crypto11.Context
	description string
}

func NewPKCS11Key(desc string) (*PKCS11Key, error) {
	// TODO: Implement generating keys
	return &PKCS11Key{
		keytype:     PKCS11Backend,
		cert:        nil,
		description: desc,
		context:     nil,
	}, nil
}

func (p *PKCS11Key) Type() BackendType              { return p.keytype }
func (p *PKCS11Key) Certificate() *x509.Certificate { return p.cert }
func (p *PKCS11Key) Description() string            { return p.description }

func (p *PKCS11Key) Signer() crypto.Signer {
	// TODO: This will be the signer from PKCS11Key.context from finding the matching cert
	return nil
}

func (p *PKCS11Key) PrivateKeyBytes() []byte {
	// TODO: This should be a stub to describe the key object in PKCS11
	return nil
}

func (p *PKCS11Key) CertificateBytes() []byte {
	// TODO: Return key by using FindCertificate
	return nil
}

func PKCS11KeyFromBytes(keyb, pemb []byte) (*PKCS11Key, error) {
	// TODO: Make it so that the key file bytes are used to locate the key on the PKCS11 device
	// This might be done by using signatures of the keys when generating
	// We can use FindCertificate from FindCertificate from the PKCS11Key.context
	return nil, fmt.Errorf("not implmented")
}
