package utils

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log"
	"math/big"
	"time"
)

func CreateKey() ([]byte, []byte) {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		log.Fatalf("Failed to generate serial number: %v", err)
	}
	c := x509.Certificate{
		SerialNumber:       serialNumber,
		PublicKeyAlgorithm: x509.RSA,
		SignatureAlgorithm: x509.SHA256WithRSA,
		NotBefore:          time.Now(),
		NotAfter:           time.Now().AddDate(5, 0, 0),
		Subject: pkix.Name{
			Country:    []string{"Test Suite Key"},
			CommonName: "Test Suite",
		},
	}
	priv, err := rsa.GenerateKey(rand.Reader, 4098)
	if err != nil {
		log.Fatal(err)
	}
	privateKeyBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		log.Fatalf("Unable to marshal private key: %v", err)
	}
	keyOut := new(bytes.Buffer)
	if err := pem.Encode(keyOut, &pem.Block{Type: "PRIVATE KEY", Bytes: privateKeyBytes}); err != nil {
		log.Fatalf("Failed to write data to key.pem: %v", err)
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, &c, &c, &priv.PublicKey, priv)
	if err != nil {
		log.Fatalf("Failed to create certificate: %v", err)
	}
	certOut := new(bytes.Buffer)
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		log.Fatalf("Failed to write data to cert.pem: %v", err)
	}
	return keyOut.Bytes(), certOut.Bytes()
}
