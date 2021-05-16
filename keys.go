package sbctl

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/foxboron/sbctl/logging"
	"github.com/google/uuid"
	"golang.org/x/sys/unix"
)

var RSAKeySize = 4096

var (
	DatabasePath = "/usr/share/secureboot/"
	KeysPath     = filepath.Join(DatabasePath, "keys")
	PKKey        = filepath.Join(KeysPath, "PK", "PK.key")
	PKCert       = filepath.Join(KeysPath, "PK", "PK.pem")
	KEKKey       = filepath.Join(KeysPath, "KEK", "KEK.key")
	KEKCert      = filepath.Join(KeysPath, "KEK", "KEK.pem")
	DBKey        = filepath.Join(KeysPath, "db", "db.key")
	DBCert       = filepath.Join(KeysPath, "db", "db.pem")

	DBPath = filepath.Join(DatabasePath, "files.db")
)

func CreateKey(path, name string) []byte {
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
		KeyUsage:           x509.KeyUsageDigitalSignature,
		Subject: pkix.Name{
			Country:    []string{name},
			CommonName: name,
		},
	}
	priv, err := rsa.GenerateKey(rand.Reader, RSAKeySize)
	if err != nil {
		log.Fatal(err)
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, &c, &c, &priv.PublicKey, priv)
	if err != nil {
		log.Fatalf("Failed to create certificate: %v", err)
	}
	keyOut, err := os.OpenFile(fmt.Sprintf("%s.key", path), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		log.Fatalf("Failed to open key.pem for writing: %v", err)
	}
	privBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		log.Fatalf("Unable to marshal private key: %v", err)
	}
	if err := pem.Encode(keyOut, &pem.Block{Type: "PRIVATE KEY", Bytes: privBytes}); err != nil {
		log.Fatalf("Failed to write data to key.pem: %v", err)
	}
	if err := keyOut.Close(); err != nil {
		log.Fatalf("Error closing key.pem: %v", err)
	}
	return derBytes
}

func SaveKey(k []byte, path string) {
	err := os.WriteFile(fmt.Sprintf("%s.der", path), k, 0644)
	if err != nil {
		log.Fatal(err)
	}
	certOut, err := os.Create(fmt.Sprintf("%s.pem", path))
	if err != nil {
		log.Fatalf("Failed to open cert.pem for writing: %v", err)
	}
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: k}); err != nil {
		log.Fatalf("Failed to write data to cert.pem: %v", err)
	}
	if err := certOut.Close(); err != nil {
		log.Fatalf("Error closing cert.pem: %v", err)
	}

}

func KeyToSiglist(UUID []byte, input string) []byte {
	logging.Print("Create EFI signature list %s.esl...", input)
	out, err := exec.Command(
		"sbsiglist",
		"--owner", string(UUID),
		"--type", "x509",
		"--output", fmt.Sprintf("%s.esl", input), input,
	).Output()
	if err != nil {
		log.Fatalf("Failed creating signature list: %s", err)
	}
	return out
}

func SignEFIVariable(key, cert, varname, vardatafile, output string) ([]byte, error) {
	logging.Print("Signing %s with %s...", vardatafile, key)
	out, err := exec.Command("sbvarsign", "--key", key, "--cert", cert, "--output", output, varname, vardatafile).Output()
	if err != nil {
		return nil, fmt.Errorf("failed signing EFI variable: %v", err)
	}
	return out, nil
}

func SBKeySync(dir string) bool {
	logging.Print("Syncing %s to EFI variables...", dir)
	cmd := exec.Command("sbkeysync", "--pk", "--verbose", "--keystore", dir)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Run(); err != nil {
		if exitError, ok := err.(*exec.ExitError); ok {
			return exitError.ExitCode() == 0
		}
	}
	stdout := out.String()
	for _, line := range strings.Split(stdout, "\n") {
		if strings.Contains(line, "Operation not permitted") {
			fmt.Println(stdout)
			return false
		}
		if strings.Contains(line, "Permission denied") {
			fmt.Println(stdout)
			return false
		}
	}
	return true
}

func VerifyFile(cert, file string) bool {
	cmd := exec.Command("sbverify", "--cert", cert, file)
	if err := cmd.Run(); err != nil {
		if exitError, ok := err.(*exec.ExitError); ok {
			return exitError.ExitCode() == 0
		}
	}
	return true
}

func SignFile(key, cert, file, output, checksum string) error {

	// Check file exists before we do anything
	if _, err := os.Stat(file); os.IsNotExist(err) {
		return fmt.Errorf("%s does not exist!", file)
	}

	// Let's check if we have signed it already AND the original file hasn't changed
	if VerifyFile(cert, output) && ChecksumFile(file) == checksum {
		logging.Print("have already signed %s\n", file)
		return nil
	}

	// Let's also check if we can access the key
	if err := unix.Access(key, unix.R_OK); err != nil {
		return fmt.Errorf("couldn't access %s", key)
	}

	logging.Ok("signing %s", file)
	_, err := exec.Command("sbsign", "--key", key, "--cert", cert, "--output", output, file).Output()
	if err != nil {
		return fmt.Errorf("Failed signing file: %w", err)
	}
	return nil
}

var SecureBootKeys = []struct {
	Key         string
	Description string
	// Path to the key we sign it with
	SignedWith string
}{
	{
		Key:         "PK",
		Description: "Platform Key",
		SignedWith:  "PK",
	},
	{
		Key:         "KEK",
		Description: "Key Exchange Key",
		SignedWith:  "PK",
	},
	{
		Key:         "db",
		Description: "Database Key",
		SignedWith:  "KEK",
	},
	// Haven't used this yet so WIP
	// {
	// 	Key:         "dbx",
	// 	Description: "Forbidden Database Key",
	// 	SignedWith:  "KEK",
	// },
}

func CheckIfKeysInitialized(output string) bool {
	for _, key := range SecureBootKeys {
		path := filepath.Join(output, key.Key)
		if _, err := os.Stat(path); os.IsNotExist(err) {
			return false
		}
	}
	return true
}

func CreateUUID() []byte {
	id, err := uuid.NewRandom()
	if err != nil {
		log.Fatal(err)
	}
	return []byte(id.String())
}

func CreateGUID(output string) ([]byte, error) {
	var uuid []byte
	guidPath := filepath.Join(output, "GUID")
	if _, err := os.Stat(guidPath); os.IsNotExist(err) {
		uuid = CreateUUID()
		logging.Print("Created UUID %s...", uuid)
		err := os.WriteFile(guidPath, uuid, 0600)
		if err != nil {
			return nil, err
		}
		logging.Ok("")
	} else {
		uuid, err = os.ReadFile(guidPath)
		if err != nil {
			return nil, err
		}
		logging.Print("Using UUID %s...", uuid)
	}
	return uuid, nil
}

func InitializeSecureBootKeys(output string) error {
	os.MkdirAll(output, os.ModePerm)
	uuid, err := CreateGUID(output)
	if err != nil {
		return err
	}
	// Create the directories we need and keys
	for _, key := range SecureBootKeys {
		path := filepath.Join(output, "keys", key.Key)
		os.MkdirAll(path, os.ModePerm)
		keyPath := filepath.Join(path, key.Key)
		pk := CreateKey(keyPath, key.Description)
		SaveKey(pk, keyPath)
		KeyToSiglist(uuid, fmt.Sprintf("%s.der", keyPath))
		// Confusing code
		// TODO: make it cleaner
		signingkeyPath := filepath.Join(output, "keys", key.SignedWith, key.SignedWith)
		signingKey := fmt.Sprintf("%s.key", signingkeyPath)
		signingCertificate := fmt.Sprintf("%s.pem", signingkeyPath)
		SignEFIVariable(signingKey, signingCertificate, key.Key, fmt.Sprintf("%s.der.esl", keyPath), fmt.Sprintf("%s.auth", keyPath))
	}
	return nil
}
