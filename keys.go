package sbctl

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/foxboron/go-uefi/efi"
	"github.com/foxboron/go-uefi/efi/signature"
	"github.com/foxboron/go-uefi/efi/util"
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

	GUIDPath = filepath.Join(DatabasePath, "GUID")
)

// Check if we can access the db certificate to verify files
func CanVerifyFiles() error {
	if err := unix.Access(DBCert, unix.R_OK); err != nil {
		return fmt.Errorf("couldn't access %s: %w", DBCert, err)
	}
	return nil
}

func CreateKey(name string) ([]byte, []byte, error) {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, _ := rand.Int(rand.Reader, serialNumberLimit)
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
		return nil, nil, err
	}
	privateKeyBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to marshal private key: %v", err)
	}
	keyOut := new(bytes.Buffer)
	if err := pem.Encode(keyOut, &pem.Block{Type: "PRIVATE KEY", Bytes: privateKeyBytes}); err != nil {
		return nil, nil, fmt.Errorf("failed to write data to key: %v", err)
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, &c, &c, &priv.PublicKey, priv)
	if err != nil {
		return nil, nil, err
	}
	certOut := new(bytes.Buffer)
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		return nil, nil, fmt.Errorf("failed to write data to certificate: %v", err)
	}
	return keyOut.Bytes(), certOut.Bytes(), nil
}

func SaveKey(k []byte, file string) error {
	os.MkdirAll(filepath.Dir(file), os.ModePerm)
	err := os.WriteFile(file, k, 0644)
	if err != nil {
		return err
	}
	return nil
}

func KeyToSiglist(UUID []byte, input string) error {
	_, err := exec.Command(
		"sbsiglist",
		"--owner", string(UUID),
		"--type", "x509",
		"--output", fmt.Sprintf("%s.esl", input), input,
	).Output()
	if err != nil {
		return err
	}
	return nil
}

func SignEFIVariable(key, cert, varname, vardatafile, output string) ([]byte, error) {
	out, err := exec.Command("sbvarsign", "--key", key, "--cert", cert, "--output", output, varname, vardatafile).Output()
	if err != nil {
		return nil, fmt.Errorf("failed signing EFI variable: %v", err)
	}
	return out, nil
}

func SBKeySync(dir string) bool {
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

func VerifyFile(cert, file string) (bool, error) {
	if err := unix.Access(cert, unix.R_OK); err != nil {
		return false, fmt.Errorf("couldn't access %s: %w", cert, err)
	}

	cmd := exec.Command("sbverify", "--cert", cert, file)
	if err := cmd.Run(); err != nil {
		if exitError, ok := err.(*exec.ExitError); ok {
			return exitError.ExitCode() == 0, nil
		}
	}
	return true, nil
}

var ErrAlreadySigned = errors.New("already signed file")

func SignFile(key, cert, file, output, checksum string) error {

	// Check file exists before we do anything
	if _, err := os.Stat(file); errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("%s does not exist", file)
	}

	// Let's check if we have signed it already AND the original file hasn't changed
	ok, err := VerifyFile(cert, output)
	if err != nil {
		return err
	}
	chk, err := ChecksumFile(file)
	if err != nil {
		return err
	}
	if ok && chk == checksum {
		return ErrAlreadySigned
	}

	// Let's also check if we can access the key
	if err := unix.Access(key, unix.R_OK); err != nil {
		return fmt.Errorf("couldn't access %s: %w", key, err)
	}

	_, err = exec.Command("sbsign", "--key", key, "--cert", cert, "--output", output, file).Output()
	if err != nil {
		return fmt.Errorf("failed signing file: %w", err)
	}
	return nil
}

// Map up our default keys in a struct
var SecureBootKeys = []struct {
	Key         string
	Description string
}{
	{
		Key:         "PK",
		Description: "Platform Key",
	},
	{
		Key:         "KEK",
		Description: "Key Exchange Key",
	},
	{
		Key:         "db",
		Description: "Database Key",
	},
	// Haven't used this yet so WIP
	// {
	// 	Key:         "dbx",
	// 	Description: "Forbidden Database Key",
	// 	SignedWith:  "KEK",
	// },
}

// Check if we have already intialized keys in the given output directory
func CheckIfKeysInitialized(output string) bool {
	for _, key := range SecureBootKeys {
		path := filepath.Join(output, key.Key)
		if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
			return false
		}
	}
	return true
}

// Initialize the secure boot keys needed to setup secure boot.
// It creates the following keys:
//	* Platform Key (PK)
//	* Key Exchange Key (KEK)
//	* db (database)
func InitializeSecureBootKeys(output string) error {
	if CheckIfKeysInitialized(output) {
		return nil
	}
	for _, key := range SecureBootKeys {
		keyfile, cert, err := CreateKey(key.Description)
		if err != nil {
			return err
		}
		path := filepath.Join(output, key.Key)
		SaveKey(keyfile, filepath.Join(path, fmt.Sprintf("%s.key", key.Key)))
		SaveKey(cert, filepath.Join(path, fmt.Sprintf("%s.pem", key.Key)))
	}
	return nil
}
