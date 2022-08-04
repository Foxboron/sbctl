package sbctl

import (
	"os"
	"path/filepath"
	"testing"
)

func TestNewFile(t *testing.T) {
	dbPath := t.TempDir() // Why does THIS take so long!?

	if err := InitializeSecureBootKeys(dbPath); err != nil {
		t.Fatalf("Error creating test keys: %v", err)
	}

	dbKey := filepath.Join(dbPath, "db", "db.key")
	dbCert := filepath.Join(dbPath, "db", "db.pem")

	// Possible leftover from previous test runs.
	_ = os.Remove("./test-output.bin")
	_ = os.Remove("./test-output.bin2")

	err := SignFile(dbKey, dbCert, "/usr/lib/systemd/boot/efi/systemd-bootaa64.efi", "./test-output.bin")
	if err != nil {
		t.Fatalf("Failed to sign unsigned file: %v", err)
	}

	err = SignFile(dbKey, dbCert, "/usr/lib/systemd/boot/efi/systemd-bootaa64.efi", "./test-output.bin")
	if err != ErrAlreadySigned {
		t.Fatalf("Signing already signed file did not return ErrAlreadySigned, retured: %v", err)
	}

	err = SignFile(dbKey, dbCert, "./test-output.bin", "./test-output2.bin")
	if err != nil {
		t.Fatalf("Error signing already-signed file to new output location: %v", err)
	}

	checksum1, err := ChecksumFile("./test-output.bin")
	if err != nil {
		t.Fatalf("Error calling stat() for file I just created: %v", err)
	}

	checksum2, err := ChecksumFile("./test-output2.bin")
	if err != nil {
		t.Fatalf("Error calling stat() for file I just created: %v", err)
	}

	if checksum1 != checksum2 {
		// This would happen if the file is signed again, which is wrong.
		t.Errorf("Signing already-signed file to new location yielded different results.")
	}

	err = SignFile(dbKey, dbCert, "./test-output.bin", "./test-output2.bin")
	if err != ErrAlreadySigned {
		t.Fatalf("Signing already signed file did not return ErrAlreadySigned, retured: %v", err)
	}
}
