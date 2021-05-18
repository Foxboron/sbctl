package sbctl

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/foxboron/sbctl/logging"
)

// Functions that doesn't fit anywhere else

type LsblkEntry struct {
	Parttype   string `json:"parttype"`
	Mountpoint string `json:"mountpoint"`
	Pttype     string `json:"pttype"`
	Fstype     string `json:"fstype"`
}

type LsblkRoot struct {
	Blockdevices []LsblkEntry `json:"blockdevices"`
}

// Slightly more advanced check
func GetESP() string {

	for _, env := range []string{"SYSTEMD_ESP_PATH", "ESP_PATH"} {
		envEspPath, found := os.LookupEnv(env)
		if found {
			return envEspPath
		}
	}

	out, err := exec.Command(
		"lsblk",
		"--json",
		"--output", "PARTTYPE,MOUNTPOINT,PTTYPE,FSTYPE").Output()
	if err != nil {
		log.Panic(err)
	}

	var lsblkRoot LsblkRoot
	json.Unmarshal(out, &lsblkRoot)

	var pathBootEntry *LsblkEntry
	var pathBootEfiEntry *LsblkEntry
	var pathEfiEntry *LsblkEntry

	for _, lsblkEntry := range lsblkRoot.Blockdevices {
		switch lsblkEntry.Mountpoint {
		case "/boot":
			pathBootEntry = new(LsblkEntry)
			*pathBootEntry = lsblkEntry
		case "/boot/efi":
			pathBootEfiEntry = new(LsblkEntry)
			*pathBootEfiEntry = lsblkEntry
		case "/efi":
			pathEfiEntry = new(LsblkEntry)
			*pathEfiEntry = lsblkEntry
		}
	}

	for _, entryToCheck := range []*LsblkEntry{pathEfiEntry, pathBootEntry, pathBootEfiEntry} {
		if entryToCheck == nil {
			continue
		}

		if entryToCheck.Pttype != "gpt" {
			continue
		}

		if entryToCheck.Fstype != "vfat" {
			continue
		}

		if entryToCheck.Parttype != "c12a7328-f81f-11d2-ba4b-00a0c93ec93b" {
			continue
		}

		return entryToCheck.Mountpoint
	}

	return ""
}

func VerifyESP() error {
	espPath := GetESP()
	files, err := ReadFileDatabase(DBPath)
	if err != nil {
		return err
	}
	logging.Print("Verifying file database and EFI images in %s...\n", espPath)

	// Cache files we have looked at.
	checked := make(map[string]bool)
	for _, file := range files {
		normalized := strings.Join(strings.Split(file.OutputFile, "/")[2:], "/")
		checked[normalized] = true

		// Check output file exists before checking if it's signed
		if _, err := os.Open(file.OutputFile); errors.Is(err, os.ErrNotExist) {
			logging.Warn("%s does not exist", file.OutputFile)
		} else if errors.Is(err, os.ErrPermission) {
			logging.Warn("%s permission denied. Can't read file\n", file.OutputFile)
		} else if ok, _ := VerifyFile(DBCert, file.OutputFile); ok {
			logging.Ok("%s is signed", file.OutputFile)
		} else {
			logging.NotOk("%s is not signed", file.OutputFile)
		}
	}

	err = filepath.Walk(espPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if fi, _ := os.Stat(path); fi.IsDir() {
			return nil
		}

		// Don't check files we have checked
		normalized := strings.Join(strings.Split(path, "/")[2:], "/")
		if ok := checked[normalized]; ok {
			return nil
		}

		r, _ := os.Open(path)
		defer r.Close()

		// We are looking for MS-DOS executables.
		// They contain "MZ" as the two first bytes
		var header [2]byte
		if _, err = io.ReadFull(r, header[:]); err != nil {
			return nil
		}
		if !bytes.Equal(header[:], []byte{0x4d, 0x5a}) {
			return nil
		}

		if ok, _ := VerifyFile(DBCert, path); ok {
			logging.Ok("%s is signed\n", path)
		} else {
			logging.NotOk("%s is not signed\n", path)
		}
		return nil
	})
	if err != nil {
		log.Println(err)
	}

	return nil
}

func Sign(file, output string, enroll bool) error {
	file, err := filepath.Abs(file)
	if err != nil {
		log.Fatal(err)
	}

	if output == "" {
		output = file
	} else {
		output, err = filepath.Abs(output)
		if err != nil {
			log.Fatal(err)
		}
	}

	err = nil

	files, err := ReadFileDatabase(DBPath)
	if err != nil {
		return fmt.Errorf("Couldn't open database: %s", DBPath)
	}
	if entry, ok := files[file]; ok {
		err = SignFile(DBKey, DBCert, entry.File, entry.OutputFile, entry.Checksum)
		// return early if signing fails
		if err != nil {
			return err
		}
		checksum := ChecksumFile(file)
		entry.Checksum = checksum
		files[file] = entry
		WriteFileDatabase(DBPath, files)
	} else {
		err = SignFile(DBKey, DBCert, file, output, "")
		// return early if signing fails
		if err != nil {
			return err
		}
	}

	if enroll {
		checksum := ChecksumFile(file)
		files[file] = &SigningEntry{File: file, OutputFile: output, Checksum: checksum}
		WriteFileDatabase(DBPath, files)
	}

	return err
}

func CreateKeys() error {
	if !CheckIfKeysInitialized(KeysPath) {
		logging.Print("Creating secure boot keys...")
		err := InitializeSecureBootKeys(DatabasePath)
		if err != nil {
			return fmt.Errorf("couldn't initialize secure boot: %w", err)
		}
	} else {
		logging.Ok("Secure boot keys has already been created!")
	}
	return nil
}

var efivarFSFiles = []string{
	"/sys/firmware/efi/efivars/PK-8be4df61-93ca-11d2-aa0d-00e098032b8c",
	"/sys/firmware/efi/efivars/KEK-8be4df61-93ca-11d2-aa0d-00e098032b8c",
	"/sys/firmware/efi/efivars/db-d719b2cb-3d3a-4596-a3bc-dad00e67656f",
}

var ErrImmutable = errors.New("You need to chattr -i files in efivarfs")

func SyncKeys() error {
	errImmuable := false
	for _, file := range efivarFSFiles {
		b, err := IsImmutable(file)
		if err != nil {
			return fmt.Errorf("Couldn't read file: %s", file)
		}
		if !b {
			logging.Warn("File is immutable: %s", file)
			errImmuable = true
		}
	}
	if errImmuable {
		return ErrImmutable
	}
	synced := SBKeySync(KeysPath)
	if !synced {
		return errors.New("Couldn't sync keys")
	} else {
		logging.Ok("Synced keys!")
	}
	return nil
}

func CombineFiles(microcode, initramfs string) (*os.File, error) {
	tmpFile, err := os.CreateTemp("/var/tmp", "initramfs-")
	if err != nil {
		return nil, err
	}

	one, _ := os.Open(microcode)
	defer one.Close()

	two, _ := os.Open(initramfs)
	defer two.Close()

	_, err = io.Copy(tmpFile, one)
	if err != nil {
		return nil, fmt.Errorf("failed to append microcode file to output: %w", err)
	}

	_, err = io.Copy(tmpFile, two)
	if err != nil {
		return nil, fmt.Errorf("failed to append initramfs file to output: %w", err)
	}

	return tmpFile, nil
}

func CreateBundle(bundle Bundle) error {
	var microcode string
	make_bundle := false

	if bundle.IntelMicrocode != "" {
		microcode = bundle.IntelMicrocode
		make_bundle = true
	} else if bundle.AMDMicrocode != "" {
		microcode = bundle.AMDMicrocode
		make_bundle = true
	}

	if make_bundle {
		tmpFile, err := CombineFiles(microcode, bundle.Initramfs)
		if err != nil {
			return err
		}
		defer os.Remove(tmpFile.Name())
		bundle.Initramfs = tmpFile.Name()
	}

	out, err := GenerateBundle(&bundle)
	if err != nil {
		logging.Warn(err.Error())
	}
	if !out {
		return fmt.Errorf("failed to generate bundle %s!", bundle.Output)
	}

	return nil
}

func GenerateAllBundles(sign bool) error {
	logging.Println("Generating EFI bundles....")
	bundles, err := ReadBundleDatabase(BundleDBPath)
	if err != nil {
		return fmt.Errorf("Couldn't open database: %s", BundleDBPath)
	}
	out_create := true
	out_sign := true
	for _, bundle := range bundles {
		err := CreateBundle(*bundle)
		if err != nil {
			out_create = false
			continue
		}

		if sign {
			file := bundle.Output
			err = SignFile(DBKey, DBCert, file, file, "")
			if err != nil {
				out_sign = false
			}
		}
	}

	if !out_create {
		return errors.New("Error generating EFI bundles")
	}

	if !out_sign {
		return errors.New("Error signing EFI bundles")
	}

	return nil
}

func ListBundles() (Bundles, error) {
	bundles, err := ReadBundleDatabase(BundleDBPath)
	if err != nil {
		return nil, fmt.Errorf("couldn't open database: %v", err)
	}
	logging.Println("Enrolled bundles:\n")
	for key, bundle := range bundles {
		FormatBundle(key, bundle)
	}
	return bundles, nil
}
