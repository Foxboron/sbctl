package sbctl

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/foxboron/go-uefi/efi/attributes"
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
		err1.Printf("Couldn't read file database: %s", err)
		return err
	} else {
		msg.Printf("Verifying file database and EFI images in %s...", espPath)
	}

	// Cache files we have looked at.
	checked := make(map[string]bool)
	for _, file := range files {
		normalized := strings.Join(strings.Split(file.OutputFile, "/")[2:], "/")
		checked[normalized] = true

		// Check output file exists before checking if it's signed
		if _, err := os.Open(file.OutputFile); errors.Is(err, os.ErrNotExist) {
			err2.Printf("%s does not exist\n", file.OutputFile)
		} else if errors.Is(err, os.ErrPermission) {
			err2.Printf("%s permission denied. Can't read file\n", file.OutputFile)
		} else if VerifyFile(DBCert, file.OutputFile) {
			msg2.Printf("%s is signed\n", file.OutputFile)
		} else {
			warning2.Printf("%s is not signed\n", file.OutputFile)
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

		if VerifyFile(DBCert, path) {
			msg2.Printf("%s is signed\n", path)
		} else {
			warning2.Printf("%s is not signed\n", path)
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
		err2.Printf("Couldn't open database: %s", DBPath)
		return err
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

func ListFiles() {
	files, err := ReadFileDatabase(DBPath)
	if err != nil {
		err2.Printf("Couldn't open database: %s", DBPath)
		return
	}
	for path, s := range files {
		msg.Printf("File: %s", path)
		if path != s.OutputFile {
			msg2.Printf("Output: %s", s.OutputFile)
		}
	}
}

func CheckStatus() {
	if _, err := os.Stat("/sys/firmware/efi/efivars"); os.IsNotExist(err) {
		warning.Println("System is not booted with UEFI!")
		os.Exit(1)
	}
	if sm, err := attributes.ReadEfivars("SetupMode"); err == nil {
		if sm.Data[0] == 1 {
			warning.Println("Setup Mode: Enabled")
		} else {
			msg.Println("Setup Mode: Disabled")
		}
	}
	if sb, err := attributes.ReadEfivars("SecureBoot"); err == nil {
		if sb.Data[0] == 1 {
			msg.Println("Secure Boot: Enabled")
		} else {
			warning.Println("Secure Boot: Disabled")
		}
	}
}

func CreateKeys() {
	if !CheckIfKeysInitialized(KeysPath) {
		msg.Printf("Creating secure boot keys...")
		InitializeSecureBootKeys(DatabasePath)
	} else {
		msg.Printf("Secure boot keys has been created")
	}
}

var efivarFSFiles = []string{
	"/sys/firmware/efi/efivars/PK-8be4df61-93ca-11d2-aa0d-00e098032b8c",
	"/sys/firmware/efi/efivars/KEK-8be4df61-93ca-11d2-aa0d-00e098032b8c",
	"/sys/firmware/efi/efivars/db-d719b2cb-3d3a-4596-a3bc-dad00e67656f",
}

func SyncKeys() {
	errImmuable := false
	for _, file := range efivarFSFiles {
		b, err := IsImmutable(file)
		if err != nil {
			err1.Printf("Couldn't read file: %s\n", file)
			os.Exit(1)
		}
		if b {
			err1.Printf("File is immutable: %s\n", file)
			errImmuable = true
		}
	}
	if errImmuable {
		err1.Println("You need to chattr -i files in efivarfs")
		os.Exit(1)
	}
	synced := SBKeySync(KeysPath)
	if !synced {
		err1.Println("Couldn't sync keys")
		os.Exit(1)
	} else {
		msg.Println("Synced keys!")
	}
}

func CombineFiles(microcode, initramfs string) (*os.File, error) {
	tmpFile, err := os.CreateTemp("/var/tmp", "initramfs-")
	if err != nil {
		err1.Println("Cannot create temporary file", err)
	}

	one, _ := os.Open(microcode)
	defer one.Close()

	two, _ := os.Open(initramfs)
	defer two.Close()

	_, err = io.Copy(tmpFile, one)
	if err != nil {
		return nil, PrintGenerateError(err2, "failed to append microcode file to output: %s", err)
	}

	_, err = io.Copy(tmpFile, two)
	if err != nil {
		return nil, PrintGenerateError(err2, "failed to append initramfs file to output: %s", err)
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

	out := GenerateBundle(&bundle)
	if !out {
		return PrintGenerateError(err2, "failed to generate bundle %s!", bundle.Output)
	}

	return nil
}

func GenerateAllBundles(sign bool) error {
	msg.Println("Generating EFI bundles....")
	bundles, err := ReadBundleDatabase(BundleDBPath)
	if err != nil {
		err2.Printf("Couldn't open database: %s", BundleDBPath)
		return err
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
		return PrintGenerateError(err1, "Error generating EFI bundles")
	}

	if !out_sign {
		return PrintGenerateError(err1, "Error signing EFI bundles")
	}

	return nil
}

func ListBundles() {
	bundles, err := ReadBundleDatabase(BundleDBPath)
	if err != nil {
		err2.Printf("Couldn't open database: %s", BundleDBPath)
		os.Exit(1)
	}
	for key, bundle := range bundles {
		FormatBundle(key, bundle)
	}
}
