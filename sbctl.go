package sbctl

import (
	"bytes"
	"io"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/foxboron/go-uefi/efi/attributes"
)

// Functions that doesn't fit anywhere else

// Veryvery simple check
func GetESP() string {
	if _, err := os.Stat("/efi"); !os.IsNotExist(err) {
		return "/efi"
	}
	out, err := exec.Command("lsblk", "-o", "PARTTYPE,MOUNTPOINT").Output()
	if err != nil {
		log.Fatal(err)
	}
	data := string(out)
	for _, lines := range strings.Split(data, "\n") {
		if len(lines) < 1 {
			continue
		}
		l := strings.Split(lines, " ")
		if len(l) != 2 {
			continue
		}
		if l[0] == "c12a7328-f81f-11d2-ba4b-00a0c93ec93b" {
			return l[1]
		}
	}
	return ""
}

func VerifyESP() {
	// Cache files we have looked at.
	checked := make(map[string]bool)

	espPath := GetESP()
	files := ReadFileDatabase(DBPath)
	msg.Printf("Verifying file database and EFI images in %s...", espPath)

	for _, file := range files {
		normalized := strings.Join(strings.Split(file.OutputFile, "/")[2:], "/")
		checked[normalized] = true

		// Check output file exists before checking if it's signed
		if _, err := os.Stat(file.OutputFile); os.IsNotExist(err) {
			warning2.Printf("%s does not exist\n", file.OutputFile)
		} else if VerifyFile(DBCert, file.OutputFile) {
			msg2.Printf("%s is signed\n", file.OutputFile)
		} else {
			warning2.Printf("%s is not signed\n", file.OutputFile)
		}
	}

	err := filepath.Walk(espPath, func(path string, info os.FileInfo, err error) error {
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

	files := ReadFileDatabase(DBPath)
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
	files := ReadFileDatabase(DBPath)
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

func SyncKeys() {
	synced := SBKeySync(KeysPath)
	if !synced {
		err.Println("Couldn't sync keys")
		os.Exit(1)
	} else {
		msg.Println("Synced keys!")
	}
}

func CombineFiles(microcode, initramfs string) (*os.File, error) {
	tmpFile, e := ioutil.TempFile("/var/tmp", "initramfs-")
	if e != nil {
		err.Println("Cannot create temporary file", e)
	}

	one, _ := os.Open(microcode)
	defer one.Close()

	two, _ := os.Open(initramfs)
	defer two.Close()

	_, e = io.Copy(tmpFile, one)
	if e != nil {
		return nil, PrintGenerateError(err2, "failed to append microcode file to output:", err)
	}

	_, e = io.Copy(tmpFile, two)
	if e != nil {
		return nil, PrintGenerateError(err2, "failed to append initramfs file to output:", err)
	}

	return tmpFile, nil
}

func CreateBundle(bundle Bundle) error {
	var microcode string

	if bundle.IntelMicrocode != "" {
		microcode = bundle.IntelMicrocode
	} else if bundle.AMDMicrocode != "" {
		microcode = bundle.AMDMicrocode
	}

	tmpFile, err := CombineFiles(microcode, bundle.Initramfs)
	if err != nil {
		return err
	}
	defer os.Remove(tmpFile.Name())
	bundle.Initramfs = tmpFile.Name()

	out := GenerateBundle(&bundle)
	if !out {
		return PrintGenerateError(err2, "failed to generate bundle %s!", bundle.Output)
	}

	return nil
}

func GenerateAllBundles(sign bool) error {
	msg.Println("Generating EFI bundles....")
	bundles := ReadBundleDatabase(BundleDBPath)
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
		return PrintGenerateError(err, "Error generating EFI bundles")
	}

	if !out_sign {
		return PrintGenerateError(err, "Error signing EFI bundles")
	}

	return nil
}

func ListBundles() {
	bundles := ReadBundleDatabase(BundleDBPath)
	for key, bundle := range bundles {
		FormatBundle(key, bundle)
	}
}
