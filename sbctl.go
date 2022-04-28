package sbctl

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
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

var espLocations = []string{
	"/boot",
	"/boot/efi",
	"/efi",
}
var ErrNoESP = errors.New("failed to find EFI system partition")

// Slightly more advanced check
func GetESP() (string, error) {

	for _, env := range []string{"SYSTEMD_ESP_PATH", "ESP_PATH"} {
		envEspPath, found := os.LookupEnv(env)
		if found {
			return envEspPath, nil
		}
	}

	for _, location := range espLocations {
		// "Touch" a file inside all candiadate locations to trigger an
		// automount if there's an automount partition.
		os.Stat(fmt.Sprintf("%s/does-not-exist", location))
	}

	out, err := exec.Command(
		"lsblk",
		"--json",
		"--output", "PARTTYPE,MOUNTPOINT,PTTYPE,FSTYPE").Output()
	if err != nil {
		return "", err
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

		return entryToCheck.Mountpoint, nil
	}

	return "", ErrNoESP
}

func Sign(file, output string, enroll bool) error {
	file, err := filepath.Abs(file)
	if err != nil {
		return err
	}

	if output == "" {
		output = file
	} else {
		output, err = filepath.Abs(output)
		if err != nil {
			return err
		}
	}

	err = nil

	files, err := ReadFileDatabase(DBPath)
	if err != nil {
		return fmt.Errorf("couldn't open database: %s", DBPath)
	}
	if entry, ok := files[file]; ok {
		err = SignFile(DBKey, DBCert, entry.File, entry.OutputFile, entry.Checksum)
		// return early if signing fails
		if err != nil {
			return err
		}
		checksum, err := ChecksumFile(file)
		if err != nil {
			return err
		}
		entry.Checksum = checksum
		files[file] = entry
		if err := WriteFileDatabase(DBPath, files); err != nil {
			return err
		}
	} else {
		err = SignFile(DBKey, DBCert, file, output, "")
		// return early if signing fails
		if err != nil {
			return err
		}
	}

	if enroll {
		checksum, err := ChecksumFile(file)
		if err != nil {
			return err
		}
		files[file] = &SigningEntry{File: file, OutputFile: output, Checksum: checksum}
		if err := WriteFileDatabase(DBPath, files); err != nil {
			return err
		}
	}

	return err
}

func CombineFiles(microcode, initramfs string) (*os.File, error) {
	for _, file := range []string{microcode, initramfs} {
		if _, err := os.Stat(file); err != nil {
			return nil, fmt.Errorf("%s: %w", file, errors.Unwrap(err))
		}
	}

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
		return err
	}
	if !out {
		return fmt.Errorf("failed to generate bundle %s", bundle.Output)
	}

	return nil
}

// Checks if sbctl is setup on this computer
func CheckSbctlInstallation(path string) bool {
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		return false
	}
	return true
}
