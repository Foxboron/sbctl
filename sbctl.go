package sbctl

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/foxboron/sbctl/backend"
	"github.com/foxboron/sbctl/config"
	"github.com/foxboron/sbctl/hierarchy"
	"github.com/spf13/afero"
)

// TODO: Remove this at some point
//       Only here for legacy reasons to denote the old path

var (
	DatabasePath = "/usr/share/secureboot/"
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
func GetESP(vfs afero.Fs) (string, error) {

	for _, env := range []string{"SYSTEMD_ESP_PATH", "ESP_PATH"} {
		envEspPath, found := os.LookupEnv(env)
		if found {
			return envEspPath, nil
		}
	}

	for _, location := range espLocations {
		// "Read" a file inside all candiadate locations to trigger an
		// automount if there's an automount partition.
		_, _ = vfs.Stat(fmt.Sprintf("%s/does-not-exist", location))
	}

	out, err := exec.Command(
		"lsblk",
		"--json",
		"--output", "PARTTYPE,MOUNTPOINT,PTTYPE,FSTYPE").Output()
	if err != nil {
		return "", err
	}

	var lsblkRoot LsblkRoot
	if err = json.Unmarshal(out, &lsblkRoot); err != nil {
		return "", fmt.Errorf("failed to parse json: %v", err)
	}

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

func Sign(state *config.State, keys *backend.KeyHierarchy, file, output string, enroll bool) error {
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

	kh, err := backend.GetKeyHierarchy(state.Config)
	if err != nil {
		return err
	}

	files, err := ReadFileDatabase(state.Fs, state.Config.FilesDb)
	if err != nil {
		return fmt.Errorf("couldn't open database: %s", state.Config.FilesDb)
	}
	if entry, ok := files[file]; ok {
		err = SignFile(state, kh, hierarchy.Db, entry.File, entry.OutputFile)
		// return early if signing fails
		if err != nil {
			return err
		}
		files[file] = entry
		if err := WriteFileDatabase(state.Fs, state.Config.FilesDb, files); err != nil {
			return err
		}
	} else {
		err = SignFile(state, kh, hierarchy.Db, file, output)
		// return early if signing fails
		if err != nil {
			return err
		}
	}

	if enroll {
		files[file] = &SigningEntry{File: file, OutputFile: output}
		if err := WriteFileDatabase(state.Fs, state.Config.FilesDb, files); err != nil {
			return err
		}
	}

	return err
}

func CombineFiles(vfs afero.Fs, microcode, initramfs string) (afero.File, error) {
	for _, file := range []string{microcode, initramfs} {
		if _, err := vfs.Stat(file); err != nil {
			return nil, fmt.Errorf("%s: %w", file, errors.Unwrap(err))
		}
	}

	tmpFile, err := afero.TempFile(vfs, "/var/tmp", "initramfs-")
	if err != nil {
		return nil, err
	}

	one, err := vfs.Open(microcode)
	if err != nil {
		return nil, err
	}
	defer one.Close()

	two, err := vfs.Open(initramfs)
	if err != nil {
		return nil, err
	}
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

func CreateBundle(state *config.State, bundle Bundle) error {
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
		tmpFile, err := CombineFiles(state.Fs, microcode, bundle.Initramfs)
		if err != nil {
			return err
		}
		defer state.Fs.Remove(tmpFile.Name())
		bundle.Initramfs = tmpFile.Name()
	}

	out, err := GenerateBundle(state.Fs, &bundle)
	if err != nil {
		return err
	}
	if !out {
		return fmt.Errorf("failed to generate bundle %s", bundle.Output)
	}

	return nil
}
