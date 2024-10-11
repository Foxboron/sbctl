package sbctl

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"

	"github.com/foxboron/sbctl/backend"
	"github.com/foxboron/sbctl/config"
	"github.com/foxboron/sbctl/hierarchy"
	"github.com/spf13/afero"
)

var (
	// TODO: Remove this at some point
	//       Only here for legacy reasons to denote the old path
	DatabasePath = "/usr/share/secureboot/"
	Version      = "unknown"
)

// Functions that doesn't fit anywhere else

type LsblkEntry struct {
	Parttype    string        `json:"parttype"`
	Mountpoint  string        `json:"mountpoint"`
	Mountpoints []string      `json:"mountpoints"`
	Pttype      string        `json:"pttype"`
	Fstype      string        `json:"fstype"`
	Children    []*LsblkEntry `json:"children"`
}

type LsblkRoot struct {
	Blockdevices []*LsblkEntry `json:"blockdevices"`
}

var espLocations = []string{
	"/efi",
	"/boot",
	"/boot/efi",
}
var ErrNoESP = errors.New("failed to find EFI system partition")

func findESP(b []byte) (string, error) {
	var lsblkRoot LsblkRoot

	if err := json.Unmarshal(b, &lsblkRoot); err != nil {
		return "", fmt.Errorf("failed to parse json: %v", err)
	}

	for _, lsblkEntry := range lsblkRoot.Blockdevices {
		// This is our check function, that also checks mountpoints
		checkDev := func(e *LsblkEntry, pttype string) *LsblkEntry {
			if e.Pttype != "gpt" && (e.Pttype != "" && pttype != "gpt") {
				return nil
			}

			if e.Fstype != "vfat" {
				return nil
			}

			if e.Parttype != "c12a7328-f81f-11d2-ba4b-00a0c93ec93b" {
				return nil
			}

			if slices.Contains(espLocations, e.Mountpoint) {
				return e
			}

			for _, esp := range espLocations {
				n := slices.Index(e.Mountpoints, esp)
				if n == -1 {
					continue
				}
				// Replace the top-level Mountpoint with a valid one from mountpoints
				e.Mountpoint = e.Mountpoints[n]
				return e
			}
			return nil
		}

		// First check top-level devices
		p := checkDev(lsblkEntry, "")
		if p != nil {
			return p.Mountpoint, nil
		}

		// Check children, this is not recursive.
		for _, ce := range lsblkEntry.Children {
			p := checkDev(ce, lsblkEntry.Pttype)
			if p != nil {
				return p.Mountpoint, nil
			}
		}
	}
	return "", ErrNoESP
}

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
		"--tree",
		"--output", "PARTTYPE,MOUNTPOINT,PTTYPE,FSTYPE").Output()
	if err != nil {
		return "", err
	}
	return findESP(out)
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

	kh, err := backend.GetKeyHierarchy(state.Fs, state)
	if err != nil {
		return err
	}

	files, err := ReadFileDatabase(state.Fs, state.Config.FilesDb)
	if err != nil {
		return fmt.Errorf("couldn't open database: %s", state.Config.FilesDb)
	}

	if enroll {
		files[file] = &SigningEntry{File: file, OutputFile: output}
		if err := WriteFileDatabase(state.Fs, state.Config.FilesDb, files); err != nil {
			return err
		}
	}

	if entry, ok := files[file]; ok && output == entry.OutputFile {
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
