package sbctl

import (
	"debug/pe"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
)

type Bundle struct {
	Output         string `json:"output"`
	IntelMicrocode string `json:"intel_microcode"`
	AMDMicrocode   string `json:"amd_microcode"`
	KernelImage    string `json:"kernel_image"`
	Initramfs      string `json:"initramfs"`
	Cmdline        string `json:"cmdline"`
	Splash         string `json:"splash"`
	OSRelease      string `json:"os_release"`
	EFIStub        string `json:"efi_stub"`
	ESP            string `json:"esp"`
}

type Bundles map[string]*Bundle

var BundleDBPath = filepath.Join(DatabasePath, "bundles.db")

func ReadBundleDatabase(dbpath string) (Bundles, error) {
	f, err := ReadOrCreateFile(dbpath)
	if err != nil {
		return nil, err
	}
	bundles := make(Bundles)
	if len(f) == 0 {
		return bundles, nil
	}
	if err = json.Unmarshal(f, &bundles); err != nil {
		return nil, fmt.Errorf("failed to parse json: %v", err)
	}
	return bundles, nil
}

func WriteBundleDatabase(dbpath string, bundles Bundles) error {
	data, err := json.MarshalIndent(bundles, "", "    ")
	if err != nil {
		return err
	}
	err = os.WriteFile(dbpath, data, 0644)
	if err != nil {
		return err
	}
	return nil
}

func BundleIter(fn func(s *Bundle) error) error {
	files, err := ReadBundleDatabase(BundleDBPath)
	if err != nil {
		return err
	}
	for _, s := range files {
		if err := fn(s); err != nil {
			return err
		}
	}
	return nil
}

func efiStubArch() (string, error) {
	switch runtime.GOARCH {
	case "amd64":
		return "linuxx64.efi.stub", nil
	case "arm64":
		return "linuxaa64.efi.stub", nil
	case "386":
		return "linuxia32.efi.stub", nil
	}

	return "", fmt.Errorf("unsupported architecture")
}

func GetEfistub() (string, error) {
	candidatePaths := []string{
		"/lib/systemd/boot/efi/",
		"/lib/gummiboot/",
	}
	stubName, err := efiStubArch()
	if err != nil {
		return "", fmt.Errorf("cannot search for EFI stub: %v", err)
	}

	for _, f := range candidatePaths {
		if _, err := os.Stat(f + stubName); err == nil {
			return f + stubName, nil
		}
	}
	return "", fmt.Errorf("no EFI stub found")
}

func NewBundle() (bundle *Bundle, err error) {
	esp, err := GetESP()
	if err != nil {
		// This is not critical, just use an empty default.
		esp = ""
	}

	stub, err := GetEfistub()
	if err != nil {
		return nil, fmt.Errorf("no EFISTUB file found. Please install systemd-boot or gummiboot! %v", err)
	}

	bundle = &Bundle{
		Output:         "",
		IntelMicrocode: "",
		AMDMicrocode:   "",
		KernelImage:    "/boot/vmlinuz-linux",
		Initramfs:      "/boot/initramfs-linux.img",
		Cmdline:        "/etc/kernel/cmdline",
		Splash:         "",
		OSRelease:      "/usr/lib/os-release",
		EFIStub:        stub,
		ESP:            esp,
	}

	return
}

// Reference ukify from systemd:
// https://github.com/systemd/systemd/blob/d09df6b94e0c4924ea7064c79ab0441f5aff469b/src/ukify/ukify.py

func GenerateBundle(bundle *Bundle) (bool, error) {
	type section struct {
		section string
		file    string
	}
	sections := []section{
		{".osrel", bundle.OSRelease},
		{".cmdline", bundle.Cmdline},
		{".splash", bundle.Splash},
		{".initrd", bundle.Initramfs},
		{".linux", bundle.KernelImage},
	}

	e, err := pe.Open(bundle.EFIStub)
	if err != nil {
		return false, err
	}
	e.Close()
	s := e.Sections[len(e.Sections)-1]

	vma := uint64(s.VirtualAddress) + uint64(s.VirtualSize)
	switch e := e.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		vma += uint64(e.ImageBase)
	case *pe.OptionalHeader64:
		vma += e.ImageBase
	}
	vma = roundUpToBlockSize(vma)

	var args []string
	for _, s := range sections {
		if s.file == "" {
			// optional sections
			switch s.section {
			case ".splash":
				continue
			}
		}
		fi, err := os.Stat(s.file)
		if err != nil || fi.IsDir() {
			return false, err
		}
		var flags string
		switch s.section {
		case ".linux":
			flags = "code,readonly"
		default:
			flags = "data,readonly"
		}
		args = append(args,
			"--add-section", fmt.Sprintf("%s=%s", s.section, s.file),
			"--set-section-flags", fmt.Sprintf("%s=%s", s.section, flags),
			"--change-section-vma", fmt.Sprintf("%s=%#x", s.section, vma),
		)
		vma += roundUpToBlockSize(uint64(fi.Size()))
	}

	args = append(args, bundle.EFIStub, bundle.Output)
	cmd := exec.Command("objcopy", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		if errors.Is(err, exec.ErrNotFound) {
			return false, err
		}
		if exitError, ok := err.(*exec.ExitError); ok {
			return exitError.ExitCode() == 0, nil
		}
	}
	return true, nil
}

func roundUpToBlockSize(size uint64) uint64 {
	const blockSize = 4096
	return ((size + blockSize - 1) / blockSize) * blockSize
}
