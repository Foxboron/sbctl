package sbctl

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
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
	json.Unmarshal(f, &bundles)
	return bundles, nil
}

func WriteBundleDatabase(dbpath string, bundles Bundles) {
	data, err := json.MarshalIndent(bundles, "", "    ")
	if err != nil {
		log.Fatal(err)
	}
	err = os.WriteFile(dbpath, data, 0644)
	if err != nil {
		log.Fatal(err)
	}
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

func GetEfistub() string {
	candidates := []string{
		"/lib/systemd/boot/efi/linuxx64.efi.stub",
		"/lib/gummiboot/linuxx64.efi.stub",
	}
	for _, f := range candidates {
		if _, err := os.Stat(f); err == nil {
			return f
		}
	}
	return ""
}

func NewBundle() *Bundle {
	esp := GetESP()

	stub := GetEfistub()
	if stub == "" {
		panic("No EFISTUB file found. Please install systemd-boot or gummiboot!")
	}

	return &Bundle{
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
}

func GenerateBundle(bundle *Bundle) (bool, error) {
	args := []string{
		"--add-section", fmt.Sprintf(".osrel=%s", bundle.OSRelease), "--change-section-vma", ".osrel=0x20000",
		"--add-section", fmt.Sprintf(".cmdline=%s", bundle.Cmdline), "--change-section-vma", ".cmdline=0x30000",
		"--add-section", fmt.Sprintf(".linux=%s", bundle.KernelImage), "--change-section-vma", ".linux=0x2000000",
		"--add-section", fmt.Sprintf(".initrd=%s", bundle.Initramfs), "--change-section-vma", ".initrd=0x3000000",
	}

	if bundle.Splash != "" {
		args = append(args, "--add-section", fmt.Sprintf(".splash=%s", bundle.Splash), "--change-section-vma", ".splash=0x40000")
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
