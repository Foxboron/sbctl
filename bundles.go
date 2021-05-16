package sbctl

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/foxboron/sbctl/logging"
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

func GenerateBundle(bundle *Bundle) bool {
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
			err2.Printf(err.Error())
			return false
		}
		if exitError, ok := err.(*exec.ExitError); ok {
			return exitError.ExitCode() == 0
		}
	}
	logging.Print("Wrote EFI bundle %s\n", bundle.Output)
	return true
}

func FormatBundle(name string, bundle *Bundle) {
	logging.Println(name)
	logging.Print("\tSigned:\t\t")
	if VerifyFile(DBCert, name) {
		logging.Ok("Signed")
	} else {
		logging.Error("Not Signed")
	}
	esp := GetESP()
	logging.Print("\tESP Location:\t%s\n", esp)
	logging.Print("\tOutput:\t\t└─%s\n", strings.TrimPrefix(bundle.Output, esp))
	logging.Print("\tEFI Stub Image:\t  └─%s\n", bundle.EFIStub)
	if bundle.Splash != "" {
		logging.Print("\tSplash Image:\t    ├─%s\n", bundle.Splash)
	}
	logging.Print("\tCmdline:\t    ├─%s\n", bundle.Cmdline)
	logging.Print("\tOS Release:\t    ├─%s\n", bundle.OSRelease)
	logging.Print("\tKernel Image:\t    ├─%s\n", bundle.KernelImage)
	logging.Print("\tInitramfs Image:    └─%s\n", bundle.Initramfs)
	if bundle.AMDMicrocode != "" {
		logging.Print("\tAMD Microcode:        └─%s\n", bundle.AMDMicrocode)
	}
	if bundle.IntelMicrocode != "" {
		logging.Print("\tIntel Microcode:      └─%s\n", bundle.IntelMicrocode)
	}
	logging.Println("")
}
