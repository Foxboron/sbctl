package sbctl

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
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
	err = ioutil.WriteFile(dbpath, data, 0644)
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
		KernelImage:    filepath.Join(esp, "vmlinuz-linux"),
		Initramfs:      filepath.Join(esp, "initramfs-linux.img"),
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
	if err := cmd.Run(); err != nil {
		if exitError, ok := err.(*exec.ExitError); ok {
			return exitError.ExitCode() == 0
		}
	}
	msg.Printf("Wrote EFI bundle %s", bundle.Output)
	return true
}

func FormatBundle(name string, bundle *Bundle) {
	msg.Printf("Bundle: %s", name)
	if bundle.AMDMicrocode != "" {
		msg2.Printf("AMD Microcode: %s", bundle.AMDMicrocode)
	}
	if bundle.IntelMicrocode != "" {
		msg2.Printf("Intel Microcode: %s", bundle.IntelMicrocode)
	}
	msg2.Printf("Kernel Image: %s", bundle.KernelImage)
	msg2.Printf("Initramfs Image: %s", bundle.Initramfs)
	msg2.Printf("Cmdline: %s", bundle.Cmdline)
	msg2.Printf("OS Release: %s", bundle.OSRelease)
	msg2.Printf("EFI Stub Image: %s", bundle.EFIStub)
	msg2.Printf("ESP Location: %s", bundle.ESP)
	if bundle.Splash != "" {
		msg2.Printf("Splash Image: %s", bundle.Splash)
	}
	msg2.Printf("Output: %s", bundle.Output)
}
