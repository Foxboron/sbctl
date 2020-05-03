package sbctl

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
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

func ReadBundleDatabase(dbpath string) Bundles {
	bundles := make(Bundles)
	os.MkdirAll(DatabasePath, os.ModePerm)
	if _, err := os.Stat(BundleDBPath); os.IsNotExist(err) {
		file, err := os.Create(BundleDBPath)
		if err != nil {
			log.Fatal(err)
		}
		file.Close()
	}
	f, err := ioutil.ReadFile(dbpath)
	if err != nil {
		log.Fatal(err)
	}
	json.Unmarshal(f, &bundles)
	return bundles
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

func NewBundle() *Bundle {
	esp := GetESP()
	return &Bundle{
		Output:         "",
		IntelMicrocode: "",
		AMDMicrocode:   "",
		KernelImage:    filepath.Join(esp, "vmlinuz-linux"),
		Initramfs:      filepath.Join(esp, "initramfs-linux.img"),
		Cmdline:        "/proc/cmdline",
		Splash:         "",
		OSRelease:      "/usr/lib/os-release",
		EFIStub:        "/usr/lib/systemd/boot/efi/linuxx64.efi.stub",
		ESP:            esp,
	}
}

func GenerateBundle(bundle *Bundle) bool {
	args := ""
	args += fmt.Sprintf("--add-section .osrel=%s --change-section-vma .osrel=0x20000 ", bundle.OSRelease)
	args += fmt.Sprintf("--add-section .cmdline=%s --change-section-vma .cmdline=0x30000 ", bundle.Cmdline)
	if bundle.Splash != "" {
		args += fmt.Sprintf("--add-section .splash=%s --change-section-vma .splash=0x40000 ", bundle.Splash)
	}
	args += fmt.Sprintf("--add-section .linux=%s --change-section-vma .linux=0x2000000 ", bundle.KernelImage)
	args += fmt.Sprintf("--add-section .initrd=%s --change-section-vma .initrd=0x3000000 ", bundle.Initramfs)
	args += fmt.Sprintf("%s %s", bundle.EFIStub, bundle.Output)
	cmd := exec.Command("objcopy", strings.Split(args, " ")...)
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
	msg2.Printf("OS Relase: %s", bundle.OSRelease)
	msg2.Printf("EFI Stub Image: %s", bundle.EFIStub)
	msg2.Printf("ESP Location: %s", bundle.ESP)
	if bundle.Splash != "" {
		msg2.Printf("Splash Image: %s", bundle.Splash)
	}
	msg2.Printf("Output: %s", bundle.Output)
}
