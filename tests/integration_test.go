//go:build integration
// +build integration

package tests

import (
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path"
	"testing"
	"time"

	"github.com/hugelgupf/vmtest"
	"github.com/hugelgupf/vmtest/qemu"
)

type VMTest struct {
	ovmf    string
	secboot string
}

func (vm *VMTest) RunTests(packages ...string) func(t *testing.T) {
	return func(t *testing.T) {
		vmtest.RunGoTestsInVM(t, packages,
			vmtest.WithVMOpt(
				vmtest.WithSharedDir("ovmf/keys"),
				vmtest.WithInitramfsFiles("sbctl:bin/sbctl"),
				vmtest.WithQEMUFn(
					qemu.WithVMTimeout(time.Minute),
					qemu.WithQEMUCommand("qemu-system-x86_64 -enable-kvm"),
					qemu.WithKernel("bzImage"),
					qemu.ArbitraryArgs(
						"-m", "1G", "-machine", "type=q35,smm=on",
						"-drive", fmt.Sprintf("if=pflash,format=raw,unit=0,file=%s,readonly=on", vm.secboot),
						"-drive", fmt.Sprintf("if=pflash,format=raw,unit=1,file=%s", vm.ovmf),
					),
				)),
		)
	}
}

func TestMain(m *testing.M) {
	cmd := exec.Command("go", "build", "../cmd/sbctl")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		log.Fatal(err)
	}
	os.Exit(m.Run())
}

func TestEnrollement(t *testing.T) {
	os.Setenv("VMTEST_QEMU", "qemu-system-x86_64")
	if err := buildSbctl(); err != nil {
		t.Fatal(err)
	}

	WithVM(t, func(vm *VMTest) {
		t.Run("Enroll keys", vm.RunTests("github.com/foxboron/sbctl/tests/integrations/enroll_keys"))
		t.Run("Secure boot enabled", vm.RunTests("github.com/foxboron/sbctl/tests/integrations/secure_boot_enabled"))
		t.Run("List enrolled keys", vm.RunTests("github.com/foxboron/sbctl/tests/integrations/list_enrolled_keys"))
	})
}

// Sets up the test by making a copy of the OVMF files from the system
func WithVM(t *testing.T, fn func(*VMTest)) {
	t.Helper()
	dir := t.TempDir()
	vm := VMTest{
		ovmf:    path.Join(dir, "OVMF_VARS.fd"),
		secboot: path.Join(dir, "OVMF_CODE.secboot.fd"),
	}
	CopyFile("/usr/share/edk2-ovmf/x64/OVMF_VARS.fd", vm.ovmf)
	CopyFile("/usr/share/edk2-ovmf/x64/OVMF_CODE.secboot.fd", vm.secboot)
	fn(&vm)
}

func CopyFile(src, dst string) bool {
	source, err := os.Open(src)
	if err != nil {
		log.Fatal(err)
	}
	defer source.Close()

	f, err := os.OpenFile(dst, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()
	io.Copy(f, source)
	si, err := os.Stat(src)
	if err != nil {
		log.Fatal(err)
	}
	err = os.Chmod(dst, si.Mode())
	if err != nil {
		log.Fatal(err)
	}
	return true
}

func buildSbctl() error {
	cmd := exec.Command("go", "build", "../cmd/sbctl")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	return cmd.Run()
}
