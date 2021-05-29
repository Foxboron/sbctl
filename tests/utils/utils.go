package utils

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/anatol/vmtest"
	"golang.org/x/crypto/ssh"
)

func StartOVMF(conf TestConfig) *vmtest.Qemu {
	params := []string{
		"-machine", "type=q35,smm=on,accel=kvm",
		"-boot", "order=c,menu=on,strict=on",
		"-net", "none",
		"-global", "driver=cfi.pflash01,property=secure,value=on",
		"-global", "ICH9-LPC.disable_s3=1",
		"-drive", "if=pflash,format=raw,unit=0,file=/usr/share/edk2-ovmf/x64/OVMF_CODE.secboot.fd,readonly",
		"-drive", "if=pflash,format=raw,unit=1,file=ovmf/OVMF_VARS.fd",
	}
	if conf.Shared != "" {
		params = append(params, "-drive", fmt.Sprintf("file=fat:rw:%s", conf.Shared))
	}
	opts := vmtest.QemuOptions{
		Params:  params,
		Verbose: false, //testing.Verbose(),
		Timeout: 50 * time.Second,
	}
	// Run QEMU instance
	ovmf, err := vmtest.NewQemu(&opts)
	if err != nil {
		panic(err)
	}
	ovmf.ConsoleExpect("Shell>")
	return ovmf
}

type TestVM struct {
	qemu *vmtest.Qemu
	conn *ssh.Client
}

func WithVM(conf *TestConfig, fn func(vm *TestVM)) {
	vm := StartVM(conf)
	defer vm.Close()
	fn(vm)
}

// TODO: Wire this up with 9p instead of ssh
func StartVM(conf *TestConfig) *TestVM {
	params := []string{
		"-machine", "type=q35,smm=on,accel=kvm",
		"-debugcon", "file:debug.log", "-global", "isa-debugcon.iobase=0x402",
		"-netdev", "user,id=net0,hostfwd=tcp::10022-:22",
		"-device", "virtio-net-pci,netdev=net0",
		"-nic", "user,model=virtio-net-pci",
		"-fsdev", fmt.Sprintf("local,id=test_dev,path=%s,security_model=none", conf.Shared),
		"-device", "virtio-9p-pci,fsdev=test_dev,mount_tag=shared",
		"-global", "driver=cfi.pflash01,property=secure,value=on",
		"-global", "ICH9-LPC.disable_s3=1",
		"-drive", fmt.Sprintf("if=pflash,format=raw,unit=0,file=%s,readonly", conf.Secboot),
		"-drive", fmt.Sprintf("if=pflash,format=raw,unit=1,file=%s", conf.Ovmf),
		"-m", "8G", "-smp", "2", "-enable-kvm", "-cpu", "host",
	}
	opts := vmtest.QemuOptions{
		OperatingSystem: vmtest.OS_LINUX,
		Kernel:          "kernel/bzImage",
		Params:          params,
		Disks:           []vmtest.QemuDisk{{Path: "kernel/rootfs.cow", Format: "qcow2"}},
		Append:          []string{"root=/dev/sda", "quiet", "rw"},
		Verbose:         false, //testing.Verbose()
		Timeout:         50 * time.Second,
	}
	// Run QEMU instance
	qemu, err := vmtest.NewQemu(&opts)
	if err != nil {
		panic(err)
	}

	qemu.ConsoleExpect("login:")

	config := &ssh.ClientConfig{
		User:            "root",
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	conn, err := ssh.Dial("tcp", "localhost:10022", config)
	if err != nil {
		panic(err)
	}

	return &TestVM{qemu, conn}
}

func (t *TestVM) Run(command string) (ret string, err error) {
	sess, err := t.conn.NewSession()
	if err != nil {
		log.Fatal(err)
	}
	output, err := sess.CombinedOutput(command)
	return string(output), err
}

func (t *TestVM) Close() {
	t.conn.Close()
	t.qemu.Shutdown()
}

func (t *TestVM) CopyFile(path string) {
	cmd := exec.Command("scp", "-P10022", path, "root@localhost:/")
	if err := cmd.Run(); err != nil {
		log.Fatal(err)
	}
}

func (tvm *TestVM) RunTest(path string) func(t *testing.T) {
	return func(t *testing.T) {
		testName := fmt.Sprintf("%s%s", filepath.Base(path), ".test")
		cmd := exec.Command("go", "test", "-o", testName, "-c", path)
		if testing.Verbose() {
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
		}
		if err := cmd.Run(); err != nil {
			tvm.Close()
			t.Error(err)
		}
		tvm.CopyFile(testName)
		os.Remove(testName)

		ret, err := tvm.Run(fmt.Sprintf("/%s -test.v", testName))
		t.Logf("\n%s", ret)
		if err != nil {
			tvm.Close()
			t.Error(err)
		}
	}
}
