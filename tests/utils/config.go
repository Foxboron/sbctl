package utils

import (
	"io"
	"log"
	"os"
	"path"
	"path/filepath"
)

type TestConfig struct {
	Shared  string
	Ovmf    string
	Secboot string
	Files   []string
}

func NewConfig() *TestConfig {
	dir, _ := os.MkdirTemp("", "go-uefi-test")
	ret := &TestConfig{
		Shared:  dir,
		Ovmf:    path.Join(dir, "OVMF_VARS.fd"),
		Secboot: path.Join(dir, "OVMF_CODE.secboot.fd"),
		Files:   []string{},
	}
	CopyFile("/usr/share/edk2-ovmf/x64/OVMF_VARS.fd", ret.Ovmf)
	CopyFile("/usr/share/edk2-ovmf/x64/OVMF_CODE.secboot.fd", ret.Secboot)
	return ret
}

func (tc *TestConfig) AddFile(file string) {
	dst := path.Join(tc.Shared, filepath.Base(file))
	tc.Files = append(tc.Files, dst)
	CopyFile(file, dst)
}

func (tc *TestConfig) AddBytes(b []byte, name string) {
	dst := path.Join(tc.Shared, name)
	tc.Files = append(tc.Files, dst)
	os.WriteFile(dst, b, 0644)
}

func (tc *TestConfig) Remove() {
	os.RemoveAll(tc.Shared)
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
