package fs

import (
	"io"
	"os"

	"github.com/spf13/afero"
)

// Storage backend
var (
	Fs = afero.NewOsFs()
)

func SetFS(f afero.Fs) {
	Fs = f
}

func GetFS() afero.Fs {
	return Fs
}

// Afero misses a few functions. So copy-pasted os/file.go functions here

func WriteFile(name string, data []byte, perm os.FileMode) error {
	f, err := Fs.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, perm)
	if err != nil {
		return err
	}
	_, err = f.Write(data)
	if err1 := f.Close(); err1 != nil && err == nil {
		err = err1
	}
	return err
}

func ReadFile(name string) ([]byte, error) {
	f, err := Fs.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var size int
	if info, err := f.Stat(); err == nil {
		size64 := info.Size()
		if int64(int(size64)) == size64 {
			size = int(size64)
		}
	}
	size++ // one byte for final read at EOF
	if size < 512 {
		size = 512
	}

	data := make([]byte, 0, size)
	for {
		if len(data) >= cap(data) {
			d := append(data[:cap(data)], 0)
			data = d[:len(data)]
		}
		n, err := f.Read(data[len(data):cap(data)])
		data = data[:len(data)+n]
		if err != nil {
			if err == io.EOF {
				err = nil
			}
			return data, err
		}
	}
}
