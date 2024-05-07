//go:build integration
// +build integration

package main

import (
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"testing"

	"github.com/foxboron/go-uefi/efi/signature"
	"github.com/foxboron/sbctl/tests/utils"
	"github.com/hugelgupf/vmtest/guest"

	. "github.com/onsi/gomega"
)

func TestExportEnrolledKeysDer(t *testing.T) {
	g := NewWithT(t)

	guest.SkipIfNotInVM(t)

	out, err := utils.ExecWithOutput("sbctl export-enrolled-keys --dir /tmp/exported-der --format der")
	g.Expect(err).ToNot(HaveOccurred(), out)

	platformKey, err := findFileByPattern("/tmp/exported-der/PK", ".*Platform.*.der")
	g.Expect(err).ToNot(HaveOccurred())

	derBytes, err := os.ReadFile(platformKey)
	g.Expect(err).ToNot(HaveOccurred())

	cert, err := x509.ParseCertificate(derBytes)
	g.Expect(err).ToNot(HaveOccurred())

	g.Expect(cert.Issuer.String()).To(MatchRegexp("CN=Platform Key,C=Platform Key"))
}

func TestExportEnrolledKeysEsl(t *testing.T) {
	g := NewWithT(t)

	guest.SkipIfNotInVM(t)

	out, err := utils.ExecWithOutput("sbctl export-enrolled-keys --dir /tmp/exported-esl --format esl")
	g.Expect(err).ToNot(HaveOccurred(), out)

	eslReader, err := os.Open("/tmp/exported-esl/db.esl")
	g.Expect(err).ToNot(HaveOccurred())
	defer eslReader.Close()

	sl, err := signature.ReadSignatureList(eslReader)
	g.Expect(err).ToNot(HaveOccurred())

	s := sl.Signatures[0]
	certificates, err := x509.ParseCertificates(s.Data)
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(certificates[0].Issuer.CommonName).To(Equal("Database Key"))
}

func findFileByPattern(dirPath string, pattern string) (string, error) {
	files, err := os.ReadDir(dirPath)
	if err != nil {
		return "", err
	}

	re, err := regexp.Compile(pattern)
	if err != nil {
		return "", err
	}

	for _, file := range files {
		fmt.Printf("file.Name() = %+v\n", file.Name())
		if !file.IsDir() && re.MatchString(file.Name()) {
			return filepath.Join(dirPath, file.Name()), nil
		}
	}

	return "", fmt.Errorf("no file matching pattern '%s' found in directory '%s'", pattern, dirPath)
}
