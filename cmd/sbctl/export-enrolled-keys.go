package main

import (
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/foxboron/go-uefi/efi"
	"github.com/foxboron/go-uefi/efi/signature"
	"github.com/foxboron/sbctl/config"
	"github.com/foxboron/sbctl/lsm"
	"github.com/landlock-lsm/go-landlock/landlock"
	"github.com/spf13/cobra"
)

type DerList map[string][]uint8

var exportDir, format string

var exportEnrolledKeysCmd = &cobra.Command{
	Use:   "export-enrolled-keys",
	Short: "Export already enrolled keys from the system",
	RunE: func(cmd *cobra.Command, args []string) error {
		state := cmd.Context().Value(stateDataKey{}).(*config.State)

		if exportDir == "" {
			fmt.Println("--dir should be set")
			os.Exit(1)
		}
		if state.Config.Landlock {
			lsm.RestrictAdditionalPaths(
				landlock.RWFiles(exportDir),
			)
			if err := lsm.Restrict(); err != nil {
				return err
			}
		}

		var err error
		allCerts := map[string]DerList{}

		pk, err := efi.GetPK()
		if err != nil {
			return err
		}
		kek, err := efi.GetKEK()
		if err != nil {
			return err
		}
		db, err := efi.Getdb()
		if err != nil {
			return err
		}

		exportDir, err = ensureDir(exportDir)
		if err != nil {
			return fmt.Errorf("creating the output directory: %w", err)
		}

		switch format {
		case "der":
			allCerts["PK"] = ExtractDerFromSignatureDatabase(pk)
			allCerts["KEK"] = ExtractDerFromSignatureDatabase(kek)
			allCerts["DB"] = ExtractDerFromSignatureDatabase(db)

			if err := writeDerFiles(allCerts, exportDir); err != nil {
				return fmt.Errorf("writing the certificates: %w", err)
			}
		case "esl":
			if err := os.WriteFile(filepath.Join(exportDir, "db.esl"), db.Bytes(), 0o644); err != nil {
				return err
			}
			if err := os.WriteFile(filepath.Join(exportDir, "KEK.esl"), kek.Bytes(), 0o644); err != nil {
				return err
			}
			if err := os.WriteFile(filepath.Join(exportDir, "PK.esl"), pk.Bytes(), 0o644); err != nil {
				return err
			}
		default:
			return fmt.Errorf("unknown format %s", format)
		}

		return nil
	},
}

func init() {
	exportEnrolledKeysCmd.Flags().StringVar(&exportDir, "dir", "", "directory to write the exported certificates")
	exportEnrolledKeysCmd.Flags().StringVar(&format, "format", "der", "the export format. One of \"der\", \"esl\"")

	CliCommands = append(CliCommands, cliCommand{
		Cmd: exportEnrolledKeysCmd,
	})
}

func ExtractDerFromSignatureDatabase(db *signature.SignatureDatabase) DerList {
	result := DerList{}

	for _, c := range *db {
		for _, s := range c.Signatures {
			switch c.SignatureType {
			case signature.CERT_X509_GUID, signature.CERT_SHA256_GUID:
				certificates, err := x509.ParseCertificates(s.Data)
				if err != nil {
					fmt.Println("warning: " + err.Error())
					continue
				}
				for _, c := range certificates {
					result[fileNameForCertificate(c)] = s.Data
				}
			default:
				fmt.Printf("warning: format not implemented - %s\n", c.SignatureType.Format())
				continue
			}
		}
	}

	return result
}

func fileNameForCertificate(c *x509.Certificate) string {
	return fmt.Sprintf("%s_%s",
		strings.ReplaceAll(c.Issuer.CommonName, " ", "_"),
		c.SerialNumber.String(),
	)
}

func writeDerFiles(allCerts map[string]DerList, outDir string) error {
	for t, certList := range allCerts {
		certDir := filepath.Join(outDir, t)
		if err := os.MkdirAll(certDir, os.ModePerm); err != nil {
			return fmt.Errorf("creating directory %s: %w", certDir, err)
		}
		for fileName, c := range certList {
			certPath := filepath.Join(certDir, fileName) + ".der"
			if err := os.WriteFile(certPath, []byte(c), os.ModePerm); err != nil {
				return fmt.Errorf("writing file %s: %w", certPath, err)
			}
		}
	}
	return nil
}

// ensureDir resolved any relative path and creates the directory if it does not
// exist. It returns the aboslute path to the created directory or an error if one
// occurs.
func ensureDir(dir string) (string, error) {
	if !filepath.IsAbs(dir) {
		wd, err := os.Getwd()
		if err != nil {
			return "", err
		}
		// Resolve the relative path
		dir = filepath.Join(wd, dir)
	}

	if _, err := os.Stat(dir); err == nil {
		return "", fmt.Errorf("directory already exists")
	}

	return dir, os.MkdirAll(dir, 0755)
}
