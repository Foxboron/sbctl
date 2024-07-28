package main

import (
	"crypto/x509"
	"fmt"

	"github.com/foxboron/go-uefi/efi"
	"github.com/foxboron/go-uefi/efi/signature"
	"github.com/foxboron/go-uefi/efi/util"
	"github.com/foxboron/sbctl/config"
	"github.com/foxboron/sbctl/lsm"
	"github.com/spf13/cobra"
)

var listKeysCmd = &cobra.Command{
	Use: "list-enrolled-keys",
	Aliases: []string{
		"ls-enrolled-keys",
	},
	Short: "List enrolled keys on the system",
	RunE: func(cmd *cobra.Command, args []string) error {
		state := cmd.Context().Value(stateDataKey{}).(*config.State)
		if state.Config.Landlock {
			if err := lsm.Restrict(); err != nil {
				return err
			}
		}

		var err error
		certList := map[string]([]*x509.Certificate){}

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

		certList["PK"] = ExtractCertsFromSignatureDatabase(pk)
		certList["KEK"] = ExtractCertsFromSignatureDatabase(kek)
		certList["DB"] = ExtractCertsFromSignatureDatabase(db)

		if cmdOptions.JsonOutput {
			return JsonOut(certList)
		}

		printCertsPlainText(certList)

		return nil
	},
}

func init() {
	CliCommands = append(CliCommands, cliCommand{
		Cmd: listKeysCmd,
	})
}

// ExtractCertsFromSignatureDatabase returns a []*x509.Certificate from a *signature.SignatureDatabase
func ExtractCertsFromSignatureDatabase(database *signature.SignatureDatabase) []*x509.Certificate {
	var result []*x509.Certificate
	for _, k := range *database {
		if isValidSignature(k.SignatureType) {
			for _, k1 := range k.Signatures {
				// Note the S at the end of the function, we are parsing multiple certs, not just one
				certificates, err := x509.ParseCertificates(k1.Data)
				if err != nil {
					continue
				}
				result = append(result, certificates...)
			}
		}
	}
	return result
}

// isValidSignature identifies a signature based as a DER-encoded X.509 certificate
func isValidSignature(sign util.EFIGUID) bool {
	return sign == signature.CERT_X509_GUID
}

func printCertsPlainText(certList map[string][]*x509.Certificate) {
	for db, certs := range certList {
		fmt.Printf("%s:\n", db)
		for _, c := range certs {
			fmt.Printf("  %s\n", c.Issuer.CommonName)
		}
	}
}
