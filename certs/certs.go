package certs

import (
	"embed"
	"fmt"
	"path/filepath"

	"github.com/foxboron/go-uefi/efi/signature"
	"github.com/foxboron/go-uefi/efi/util"
)

//go:embed microsoft/*
var content embed.FS

var (
	defaultCerts = []string{"microsoft"}
	oemGUID      = map[string]util.EFIGUID{
		"microsoft":    *util.StringToGUID("77fa9abd-0359-4d32-bd60-28f4e78f784b"),
		"tpm-eventlog": *util.StringToGUID("4f52704f-494d-41736e-6e6f79696e6721"),
	}
)

func GetVendors() []string {
	var oems []string
	files, _ := content.ReadDir(".")
	for _, file := range files {
		oems = append(oems, file.Name())
	}
	return oems
}

func GetCerts(oem string) (*signature.SignatureDatabase, error) {
	GUID, ok := oemGUID[oem]
	if !ok {
		return nil, fmt.Errorf("invalid OEM")
	}
	sigdb := signature.NewSignatureDatabase()
	files, _ := content.ReadDir(oem)
	for _, file := range files {
		path := filepath.Join(oem, file.Name())
		if !file.Type().IsRegular() {
			continue
		}
		buf, _ := content.ReadFile(path)
		sigdb.Append(signature.CERT_X509_GUID, GUID, buf)
	}
	return sigdb, nil
}

func GetDefaultCerts() (*signature.SignatureDatabase, error) {
	sigdb := signature.NewSignatureDatabase()
	for _, oem := range defaultCerts {
		db, err := GetCerts(oem)
		if err != nil {
			return nil, err
		}
		sigdb.AppendDatabase(db)
	}
	return sigdb, nil
}

func DetectVendorCerts(sb *signature.SignatureDatabase) []string {
	oems := []string{}
	detect := map[util.EFIGUID]string{}
	for k, v := range oemGUID {
		detect[v] = k
	}
	for _, l := range *sb {
		for _, sig := range l.Signatures {
			if o, ok := detect[sig.Owner]; ok {
				oems = append(oems, o)
				delete(detect, sig.Owner)
			}
		}
	}
	return oems
}
