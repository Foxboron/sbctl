package certs

import (
	"embed"
	"fmt"
	"os"
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
		"custom":       *util.StringToGUID("88a69775-5ad7-45d9-9f34-cec43e1f1989"),
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

func GetOEMCerts(oem string, variable string) (*signature.SignatureDatabase, error) {
	GUID, ok := oemGUID[oem]
	if !ok {
		return nil, fmt.Errorf("invalid OEM")
	}
	sigdb := signature.NewSignatureDatabase()
	files, _ := content.ReadDir(filepath.Join(oem, variable))
	for _, file := range files {
		path := filepath.Join(oem, variable, file.Name())
		if !file.Type().IsRegular() {
			continue
		}
		buf, _ := content.ReadFile(path)
		if err := sigdb.Append(signature.CERT_X509_GUID, GUID, buf); err != nil {
			return nil, err
		}
	}
	return sigdb, nil
}

func GetCustomCerts(keydir string, variable string) (*signature.SignatureDatabase, error) {
	GUID, ok := oemGUID["custom"]
	if !ok {
		return nil, fmt.Errorf("GUID for custom certs not found")
	}
	sigdb := signature.NewSignatureDatabase()
	files, _ := os.ReadDir(filepath.Join(keydir, "custom", variable))
	for _, file := range files {
		path := filepath.Join(keydir, "custom", variable, file.Name())
		if !file.Type().IsRegular() {
			continue
		}
		buf, _ := os.ReadFile(path)
		if err := sigdb.Append(signature.CERT_X509_GUID, GUID, buf); err != nil {
			return nil, err
		}
	}
	return sigdb, nil
}

func GetDefaultCerts(variable string) (*signature.SignatureDatabase, error) {
	sigdb := signature.NewSignatureDatabase()
	for _, oem := range defaultCerts {
		db, err := GetOEMCerts(oem, variable)
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
