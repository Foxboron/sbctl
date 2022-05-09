package certs

import (
	"fmt"
	"os"

	"github.com/foxboron/go-uefi/efi/attributes"
	"github.com/foxboron/go-uefi/efi/signature"
	"github.com/foxboron/go-uefi/efi/util"
)

var (
	efiGlobalGuid                = util.EFIGUID{0x8be4df61, 0x93ca, 0x11d2, [8]uint8{0xaa, 0x0d, 0x00, 0xe0, 0x98, 0x03, 0x2b, 0x8c}}
	defaultSignatureDatabaseName = "dbDefault"
)

type builtinSignatureDataEntry struct {
	SignatureType util.EFIGUID
	Data          *signature.SignatureData
}

func GetBuiltinCertificates() (*signature.SignatureDatabase, error) {
	attr, buf, err := attributes.ReadEfivarsWithGuid(defaultSignatureDatabaseName, efiGlobalGuid)
	if err != nil {
		if err == os.ErrNotExist {
			// not finding a default db is not a failure!
			return signature.NewSignatureDatabase(), nil
		}
		return nil, err
	}

	if attr&attributes.EFI_VARIABLE_NON_VOLATILE != 0 {
		// If this variable has non-volatile storage, a malicious user could have created it.
		// The EDK2 implementation of default Secure Boot stores marks them volatile.
		return nil, fmt.Errorf("Vendor default database is non-volatile (and is vulnerable to being tampered with)")
	}

	database, err := signature.ReadSignatureDatabase(buf)
	if err != nil {
		return nil, err
	}

	detect := map[util.EFIGUID]string{}
	for k, v := range oemGUID {
		detect[v] = k
	}

	removals := make([]*builtinSignatureDataEntry, 0, 8)

	// Remove vendor certificates that are already covered by the built-in vendor database.
	for _, l := range database {
		if l.SignatureType == signature.CERT_X509_GUID || l.SignatureType == signature.CERT_X509_SHA256_GUID {
			for _, s := range l.Signatures {
				if _, ok := detect[s.Owner]; ok {
					removals = append(removals, &builtinSignatureDataEntry{
						SignatureType: l.SignatureType,
						Data:          &s,
					})
				}
			}
		}
	}

	// Depending on the implementation of .RemoveSignature, this could be
	// expensive; however, we don't expect dbDebault to be particularly huge.
	for _, s := range removals {
		database.RemoveSignature(s.SignatureType, s.Data)
	}

	return &database, nil
}
