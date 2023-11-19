package certs

import (
	"fmt"
	"os"

	"github.com/foxboron/go-uefi/efi"
	"github.com/foxboron/go-uefi/efi/attributes"
	"github.com/foxboron/go-uefi/efi/signature"
	"github.com/foxboron/go-uefi/efi/util"
)

var (
	efiGlobalGuid                 = util.EFIGUID{0x8be4df61, 0x93ca, 0x11d2, [8]uint8{0xaa, 0x0d, 0x00, 0xe0, 0x98, 0x03, 0x2b, 0x8c}}
	defaultSignatureDatabaseNames = map[string]string{
		"db":  "dbDefault",
		"KEK": "KEKDefault",
		"PK":  "PKDefault",
	}
)

type builtinSignatureDataEntry struct {
	SignatureType util.EFIGUID
	Data          *signature.SignatureData
}

func GetBuiltinCertificates(db string) (*signature.SignatureDatabase, error) {
	defaultName, ok := defaultSignatureDatabaseNames[db]
	if !ok {
		return nil, fmt.Errorf("%s is an unrecognized firmware database", db)
	}
	attr, buf, err := attributes.ReadEfivarsWithGuid(defaultName, efiGlobalGuid)
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
		return nil, fmt.Errorf("vendor default database is non-volatile (and is vulnerable to being tampered with)")
	}

	database, err := signature.ReadSignatureDatabase(buf)
	if err != nil {
		return nil, err
	}

	// Remove vendor certificates that are already covered by the built-in vendor database.
	// TODO: Do we actually want this? The machine might be enrolled with more Microsoft certs then sbctl actually covers

	detect := map[util.EFIGUID]string{}
	for k, v := range oemGUID {
		detect[v] = k
	}

	removals := make([]*builtinSignatureDataEntry, 0, 8)

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

func GetSignatureDatabase(s string) (*signature.SignatureDatabase, error) {
	switch s {
	case "db":
		return efi.Getdb()
	case "KEK":
		return efi.GetKEK()
	case "PK":
		return efi.GetPK()
	}
	return nil, nil
}

func BuiltinSignatureOwners() ([]string, error) {
	ret := []string{}
	for _, sbDatabase := range []string{"db", "KEK", "PK"} {
		db, err := GetSignatureDatabase(sbDatabase)
		if err != nil {
			return nil, err
		}
		dbDefault, err := GetBuiltinCertificates(sbDatabase)
		if err != nil {
			return nil, err
		}
		for _, siglist := range *dbDefault {
			if db.Exists(siglist.SignatureType, siglist) {
				ret = append(ret, fmt.Sprintf("builtin-%s", sbDatabase))
			}
		}
	}
	return ret, nil
}
