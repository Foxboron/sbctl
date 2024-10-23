package sbctl

import (
	"errors"
	"os"

	"github.com/foxboron/go-uefi/efi/signature"
	"github.com/foxboron/go-uefi/efi/util"
	"github.com/foxboron/sbctl/fs"
	"github.com/google/go-attestation/attest"
	"github.com/spf13/afero"
)

var (
	ErrOprom      = errors.New("uefi has oprom")
	ErrNoEventlog = errors.New("no eventlog found")

	// For the sake of clarity we reserve this GUID for our SignatureList.
	// It says: OpROMIsAnnoying!
	eventlogGUID = *util.StringToGUID("4f52704f-494d-41736e-6e6f79696e6721")
)

func GetEventlogEvents(vfs afero.Fs, eventlog string) ([]attest.Event, error) {
	if _, err := vfs.Stat(eventlog); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, ErrNoEventlog
		}
		return nil, err
	}
	b, err := fs.ReadFile(vfs, eventlog)
	if err != nil {
		return nil, err
	}
	log, err := attest.ParseEventLog(b)
	if err != nil {
		return nil, err
	}
	// TODO: Hardcoded. Should probably make this dynamic
	return log.Events(attest.HashSHA256), nil
}

func CheckEventlogOprom(vfs afero.Fs, eventlog string) error {
	events, err := GetEventlogEvents(vfs, eventlog)
	if err != nil {
		return err
	}
	for _, event := range events {
		switch event.Type.String() {
		case "EV_EFI_BOOT_SERVICES_DRIVER":
			return ErrOprom
		}
	}
	return nil
}

func GetEventlogChecksums(vfs afero.Fs, eventlog string) (*signature.SignatureDatabase, error) {
	events, err := GetEventlogEvents(vfs, eventlog)
	if err != nil {
		return nil, err
	}
	sigdb := signature.NewSignatureDatabase()
	for _, event := range events {
		switch event.Type.String() {
		case "EV_EFI_BOOT_SERVICES_DRIVER":
			if sigdb.BytesExists(signature.CERT_SHA256_GUID, eventlogGUID, event.Digest) {
				continue
			}
			if err = sigdb.Append(signature.CERT_SHA256_GUID, eventlogGUID, event.Digest); err != nil {
				return nil, err
			}
		}
	}
	return sigdb, nil
}

func DetectTPMEventlog(sb *signature.SignatureDatabase) bool {
	for _, l := range *sb {
		for _, sig := range l.Signatures {
			if util.CmpEFIGUID(sig.Owner, eventlogGUID) {
				return true
			}
		}
	}
	return false
}
