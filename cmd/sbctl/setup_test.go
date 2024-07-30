package main

import (
	"os"
	"testing"
	"testing/fstest"

	"github.com/foxboron/go-uefi/efi/efitest"
	"github.com/foxboron/go-uefi/efi/signature"
	"github.com/foxboron/go-uefi/efivarfs/testfs"
	"github.com/foxboron/sbctl"
	"github.com/foxboron/sbctl/backend"
	"github.com/foxboron/sbctl/config"
	"github.com/foxboron/sbctl/hierarchy"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/simulator"
)

func mustBytes(f string) []byte {
	b, err := os.ReadFile(f)
	if err != nil {
		panic(err)
	}
	return b
}

func TestSetup(t *testing.T) {
	// Embed a TPM eventlog from out test suite for enroll-keys
	mapfs := fstest.MapFS{
		systemEventlog:        {Data: mustBytes("../../tests/tpm_eventlogs/t480s_eventlog")},
		"/boot/test.efi":      {Data: mustBytes("../../tests/binaries/test.pecoff")},
		"/boot/something.efi": {Data: mustBytes("../../tests/binaries/test.pecoff")},
	}

	conf := config.DefaultConfig()

	// Disable landlock in tests
	conf.Landlock = false

	// Include test file into our file config
	conf.Files = []*config.FileConfig{
		{"/boot/test.efi", "/boot/new.efi"},
		{"/boot/something.efi", ""},
	}

	state := &config.State{
		Fs: efitest.FromMapFS(mapfs),
		Efivarfs: testfs.NewTestFS().
			With(efitest.SetUpModeOn(),
				mapfs,
			).
			Open(),
		Config: conf,
	}

	// Ignore immutable in enroll-keys
	enrollKeysCmdOptions.IgnoreImmutable = true

	err := SetupInstallation(state)
	if err != nil {
		t.Fatalf("failed running SetupInstallation: %v", err)
	}

	// Check that we can sign and verify a file
	kh, err := backend.GetKeyHierarchy(state.Fs, state)
	if err != nil {
		t.Fatalf("can't get key hierarchy: %v", err)
	}
	ok, err := sbctl.VerifyFile(state, kh, hierarchy.Db, "/boot/new.efi")
	if err != nil {
		t.Fatalf("can't verify file: %v", err)
	}
	if !ok {
		t.Fatalf("file is not properly signed")
	}

	guid, err := conf.GetGUID(state.Fs)
	if err != nil {
		t.Fatalf("can't get owner guid")
	}

	sb, err := state.Efivarfs.Getdb()
	if err != nil {
		t.Fatalf("can't get db from efivarfs")
	}
	data := &signature.SignatureData{
		Owner: *guid,
		Data:  kh.Db.Certificate().Raw,
	}
	if !sb.SigDataExists(signature.CERT_X509_GUID, data) {
		t.Fatalf("can't find db cert in efivarfs")
	}

	sb, err = state.Efivarfs.GetKEK()
	if err != nil {
		t.Fatalf("can't get kek from efivarfs")
	}
	data = &signature.SignatureData{
		Owner: *guid,
		Data:  kh.KEK.Certificate().Raw,
	}
	if !sb.SigDataExists(signature.CERT_X509_GUID, data) {
		t.Fatalf("can't find kek cert in efivarfs")
	}

	sb, err = state.Efivarfs.GetPK()
	if err != nil {
		t.Fatalf("can't get pk from efivarfs")
	}
	data = &signature.SignatureData{
		Owner: *guid,
		Data:  kh.PK.Certificate().Raw,
	}
	if !sb.SigDataExists(signature.CERT_X509_GUID, data) {
		t.Fatalf("can't find pk cert in efivarfs")
	}
}

func TestSetupTPMKeys(t *testing.T) {
	// Embed a TPM eventlog from out test suite for enroll-keys
	mapfs := fstest.MapFS{
		systemEventlog:        {Data: mustBytes("../../tests/tpm_eventlogs/t480s_eventlog")},
		"/boot/test.efi":      {Data: mustBytes("../../tests/binaries/test.pecoff")},
		"/boot/something.efi": {Data: mustBytes("../../tests/binaries/test.pecoff")},
	}

	conf := config.DefaultConfig()

	// Disable landlock
	conf.Landlock = false

	// Set PK to be a TPM key
	conf.Keys.PK.Type = "tpm"
	conf.Keys.KEK.Type = "tpm"
	conf.Keys.Db.Type = "tpm"

	// Include test file into our file config
	conf.Files = []*config.FileConfig{
		{"/boot/test.efi", "/boot/new.efi"},
		{"/boot/something.efi", ""},
	}

	rwc, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatal(err)
	}
	defer rwc.Close()

	state := &config.State{
		TPM: func() transport.TPMCloser {
			return rwc
		},
		Fs: efitest.FromMapFS(mapfs),
		Efivarfs: testfs.NewTestFS().
			With(efitest.SetUpModeOn(),
				mapfs,
			).
			Open(),
		Config: conf,
	}

	// Ignore immutable in enroll-keys
	enrollKeysCmdOptions.IgnoreImmutable = true

	err = SetupInstallation(state)
	if err != nil {
		t.Fatalf("failed running SetupInstallation: %v", err)
	}

	// Check that we can sign and verify a file
	kh, err := backend.GetKeyHierarchy(state.Fs, state)
	if err != nil {
		t.Fatalf("can't get key hierarchy: %v", err)
	}
	ok, err := sbctl.VerifyFile(state, kh, hierarchy.Db, "/boot/new.efi")
	if err != nil {
		t.Fatalf("can't verify file: %v", err)
	}
	if !ok {
		t.Fatalf("file is not properly signed")
	}

	guid, err := conf.GetGUID(state.Fs)
	if err != nil {
		t.Fatalf("can't get owner guid")
	}

	sb, err := state.Efivarfs.Getdb()
	if err != nil {
		t.Fatalf("can't get db from efivarfs")
	}
	data := &signature.SignatureData{
		Owner: *guid,
		Data:  kh.Db.Certificate().Raw,
	}
	if !sb.SigDataExists(signature.CERT_X509_GUID, data) {
		t.Fatalf("can't find db cert in efivarfs")
	}

	sb, err = state.Efivarfs.GetKEK()
	if err != nil {
		t.Fatalf("can't get kek from efivarfs")
	}
	data = &signature.SignatureData{
		Owner: *guid,
		Data:  kh.KEK.Certificate().Raw,
	}
	if !sb.SigDataExists(signature.CERT_X509_GUID, data) {
		t.Fatalf("can't find kek cert in efivarfs")
	}

	sb, err = state.Efivarfs.GetPK()
	if err != nil {
		t.Fatalf("can't get pk from efivarfs")
	}
	data = &signature.SignatureData{
		Owner: *guid,
		Data:  kh.PK.Certificate().Raw,
	}
	if !sb.SigDataExists(signature.CERT_X509_GUID, data) {
		t.Fatalf("can't find pk cert in efivarfs")
	}
}
