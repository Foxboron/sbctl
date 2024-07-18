package sbctl

import (
	"errors"
	"testing"

	"github.com/spf13/afero"
)

var (
	tests = []struct {
		Result    error
		File      string
		Checksums int
	}{
		{
			Result:    nil,
			File:      "tests/tpm_eventlogs/t480s_eventlog",
			Checksums: 0,
		},
		{
			Result:    ErrOprom,
			File:      "tests/tpm_eventlogs/t14s_eventlog",
			Checksums: 11,
		},
		{
			Result:    ErrOprom,
			File:      "tests/tpm_eventlogs/t14_eventlog",
			Checksums: 7,
		},
		{
			Result:    ErrNoEventlog,
			File:      "tests/tpm_eventlogs/this_file_does_not_exist",
			Checksums: 0,
		},
	}
)

func TestParseEventlog(t *testing.T) {
	for _, test := range tests {
		err := CheckEventlogOprom(afero.NewOsFs(), test.File)
		if !errors.Is(err, test.Result) {
			t.Fatalf("Test case file '%s' not correct. Expected '%s', got '%s'", test.File, test.Result, err.Error())
		}
	}
}

func TestEventlogChecksums(t *testing.T) {
	for _, test := range tests {
		digests, err := GetEventlogChecksums(afero.NewOsFs(), test.File)
		if err != nil {
			continue
		}
		if len((*digests)) == 0 {
			continue
		}
		if len((*digests)[0].Signatures) != test.Checksums {
			t.Fatalf("Test case file '%s' not correct. Expected '%d', got '%d'", test.File, test.Checksums, len((*digests)))
		}
	}
}
