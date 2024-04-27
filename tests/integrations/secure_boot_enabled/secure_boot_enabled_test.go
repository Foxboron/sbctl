//go:build integration
// +build integration

package main

import (
	"testing"

	"github.com/foxboron/go-uefi/efi"
	"github.com/foxboron/sbctl/tests/utils"
	"github.com/hugelgupf/vmtest/guest"
	. "github.com/onsi/gomega"
)

func TestSecureBootEnabled(t *testing.T) {
	g := NewWithT(t)

	guest.SkipIfNotInVM(t)

	g.Expect(efi.GetSecureBoot()).To(BeTrue(), "should be in secure boot mode")
	g.Expect(efi.GetSetupMode()).To(BeFalse(), "should not be in setup mode")

	out, err := utils.ExecWithOutput("sbctl status")
	g.Expect(err).ToNot(HaveOccurred(), out)
	g.Expect(out).To(MatchRegexp("Secure Boot:.*Enabled"))
}
