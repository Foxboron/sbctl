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

func TestEnrollKeys(t *testing.T) {
	g := NewWithT(t)

	guest.SkipIfNotInVM(t)

	g.Expect(efi.GetSecureBoot()).To(BeFalse(), "should not be in secure boot mode")
	g.Expect(efi.GetSetupMode()).To(BeTrue(), "should be in setup mode")

	utils.Exec("rm -rf /usr/share/secureboot")
	utils.Exec("sbctl status")
	utils.Exec("sbctl create-keys")
	out, err := utils.ExecWithOutput("sbctl enroll-keys")
	g.Expect(err).To(HaveOccurred())
	g.Expect(out).To(MatchRegexp("Could not find any TPM Eventlog in the system"))

	out, err = utils.ExecWithOutput("sbctl enroll-keys --yes-this-might-brick-my-machine")
	g.Expect(err).ToNot(HaveOccurred(), out)

	g.Expect(efi.GetSetupMode()).To(BeFalse(), "should no longer be in setup mode")
}
