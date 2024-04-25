//go:build integration
// +build integration

package main

import (
	"testing"

	"github.com/foxboron/sbctl/tests/utils"
	"github.com/hugelgupf/vmtest/guest"
	. "github.com/onsi/gomega"
)

func TestListEnrolledKeys(t *testing.T) {
	g := NewWithT(t)

	guest.SkipIfNotInVM(t)

	out, err := utils.ExecWithOutput("sbctl list-enrolled-keys")
	g.Expect(err).ToNot(HaveOccurred(), out)
	g.Expect(out).To(SatisfyAll(
		MatchRegexp("Platform Key"),
		MatchRegexp("Key Exchange Key"),
		MatchRegexp("Database Key")))
}
