// +build integration

package tests

import (
	"log"
	"os"
	"os/exec"
	"testing"

	"github.com/foxboron/sbctl/tests/utils"
)

func TestKeyEnrollment(t *testing.T) {
	conf := utils.NewConfig()
	conf.AddFile("sbctl")
	utils.WithVM(conf,
		func(vm *utils.TestVM) {
			t.Run("Enroll Keys", vm.RunTest("./integrations/enroll_keys_test.go"))
		})
}

func TestMain(m *testing.M) {
	cmd := exec.Command("go", "build", "../cmd/sbctl")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		log.Fatal(err)
	}
	os.Exit(m.Run())
}
