package lsm

import (
	"path/filepath"

	"github.com/foxboron/sbctl/config"
	"github.com/landlock-lsm/go-landlock/landlock"
)

var (
	rules []landlock.Rule
)

func LandlockRulesFromConfig(conf *config.Config) {
	rules = append(rules, landlock.RWDirs(
		filepath.Dir(conf.Keydir),
		// It seems to me that RWFiles should work on efivars, but it doesn't.
		// TODO: Lock this down to induvidual files?
		"/sys/firmware/efi/efivars/",
	).IgnoreIfMissing(),
		landlock.ROFiles(
			"/sys/kernel/security/tpm0/binary_bios_measurements",
			// Go timezone reads /etc/localtime
			"/etc/localtime",
		).IgnoreIfMissing(),
		landlock.RWFiles(
			conf.GUID,
			conf.FilesDb,
			conf.BundlesDb,
		).IgnoreIfMissing(),
	)
}

func RestrictAdditionalPaths(r ...landlock.Rule) {
	rules = append(rules, r...)
}

func Restrict() error {
	// TODO: For debug logging
	// for _, r := range rules {
	// 	fmt.Println(r)
	// }
	landlock.V5.BestEffort().RestrictNet()
	return landlock.V5.BestEffort().RestrictPaths(rules...)
}
