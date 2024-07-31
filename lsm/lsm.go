package lsm

import (
	"log/slog"
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
		"/sys/devices/virtual/dmi/id/",
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
			// Enable the TPM devices by default if they exist
			"/dev/tpm0", "/dev/tpmrm0",
		).IgnoreIfMissing(),
	)
}

func RestrictAdditionalPaths(r ...landlock.Rule) {
	rules = append(rules, r...)
}

func Restrict() error {
	for _, r := range rules {
		slog.Debug("landlock", slog.Any("rule", r))
	}
	landlock.V5.BestEffort().RestrictNet()
	return landlock.V5.BestEffort().RestrictPaths(rules...)
}
