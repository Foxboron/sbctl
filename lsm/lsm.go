package lsm

import (
	"bufio"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/foxboron/sbctl/config"
	"github.com/landlock-lsm/go-landlock/landlock"

	ll "github.com/landlock-lsm/go-landlock/landlock/syscall"
)

var (
	rules []landlock.Rule

	// Include file truncation
	truncFile landlock.AccessFSSet = ll.AccessFSExecute | ll.AccessFSWriteFile | ll.AccessFSReadFile | ll.AccessFSTruncate
)

func TruncFile(p string) landlock.FSRule {
	return landlock.PathAccess(truncFile, p)
}

// pcscRealLibraryPath returns the path to libpcsclite_real.so.1 when sbctl
// is linked against the PC/SC spy wrapper. The real library is installed next
// to the loaded libpcsclite.so.1, but that directory is distro- and
// architecture-specific (for example /usr/lib64 or /usr/lib/x86_64-linux-gnu).
func pcscRealLibraryPath() string {
	maps, err := os.Open("/proc/self/maps")
	if err != nil {
		return ""
	}
	defer maps.Close()

	scanner := bufio.NewScanner(maps)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 6 {
			continue
		}

		path := strings.TrimSuffix(fields[len(fields)-1], " (deleted)")
		if filepath.Base(path) != "libpcsclite.so.1" {
			continue
		}

		realLibrary := filepath.Join(filepath.Dir(path), "libpcsclite_real.so.1")
		if _, err := os.Stat(realLibrary); err == nil {
			return realLibrary
		}
	}

	if err := scanner.Err(); err != nil {
		return ""
	}

	return ""
}

func LandlockRulesFromConfig(conf *config.Config) {
	roFiles := []string{
		"/sys/kernel/security/tpm0/binary_bios_measurements",
		// Go timezone reads /etc/localtime.
		"/etc/localtime",
	}

	// YubiKeys require access to pcsclite lib
	if path := pcscRealLibraryPath(); path != "" {
		roFiles = append(roFiles, path)
	}

	rules = append(rules,
		landlock.RODirs(
			"/sys/devices/virtual/dmi/id/",
		).IgnoreIfMissing(),
		landlock.RWDirs(
			filepath.Dir(conf.Keydir),
			// It seems to me that RWFiles should work on efivars, but it doesn't.
			// TODO: Lock this down to individual files?
			"/sys/firmware/efi/efivars/",
		).IgnoreIfMissing(),
		landlock.ROFiles(roFiles...).IgnoreIfMissing(),
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
