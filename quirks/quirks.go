package quirks

import (
	"strings"
	"time"

	"github.com/foxboron/sbctl/config"
	"github.com/foxboron/sbctl/dmi"
)

type Quirk struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Link     string `json:"link"`
	Severity string `json:"severity"`
	Method   string `json:"method"`
}

type affectedDevice struct {
	Name       string
	NameSrc    *string
	NameStrict bool
	DateFrom   time.Time
	DateTo     time.Time
}

type unaffectedVersion struct {
	Name       string
	NameSrc    *string
	NameStrict bool
	Version    string
	VersionSrc *string
}

type affectedDateRange struct {
	From time.Time
	To   time.Time
}

func isUnaffectedVersion(list []unaffectedVersion) bool {
	for _, item := range list {
		if (item.NameStrict && item.Name == *item.NameSrc || !item.NameStrict && strings.Contains(*item.NameSrc, item.Name)) &&
			item.Version == *item.VersionSrc {
			return true
		}
	}
	return false
}

func isAffectedDate(list []affectedDateRange) bool {
	for _, item := range list {
		if (item.From.IsZero() || !dmi.Table.FirmwareDate.Before(item.From)) && (item.To.IsZero() || !dmi.Table.FirmwareDate.After(item.To)) {
			return true
		}
	}
	return false
}

func isAffectedDevice(list []affectedDevice) bool {
	for _, item := range list {
		if (item.NameStrict && item.Name == *item.NameSrc || !item.NameStrict && strings.Contains(*item.NameSrc, item.Name)) &&
			(item.DateFrom.IsZero() || !dmi.Table.FirmwareDate.Before(item.DateFrom)) && (item.DateTo.IsZero() || !dmi.Table.FirmwareDate.After(item.DateTo)) {
			return true
		}
	}
	return false
}

func CheckFirmwareQuirks(state *config.State) []Quirk {
	dmi.Table = dmi.ParseDMI(state)
	quirks := []Quirk{}

	if HasFQ0001() {
		quirks = append(quirks, FQ0001)
	}

	for i := range quirks {
		quirks[i].Link = "https://github.com/Foxboron/sbctl/wiki/" + quirks[i].ID
	}

	return quirks
}
