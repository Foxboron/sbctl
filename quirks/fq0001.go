package quirks

import (
	"time"

	"github.com/foxboron/sbctl/dmi"
)

var FQ0001 = Quirk {
	ID: "FQ0001",
	Name: "Defaults to executing on Secure Boot policy violation",
	Severity: "CRITICAL",
}

func HasFQ0001() bool {
	unaffectedVersions := []unaffectedVersion{
		// MSI MAG Z490 TOMAHAWK
		{Name: "MS-7C80", NameSrc: &dmi.Table.ProductName, NameStrict: true, Version: "1.B0", VersionSrc: &dmi.Table.FirmwareVersion},
		// MSI H310M PRO-C
		{Name: "MS-7D02", NameSrc: &dmi.Table.ProductName, NameStrict: true, Version: "1.20", VersionSrc: &dmi.Table.FirmwareVersion},
		// MSI MPG X670E CARBON WIFI
		{Name: "MS-7D70", NameSrc: &dmi.Table.ProductName, NameStrict: true, Version: "1.K0", VersionSrc: &dmi.Table.FirmwareVersion},
	}

	affectedDateRanges := []affectedDateRange{
		{From: time.Date(2022, 5, 10, 0, 0, 0, 0, time.UTC)},
	}

	affectedDevices := []affectedDevice{
		// MSI AMD boards
		{Name: "X570", NameSrc: &dmi.Table.BoardName, NameStrict: false, DateFrom: time.Date(2021, 12, 16, 0, 0, 0, 0, time.UTC)},
		{Name: "X470", NameSrc: &dmi.Table.BoardName, NameStrict: false, DateFrom: time.Date(2021, 9, 28, 0, 0, 0, 0, time.UTC)},
		{Name: "B550", NameSrc: &dmi.Table.BoardName, NameStrict: false, DateFrom: time.Date(2021, 12, 13, 0, 0, 0, 0, time.UTC)},
		{Name: "B450", NameSrc: &dmi.Table.BoardName, NameStrict: false, DateFrom: time.Date(2021, 12, 13, 0, 0, 0, 0, time.UTC)},
		{Name: "B350", NameSrc: &dmi.Table.BoardName, NameStrict: false, DateFrom: time.Date(2021, 11, 1, 0, 0, 0, 0, time.UTC)},
		{Name: "A520", NameSrc: &dmi.Table.BoardName, NameStrict: false, DateFrom: time.Date(2021, 9, 11, 0, 0, 0, 0, time.UTC)},
		// MSI Intel boards
		{Name: "Z590", NameSrc: &dmi.Table.BoardName, NameStrict: false, DateFrom: time.Date(2021, 9, 6, 0, 0, 0, 0, time.UTC)},
		{Name: "Z490", NameSrc: &dmi.Table.BoardName, NameStrict: false, DateFrom: time.Date(2021, 9, 30, 0, 0, 0, 0, time.UTC)},
		{Name: "B560", NameSrc: &dmi.Table.BoardName, NameStrict: false, DateFrom: time.Date(2021, 9, 9, 0, 0, 0, 0, time.UTC)},
		{Name: "B460", NameSrc: &dmi.Table.BoardName, NameStrict: false, DateFrom: time.Date(2021, 10, 22, 0, 0, 0, 0, time.UTC)},
		{Name: "H510", NameSrc: &dmi.Table.BoardName, NameStrict: false, DateFrom: time.Date(2021, 9, 10, 0, 0, 0, 0, time.UTC)},
		{Name: "H410", NameSrc: &dmi.Table.BoardName, NameStrict: false, DateFrom: time.Date(2021, 10, 22, 0, 0, 0, 0, time.UTC)},
	}

	if dmi.Table.BoardVendor == "Micro-Star International Co., Ltd." && dmi.Table.ChassisType == "3" {
		if isUnaffectedVersion(unaffectedVersions) {
			return false
		} else if isAffectedDate(affectedDateRanges) {
			FQ0001.Method = "date"
			return true
		} else if isAffectedDevice(affectedDevices) {
			FQ0001.Method = "device_name"
			return true
		}
	}

	return false
}
