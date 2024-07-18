package dmi

import (
	"testing"
	"testing/fstest"
	"time"

	"github.com/foxboron/go-uefi/efi/efitest"
	"github.com/foxboron/sbctl/config"
)

func TestDMIParse(t *testing.T) {
	f := efitest.NewFS().With(
		fstest.MapFS{"/sys/devices/virtual/dmi/id/bios_date": {Data: []byte("01/13/2023\n")}},
		fstest.MapFS{"/sys/devices/virtual/dmi/id/bios_release": {Data: []byte("HorribleFirmwareRelease\n")}},
		fstest.MapFS{"/sys/devices/virtual/dmi/id/bios_vendor": {Data: []byte("EmbarrassedFirmwareVendor\n")}},
		fstest.MapFS{"/sys/devices/virtual/dmi/id/bios_version": {Data: []byte("InsecureFirmwareVersion\n")}},
		fstest.MapFS{"/sys/devices/virtual/dmi/id/board_name": {Data: []byte("BadBoardName\n")}},
		fstest.MapFS{"/sys/devices/virtual/dmi/id/board_vendor": {Data: []byte("IncompetentBoardVendor\n")}},
		fstest.MapFS{"/sys/devices/virtual/dmi/id/board_version": {Data: []byte("WeirdBoardVersion\n")}},
		fstest.MapFS{"/sys/devices/virtual/dmi/id/chassis_type": {Data: []byte("3\n")}},
		fstest.MapFS{"/sys/devices/virtual/dmi/id/product_family": {Data: []byte("MediocreProductFamily\n")}},
		fstest.MapFS{"/sys/devices/virtual/dmi/id/product_name": {Data: []byte("AwfulProductName\n")}},
		fstest.MapFS{"/sys/devices/virtual/dmi/id/product_sku": {Data: []byte("RandomProductSKU\n")}},
		fstest.MapFS{"/sys/devices/virtual/dmi/id/product_version": {Data: []byte("CrazyProductVersion\n")}},
		fstest.MapFS{"/sys/devices/virtual/dmi/id/sys_vendor": {Data: []byte("EvilSystemVendor\n")}},
		efitest.SecureBootOn(),
	).SetFS()

	dmiTable := ParseDMI(&config.State{Fs: f.ToAfero()})

	if dmiTable.BoardName != "BadBoardName" {
		t.Fatal("BoardName: expected 'BadBoardName', got '" + dmiTable.BoardName + "'")
	}
	if dmiTable.BoardVendor != "IncompetentBoardVendor" {
		t.Fatal("BoardVendor: expected 'IncompetentBoardVendor', got '" + dmiTable.BoardVendor + "'")
	}
	if dmiTable.BoardVersion != "WeirdBoardVersion" {
		t.Fatal("BoardVersion: expected 'WeirdBoardVersion', got '" + dmiTable.BoardVersion + "'")
	}
	if dmiTable.ChassisType != "3" {
		t.Fatal("ChassisType: expected '3', got '" + dmiTable.ChassisType + "'")
	}
	if dmiTable.FirmwareDate != time.Date(2023, 1, 13, 0, 0, 0, 0, time.UTC) {
		t.Fatal("FirmwareDate: expected '2023-01-13', got '" + dmiTable.FirmwareDate.Format("2006-01-02") + "'")
	}
	if dmiTable.FirmwareRelease != "HorribleFirmwareRelease" {
		t.Fatal("FirmwareRelease: expected 'HorribleFirmwareRelease', got '" + dmiTable.FirmwareRelease + "'")
	}
	if dmiTable.FirmwareVendor != "EmbarrassedFirmwareVendor" {
		t.Fatal("FirmwareVendor: expected 'EmbarrassedFirmwareVendor', got '" + dmiTable.FirmwareVendor + "'")
	}
	if dmiTable.FirmwareVersion != "InsecureFirmwareVersion" {
		t.Fatal("FirmwareVersion: expected 'InsecureFirmwareVersion', got '" + dmiTable.FirmwareVersion + "'")
	}
	if dmiTable.ProductFamily != "MediocreProductFamily" {
		t.Fatal("ProductFamily: expected 'MediocreProductFamily', got '" + dmiTable.ProductFamily + "'")
	}
	if dmiTable.ProductName != "AwfulProductName" {
		t.Fatal("ProductName: expected 'AwfulProductName', got '" + dmiTable.ProductName + "'")
	}
	if dmiTable.ProductSKU != "RandomProductSKU" {
		t.Fatal("ProductSKU: expected 'RandomProductSKU', got '" + dmiTable.ProductSKU + "'")
	}
	if dmiTable.ProductVersion != "CrazyProductVersion" {
		t.Fatal("ProductVersion: expected 'CrazyProductVersion' , got '" + dmiTable.ProductVersion + "'")
	}
	if dmiTable.SystemVendor != "EvilSystemVendor" {
		t.Fatal("SystemVendor: expected 'EvilSystemVendor', got '" + dmiTable.SystemVendor + "'")
	}
}
