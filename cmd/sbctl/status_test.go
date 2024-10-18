package main

import (
	"reflect"
	"testing"
	"testing/fstest"

	"github.com/foxboron/go-uefi/efi/efitest"
	"github.com/foxboron/sbctl/quirks"
)

var (
	out Status
)

func TestStatusOff(t *testing.T) {
	cmd := SetFS(
		efitest.SecureBootOff(),
		efitest.SetUpModeOn(),
	)

	if err := captureJsonOutput(&out, func() error {
		return RunStatus(cmd, []string{})
	}); err != nil {
		t.Fatal(err)
	}

	if out.SecureBoot != false {
		t.Fatal("secure boot is not disabled")
	}
}

func TestStatusOn(t *testing.T) {
	cmd := SetFS(efitest.SecureBootOn(),
		efitest.SetUpModeOff())

	if err := captureJsonOutput(&out, func() error {
		return RunStatus(cmd, []string{})
	}); err != nil {
		t.Fatal(err)
	}

	if out.SecureBoot != true {
		t.Fatal("secure boot is not enabled")
	}
}

func TestFQ0001DateMethod(t *testing.T) {
	cmd := SetFS(
		fstest.MapFS{"/sys/devices/virtual/dmi/id/bios_date": {Data: []byte("01/06/2023\n")}},
		fstest.MapFS{"/sys/devices/virtual/dmi/id/bios_version": {Data: []byte("A.30\n")}},
		fstest.MapFS{"/sys/devices/virtual/dmi/id/board_name": {Data: []byte("PRO Z790-A WIFI (MS-7E07)\n")}},
		fstest.MapFS{"/sys/devices/virtual/dmi/id/board_vendor": {Data: []byte("Micro-Star International Co., Ltd.\n")}},
		fstest.MapFS{"/sys/devices/virtual/dmi/id/chassis_type": {Data: []byte("3\n")}},
		fstest.MapFS{"/sys/devices/virtual/dmi/id/product_name": {Data: []byte("MS-7E07\n")}},
		efitest.SecureBootOn(),
		efitest.SetUpModeOff(),
	)

	if err := captureJsonOutput(&out, func() error {
		return RunStatus(cmd, []string{})
	}); err != nil {
		t.Fatal(err)
	}

	fq0001 := quirks.Quirk{}
	for _, quirk := range out.FirmwareQuirks {
		if quirk.ID == "FQ0001" {
			fq0001 = quirk
		}
	}

	if reflect.ValueOf(fq0001).IsZero() {
		t.Fatal("quirk not detected")
	} else if fq0001.Method != "date" {
		t.Fatal("expected 'date' method, got '" + fq0001.Method + "'")
	}
}

func TestFQ0001DeviceMethod(t *testing.T) {
	cmd := SetFS(
		fstest.MapFS{"/sys/devices/virtual/dmi/id/bios_date": {Data: []byte("12/29/2021\n")}},
		fstest.MapFS{"/sys/devices/virtual/dmi/id/bios_version": {Data: []byte("1.80\n")}},
		fstest.MapFS{"/sys/devices/virtual/dmi/id/board_name": {Data: []byte("MAG X570 TOMAHAWK WIFI (MS-7C84)\n")}},
		fstest.MapFS{"/sys/devices/virtual/dmi/id/board_vendor": {Data: []byte("Micro-Star International Co., Ltd.\n")}},
		fstest.MapFS{"/sys/devices/virtual/dmi/id/chassis_type": {Data: []byte("3\n")}},
		fstest.MapFS{"/sys/devices/virtual/dmi/id/product_name": {Data: []byte("MS-7C84\n")}},
		efitest.SecureBootOn(),
		efitest.SetUpModeOff(),
	)

	if err := captureJsonOutput(&out, func() error {
		return RunStatus(cmd, []string{})
	}); err != nil {
		t.Fatal(err)
	}

	fq0001 := quirks.Quirk{}
	for _, quirk := range out.FirmwareQuirks {
		if quirk.ID == "FQ0001" {
			fq0001 = quirk
		}
	}

	if reflect.ValueOf(fq0001).IsZero() {
		t.Fatal("quirk not detected")
	} else if fq0001.Method != "device_name" {
		t.Fatal("expected 'device_name' method, got '" + fq0001.Method + "'")
	}
}

func TestFQ0001ExplicitlyUnaffected(t *testing.T) {
	cmd := SetFS(
		fstest.MapFS{"/sys/devices/virtual/dmi/id/bios_date": {Data: []byte("03/31/2022\n")}},
		fstest.MapFS{"/sys/devices/virtual/dmi/id/bios_version": {Data: []byte("1.B0\n")}},
		fstest.MapFS{"/sys/devices/virtual/dmi/id/board_name": {Data: []byte("MAG Z490 TOMAHAWK (MS-7C80)\n")}},
		fstest.MapFS{"/sys/devices/virtual/dmi/id/board_vendor": {Data: []byte("Micro-Star International Co., Ltd.\n")}},
		fstest.MapFS{"/sys/devices/virtual/dmi/id/chassis_type": {Data: []byte("3\n")}},
		fstest.MapFS{"/sys/devices/virtual/dmi/id/product_name": {Data: []byte("MS-7C80\n")}},
		efitest.SecureBootOn(),
		efitest.SetUpModeOff(),
	)

	if err := captureJsonOutput(&out, func() error {
		return RunStatus(cmd, []string{})
	}); err != nil {
		t.Fatal(err)
	}

	fq0001 := quirks.Quirk{}
	for _, quirk := range out.FirmwareQuirks {
		if quirk.ID == "FQ0001" {
			fq0001 = quirk
		}
	}

	if !reflect.ValueOf(fq0001).IsZero() {
		t.Fatal("quirk got detected, with method '" + fq0001.Method + "'")
	}
}

func TestFQ0001WrongChassis(t *testing.T) {
	cmd := SetFS(
		fstest.MapFS{"/sys/devices/virtual/dmi/id/bios_date": {Data: []byte("01/06/2023\n")}},
		fstest.MapFS{"/sys/devices/virtual/dmi/id/bios_version": {Data: []byte("A.30\n")}},
		fstest.MapFS{"/sys/devices/virtual/dmi/id/board_name": {Data: []byte("PRO Z790-A WIFI (MS-7E07)\n")}},
		fstest.MapFS{"/sys/devices/virtual/dmi/id/board_vendor": {Data: []byte("Micro-Star International Co., Ltd.\n")}},
		fstest.MapFS{"/sys/devices/virtual/dmi/id/chassis_type": {Data: []byte("5\n")}},
		fstest.MapFS{"/sys/devices/virtual/dmi/id/product_name": {Data: []byte("MS-7E07\n")}},
		efitest.SecureBootOn(),
		efitest.SetUpModeOff(),
	)

	if err := captureJsonOutput(&out, func() error {
		return RunStatus(cmd, []string{})
	}); err != nil {
		t.Fatal(err)
	}

	fq0001 := quirks.Quirk{}
	for _, quirk := range out.FirmwareQuirks {
		if quirk.ID == "FQ0001" {
			fq0001 = quirk
		}
	}

	if !reflect.ValueOf(fq0001).IsZero() {
		t.Fatal("quirk got detected using '" + fq0001.Method + "' method")
	}
}

func TestFQ0001WrongVendor(t *testing.T) {
	cmd := SetFS(
		fstest.MapFS{"/sys/devices/virtual/dmi/id/bios_date": {Data: []byte("01/06/2023\n")}},
		fstest.MapFS{"/sys/devices/virtual/dmi/id/bios_version": {Data: []byte("A.30\n")}},
		fstest.MapFS{"/sys/devices/virtual/dmi/id/board_name": {Data: []byte("PRO Z790-A WIFI (MS-7E07)\n")}},
		fstest.MapFS{"/sys/devices/virtual/dmi/id/board_vendor": {Data: []byte("More-Security Issues Co., Ltd.\n")}},
		fstest.MapFS{"/sys/devices/virtual/dmi/id/chassis_type": {Data: []byte("3\n")}},
		fstest.MapFS{"/sys/devices/virtual/dmi/id/product_name": {Data: []byte("MS-7E07\n")}},
		efitest.SecureBootOn(),
		efitest.SetUpModeOff(),
	)

	if err := captureJsonOutput(&out, func() error {
		return RunStatus(cmd, []string{})
	}); err != nil {
		t.Fatal(err)
	}

	fq0001 := quirks.Quirk{}
	for _, quirk := range out.FirmwareQuirks {
		if quirk.ID == "FQ0001" {
			fq0001 = quirk
		}
	}

	if !reflect.ValueOf(fq0001).IsZero() {
		t.Fatal("quirk got detected using '" + fq0001.Method + "' method")
	}
}
