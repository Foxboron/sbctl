package dmi

import (
	"strings"
	"time"

	"github.com/foxboron/sbctl/config"
	"github.com/foxboron/sbctl/fs"
)

var Table = DMI{}

type DMI struct {
	BoardName       string    `json:"board_name"`
	BoardVendor     string    `json:"board_vendor"`
	BoardVersion    string    `json:"board_version"`
	ChassisType     string    `json:"chassis_type"`
	FirmwareDate    time.Time `json:"firmware_date"`
	FirmwareRelease string    `json:"firmware_release"`
	FirmwareVendor  string    `json:"firmware_vendor"`
	FirmwareVersion string    `json:"firmware_version"`
	ProductFamily   string    `json:"product_family"`
	ProductName     string    `json:"product_name"`
	ProductSKU      string    `json:"product_sku"`
	ProductVersion  string    `json:"product_version"`
	SystemVendor    string    `json:"system_vendor"`
}

func ParseDMI(state *config.State) DMI {
	dmi := DMI{}

	readValue := func(filename string) string {
		f, _ := fs.ReadFile(state.Fs, "/sys/devices/virtual/dmi/id/"+filename)
		return strings.TrimSpace(string(f))
	}

	dmi.BoardName = readValue("board_name")
	dmi.BoardVendor = readValue("board_vendor")
	dmi.BoardVersion = readValue("board_version")
	dmi.ChassisType = readValue("chassis_type")
	dmi.FirmwareDate, _ = time.Parse("01/02/2006", readValue("bios_date"))
	dmi.FirmwareRelease = readValue("bios_release")
	dmi.FirmwareVendor = readValue("bios_vendor")
	dmi.FirmwareVersion = readValue("bios_version")
	dmi.ProductFamily = readValue("product_family")
	dmi.ProductName = readValue("product_name")
	dmi.ProductSKU = readValue("product_sku")
	dmi.ProductVersion = readValue("product_version")
	dmi.SystemVendor = readValue("sys_vendor")

	return dmi
}
