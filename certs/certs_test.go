package certs

import (
	"reflect"
	"testing"
)

func TestGetVendors(t *testing.T) {
	oems := GetVendors()
	if !reflect.DeepEqual(oems, []string{"microsoft"}) {
		t.Fatalf("GetVendors: not the same")
	}
}

func TestGetCerts(t *testing.T) {
	db, _ := GetCerts("microsoft")
	if len(*db) != 2 {
		t.Fatalf("GetCerts: not correct size, got %d, expected %d", len(*db), 2)
	}
}

func TestDefaultCerts(t *testing.T) {
	db, _ := GetDefaultCerts()
	if len(*db) != 2 {
		t.Fatalf("GetDefaultCerts: not correct size, got %d, expected %d", len(*db), 2)
	}
}
