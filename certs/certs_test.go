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

func TestGetOEMCertsDb(t *testing.T) {
	db, _ := GetOEMCerts("microsoft", "db")
	if len(*db) != 5 {
		t.Fatalf("GetOEMCerts: not correct size, got %d, expected %d", len(*db), 5)
	}
}

func TestGetOEMCertsKek(t *testing.T) {
	kek, _ := GetOEMCerts("microsoft", "KEK")
	if len(*kek) != 2 {
		t.Fatalf("GetOEMCerts: not correct size, got %d, expected %d", len(*kek), 2)
	}
}

func TestDefaultCertsDb(t *testing.T) {
	db, _ := GetDefaultCerts("db")
	if len(*db) != 5 {
		t.Fatalf("GetDefaultCerts: not correct size, got %d, expected %d", len(*db), 5)
	}
}

func TestDefaultCertsKek(t *testing.T) {
	kek, _ := GetDefaultCerts("KEK")
	if len(*kek) != 2 {
		t.Fatalf("GetDefaultCerts: not correct size, got %d, expected %d", len(*kek), 2)
	}
}
