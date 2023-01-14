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

func TestGetCertsDb(t *testing.T) {
	db, _ := GetCerts("microsoft", "db")
	if len(*db) != 2 {
		t.Fatalf("GetCerts: not correct size, got %d, expected %d", len(*db), 2)
	}
}

func TestGetCertsKek(t *testing.T) {
	kek, _ := GetCerts("microsoft", "KEK")
	if len(*kek) != 1 {
		t.Fatalf("GetCerts: not correct size, got %d, expected %d", len(*kek), 1)
	}
}

func TestDefaultCertsDb(t *testing.T) {
	db, _ := GetDefaultCerts("db")
	if len(*db) != 2 {
		t.Fatalf("GetDefaultCerts: not correct size, got %d, expected %d", len(*db), 2)
	}
}

func TestDefaultCertsKek(t *testing.T) {
	kek, _ := GetDefaultCerts("KEK")
	if len(*kek) != 1 {
		t.Fatalf("GetDefaultCerts: not correct size, got %d, expected %d", len(*kek), 1)
	}
}
