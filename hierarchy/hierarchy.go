package hierarchy

import "github.com/foxboron/go-uefi/efivar"

type Hierarchy uint8

const (
	PK Hierarchy = iota + 1
	KEK
	Db
	Dbx
)

func (h Hierarchy) String() string {
	switch h {
	case PK:
		return "PK"
	case KEK:
		return "KEK"
	case Db:
		return "db"
	case Dbx:
		return "dbx"
	default:
		return "unknown"
	}
}

func (h Hierarchy) Description() string {
	switch h {
	case PK:
		return "Platform Key"
	case KEK:
		return "Key Exchange Key"
	case Db:
		return "Database Key"
	case Dbx:
		return "Forbidden Database"
	default:
		return "unknown"
	}
}

func (h Hierarchy) Efivar() efivar.Efivar {
	switch h {
	case PK:
		return efivar.PK
	case KEK:
		return efivar.KEK
	case Db:
		return efivar.Db
	case Dbx:
		return efivar.Dbx
	default:
		return efivar.Efivar{}
	}
}
