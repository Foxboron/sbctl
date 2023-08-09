package hierarchy

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
