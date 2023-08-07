package hierarchy

type Hierarchy uint8

const (
	PK Hierarchy = iota + 1
	KEK
	Db
)

func (h Hierarchy) String() string {
	switch h {
	case PK:
		return "PK"
	case KEK:
		return "KEK"
	case Db:
		return "db"
	default:
		return "unknown"
	}
}
