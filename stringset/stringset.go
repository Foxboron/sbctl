package stringset

import (
	"fmt"
	"strings"

	"golang.org/x/exp/slices"
)

type StringSet struct {
	Allowed []string
	Value   string
}

func NewStringSet(allowed []string, d string) *StringSet {
	return &StringSet{
		Allowed: allowed,
		Value:   d,
	}
}

func (s StringSet) String() string {
	return s.Value
}

func (s *StringSet) Set(p string) error {
	if !slices.Contains(s.Allowed, p) {
		return fmt.Errorf("%s is not included in %s", p, strings.Join(s.Allowed, ","))
	}
	s.Value = p
	return nil
}

func (s *StringSet) Type() string {
	var allowedValues string

	for _, allowedValue := range s.Allowed {
		allowedValues += fmt.Sprintf("%v,", allowedValue)
	}

	allowedValues = strings.TrimRight(allowedValues, ",")

	return fmt.Sprintf("[%v]", allowedValues)
}
