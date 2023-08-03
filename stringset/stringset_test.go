package stringset

import (
	"testing"
)

func TestStringSet(t *testing.T) {
	for _, tt := range []struct {
		name       string
		allowed    []string
		value      string
		wantType   string
		wantError  bool
		wantString string
	}{
		{
			name:      "no string allowed",
			value:     "abc",
			wantType:  "[]",
			wantError: true,
		},
		{
			name:       "set value",
			allowed:    []string{"pk"},
			value:      "pk",
			wantType:   "[pk]",
			wantError:  false,
			wantString: "pk",
		},
		{
			name:      "set wrong value",
			allowed:   []string{"pk"},
			value:     "pj",
			wantType:  "[pk]",
			wantError: true,
		},
		{
			name:       "multiple allowed",
			allowed:    []string{"pk", "kek", "db"},
			value:      "db",
			wantType:   "[pk,kek,db]",
			wantString: "db",
		},
		{
			name:      "fail on multiple allowed",
			allowed:   []string{"pk", "kek", "db"},
			value:     "da",
			wantType:  "[pk,kek,db]",
			wantError: true,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			stringSet := NewStringSet(tt.allowed, "")

			if stringSet.Type() != tt.wantType {
				t.Errorf("got type of stringSet: %v, but want: %v", stringSet.Type(), tt.wantType)
			}

			err := stringSet.Set(tt.value)
			if (err != nil && !tt.wantError) || (err == nil && tt.wantError) {
				t.Fatalf("expected error: %v, but got %v", tt.wantError, err)
			}

			if stringSet.String() != tt.wantString {
				t.Errorf("expected stringSet value %v, but got %v", tt.wantString, stringSet.String())
			}
		})
	}
}
