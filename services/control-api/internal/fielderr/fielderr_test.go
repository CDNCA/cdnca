package fielderr

import (
	"errors"
	"fmt"
	"testing"
)

var errInvalid = errors.New("invalid input")

func TestNewKeepsSentinelAndField(t *testing.T) {
	err := fmt.Errorf("save: %w", New(errInvalid, "limits.domains", OutOfRange))
	if !errors.Is(err, errInvalid) {
		t.Fatal("field error must still match the domain sentinel")
	}
	located, ok := As(err)
	if !ok || located.Field != "limits.domains" || located.Reason != OutOfRange {
		t.Fatalf("As = %+v, %v", located, ok)
	}
	if _, ok := As(errInvalid); ok {
		t.Fatal("a bare sentinel has no field")
	}
}

func TestWithinPrefixesPath(t *testing.T) {
	cases := map[string]string{"name": "spec.name", "group_ids[1]": "spec.group_ids[1]", "[0]": "spec[0]"}
	for field, want := range cases {
		located, _ := As(Within(New(errInvalid, field, Invalid), "spec"))
		if located.Field != want {
			t.Errorf("Within(%q) = %q, want %q", field, located.Field, want)
		}
	}
	if Within(errInvalid, "spec") != errInvalid {
		t.Fatal("Within must not change an error without a field")
	}
	if !errors.Is(Within(New(errInvalid, "name", Required), "spec"), errInvalid) {
		t.Fatal("Within must keep the sentinel")
	}
}
