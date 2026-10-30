package updater

import (
	"errors"
	"fmt"
	"testing"
)

type codedHealthError struct{ code string }

func (e codedHealthError) Error() string      { return e.code }
func (e codedHealthError) HealthCode() string { return e.code }

// node-runtime-upgrade: a health probe failure that names its cause (the
// native runtime switch) keeps its code in the upgrade status.
func TestHealthFailureCodeKeepsRuntimeCode(t *testing.T) {
	cases := map[error]string{
		ErrHealth: "HEALTH_FAILED",
		fmt.Errorf("wrapped: %w", codedHealthError{"RUNTIME_PRECHECK_FAILED"}): "RUNTIME_PRECHECK_FAILED",
		codedHealthError{"lower_case"}: "HEALTH_FAILED",
		errors.New("plain"):             "HEALTH_FAILED",
	}
	for err, want := range cases {
		if got := healthFailureCode(err); got != want {
			t.Fatalf("healthFailureCode(%v) = %s, want %s", err, got, want)
		}
	}
	if !errors.Is(errorForCode("RUNTIME_RELOAD_FAILED"), ErrHealth) {
		t.Fatal("a runtime switch failure must map to ErrHealth")
	}
}
