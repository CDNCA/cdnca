package nodescheduler

import (
	"errors"
	"fmt"
	"testing"
)

func TestLineGroupInUseErrorIsReferenceConflict(t *testing.T) {
	err := fmt.Errorf("delete node line group: %w", &LineGroupInUseError{Sites: 1})
	var inUse *LineGroupInUseError
	if !errors.Is(err, ErrReferenceConflict) || !errors.As(err, &inUse) || inUse.Sites != 1 {
		t.Fatalf("err = %v", err)
	}
	if errors.Is(err, ErrMarketSupplyInUse) || errors.Is(err, ErrRevisionConflict) {
		t.Fatalf("err matches an unrelated sentinel: %v", err)
	}
}
