package httpapi

import (
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/site"
)

func TestSITE14CompatibilityStatusAdapter(t *testing.T) {
	tests := []struct {
		code  int
		state site.OperationalStatus
	}{
		{code: 200, state: site.OperationalStatusNormal},
		{code: 512, state: site.OperationalStatusPackageExpired},
		{code: 513, state: site.OperationalStatusTrafficExceeded},
		{code: 514, state: site.OperationalStatusLocked},
	}
	for _, test := range tests {
		state, ok := statusStateFromCompatibilityCode(test.code)
		if !ok || state != test.state {
			t.Fatalf("statusStateFromCompatibilityCode(%d)=%q,%t", test.code, state, ok)
		}
		code, ok := compatibilityCodeFromStatusState(test.state)
		if !ok || code != test.code {
			t.Fatalf("compatibilityCodeFromStatusState(%q)=%d,%t", test.state, code, ok)
		}
	}
	if _, ok := statusStateFromCompatibilityCode(500); ok {
		t.Fatal("unexpected compatibility mapping for 500")
	}
}
