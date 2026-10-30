package ccv2

import (
	"errors"
	"os"
	"testing"
)

// testdata/stored-1.0.33-challenge.source.json is a challenge policy as release
// 1.0.33 stored it (no proof-of-work, page lifetime, pass binding or key
// rotation parameters). The 1.0.35 baseline does not run that shape: the node
// refuses the source like any other invalid challenge.
func TestCompileSourceRefusesChallengeStoredBy133(t *testing.T) {
	source, err := os.ReadFile("testdata/stored-1.0.33-challenge.source.json")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := CompileSource(source, Binding{BindingID: "018f1000-0000-7000-8000-000000000030", BindingRevision: 1,
		PublicationID: "018f1000-0000-7000-8000-000000000031"}); !errors.Is(err, ErrInvalidSource) {
		t.Fatalf("CompileSource(1.0.33 challenge) = %v, want ErrInvalidSource", err)
	}
}
