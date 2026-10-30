package apikeycredential_test

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/apikeycredential"
)

func TestCredentialIsSealedAndRedacted(t *testing.T) {
	var credential apikeycredential.Credential
	if credential.Valid() {
		t.Fatal("zero credential is valid")
	}
	if _, err := json.Marshal(credential); err == nil {
		t.Fatal("credential JSON serialization succeeded")
	}
	for _, rendered := range []string{fmt.Sprint(credential), fmt.Sprintf("%#v", credential)} {
		if !strings.Contains(rendered, "redacted") {
			t.Fatalf("credential format = %q, want redacted", rendered)
		}
	}
}
