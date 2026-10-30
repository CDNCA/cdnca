package certificateasset

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestCertificatePublicationIntentWiredToEveryBindingMutation39(t *testing.T) {
	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve certificate asset test path")
	}
	source, err := os.ReadFile(filepath.Join(filepath.Dir(currentFile), "store.go"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(source)
	for _, mutation := range []struct {
		name, start, end, operation string
	}{
		{name: "activate", start: "func (s *Store) activate", end: "func loadCurrentBindingsForAssetAndLockSites", operation: `"publish"`},
		{name: "bind", start: "func (s *Store) bind", end: "func (s *Store) unbind", operation: `"publish"`},
		{name: "unbind", start: "func (s *Store) unbind", end: "func (s *Store) delete", operation: `"unpublish"`},
	} {
		body := certificateAssetSourceSlice39(t, text, mutation.start, mutation.end)
		bindingInsert := strings.Index(body, "INSERT INTO certificate_site_binding_facts")
		intentInsert := strings.Index(body, "appendCertificatePublicationIntent(")
		if bindingInsert < 0 || intentInsert < bindingInsert || !strings.Contains(body, mutation.operation) {
			t.Errorf("%s does not append its %s publication intent after the binding fact", mutation.name, mutation.operation)
		}
	}
}

func TestCertificatePublicationIntentInsertContainsOnlyFrozenPublicIdentity39(t *testing.T) {
	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve certificate asset test path")
	}
	source, err := os.ReadFile(filepath.Join(filepath.Dir(currentFile), "store.go"))
	if err != nil {
		t.Fatal(err)
	}
	body := certificateAssetSourceSlice39(t, string(source),
		"func appendCertificatePublicationIntent", "func loadCurrentBindingsForAssetAndLockSites")
	for _, required := range []string{
		"INSERT INTO certificate_publication_intents",
		"tenant_scope_id", "site_id", "binding_revision", "operation",
		"asset_id", "version_id", "is_default", "request_id",
		"actor_scope_id", "actor_user_id",
	} {
		if !strings.Contains(body, required) {
			t.Errorf("publication intent insert missing %q", required)
		}
	}
	for _, forbidden := range []string{"private_key", "ciphertext", "nonce", "metadata", "certificate_pem"} {
		if strings.Contains(strings.ToLower(body), forbidden) {
			t.Errorf("publication intent insert contains private material field %q", forbidden)
		}
	}
}

func certificateAssetSourceSlice39(t *testing.T, source, startMarker, endMarker string) string {
	t.Helper()
	start := strings.Index(source, startMarker)
	if start < 0 {
		t.Fatalf("source marker %q is missing", startMarker)
	}
	end := strings.Index(source[start+len(startMarker):], endMarker)
	if end < 0 {
		t.Fatalf("source marker %q after %q is missing", endMarker, startMarker)
	}
	return source[start : start+len(startMarker)+end]
}
