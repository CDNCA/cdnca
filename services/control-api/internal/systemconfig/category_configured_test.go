package systemconfig

import (
	"encoding/json"
	"testing"

	"github.com/cdnca/cdnca/libs/edgeconfig"
)

// the node detail shows DDoS protection as not
// configured only when the platform never saved it; the category document
// says whether the revision stores the category's own value.
func TestCategoryDocumentSaysWhetherTheCategoryWasSaved(t *testing.T) {
	bootstrap, err := projectBootstrapRevision()
	if err != nil {
		t.Fatal(err)
	}
	for _, category := range []string{CategoryDDoSProtection, CategoryNodeMonitoring, CategoryAccessLogFields} {
		if document := categoryDocument(bootstrap, category, 0, 0, []string{}, bootstrap); document.Configured {
			t.Fatalf("bootstrap %s configured = true, want false", category)
		}
	}
	if document := categoryDocument(bootstrap, CategoryNginx, 0, 0, []string{}, bootstrap); !document.Configured {
		t.Fatal("bootstrap nginx configured = false, want true (always carried)")
	}

	saved := bootstrap
	saved.Configuration = cloneConfiguration(bootstrap.Configuration)
	ddos := edgeconfig.DefaultDDoSProtection()
	saved.Configuration.DDoSProtection = &ddos
	document := categoryDocument(saved, CategoryDDoSProtection, 1, 1, []string{}, saved)
	if !document.Configured {
		t.Fatal("saved ddos_protection configured = false, want true")
	}
	encoded, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	var wire map[string]any
	if err := json.Unmarshal(encoded, &wire); err != nil || wire["configured"] != true {
		t.Fatalf("wire configured = %v (%v), want true", wire["configured"], err)
	}
}

// active_configured says whether the active
// revision holds the category's own value. The revision stream is shared, so
// another category being active says nothing about DDoS protection.
func TestCategoryDocumentSaysWhetherTheActiveRevisionHoldsTheCategory(t *testing.T) {
	bootstrap, err := projectBootstrapRevision()
	if err != nil {
		t.Fatal(err)
	}
	ddos := edgeconfig.DefaultDDoSProtection()
	withDDoS := cloneConfiguration(bootstrap.Configuration)
	withDDoS.DDoSProtection = &ddos
	head := bootstrap
	head.Configuration = withDDoS

	t.Run("other categories active, DDoS first saved as a draft", func(t *testing.T) {
		otherActive := cloneConfiguration(bootstrap.Configuration) // an active revision without DDoS protection
		document := categoryDocument(head, CategoryDDoSProtection, 2, 1, []string{CategoryDDoSProtection}, Revision{Configuration: otherActive})
		if !document.Configured || document.ActiveConfigured {
			t.Fatalf("configured=%v active_configured=%v, want true/false", document.Configured, document.ActiveConfigured)
		}
	})
	t.Run("DDoS published, a draft saved over it", func(t *testing.T) {
		document := categoryDocument(head, CategoryDDoSProtection, 3, 2, []string{CategoryDDoSProtection}, Revision{Configuration: withDDoS})
		if !document.Configured || !document.ActiveConfigured {
			t.Fatalf("configured=%v active_configured=%v, want true/true", document.Configured, document.ActiveConfigured)
		}
		encoded, err := json.Marshal(document)
		if err != nil {
			t.Fatal(err)
		}
		var wire map[string]any
		if err := json.Unmarshal(encoded, &wire); err != nil || wire["active_configured"] != true {
			t.Fatalf("wire active_configured = %v (%v), want true", wire["active_configured"], err)
		}
	})
	t.Run("nothing activated yet", func(t *testing.T) {
		if document := categoryDocument(head, CategoryNginx, 1, 0, []string{}, bootstrap); document.ActiveConfigured {
			t.Fatal("active_configured before any activation = true, want false")
		}
	})
}

// the document carries the active revision's snapshot hash, so a
// head restored to the active configuration (same canonical snapshot) reads as carrying no change; none before
// any activation.
func TestCategoryDocumentCarriesTheActiveSnapshot(t *testing.T) {
	bootstrap, err := projectBootstrapRevision()
	if err != nil {
		t.Fatal(err)
	}
	active := bootstrap
	active.Revision, active.Status = 1, StatusActive
	restored := bootstrap
	restored.Revision, restored.Status = 3, StatusDraft
	document := categoryDocument(restored, CategoryNginx, 3, 1, []string{}, active)
	if document.ActiveSnapshotSHA256 == "" || document.ActiveSnapshotSHA256 != document.SnapshotSHA256 {
		t.Fatalf("restored head snapshot %q, active %q; want equal", document.SnapshotSHA256, document.ActiveSnapshotSHA256)
	}
	encoded, err := json.Marshal(categoryDocument(bootstrap, CategoryNginx, 0, 0, []string{}, bootstrap))
	if err != nil {
		t.Fatal(err)
	}
	var wire map[string]any
	if err := json.Unmarshal(encoded, &wire); err != nil {
		t.Fatal(err)
	}
	if _, present := wire["active_snapshot_sha256"]; present {
		t.Fatalf("active_snapshot_sha256 present before any activation: %v", wire)
	}
}
