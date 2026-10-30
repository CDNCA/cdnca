package retentioncleanup

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// reviewedAuditReaders lists the production files that read audit_events.
// Archiving (FX01) keeps the rows these readers depend on in audit_events:
// rows referenced by a foreign key, each scope's chain head, the newest row of
// every (scope, action, resource_type, resource_id) group, and all cache.*
// rows (migration 331, audit_event_pinned_331). Older rows of a group, such as
// past idempotency receipts, may leave once their retention expires. A new
// reader must be checked against those rules (extend audit_event_pinned in a
// migration if it needs more) and then added here.
var reviewedAuditReaders = []string{
	// fix-transfer: an idempotent replay of a site transfer reads the newest
	// site.transfer row of the new site (its copied/released lists); the
	// newest row of a (scope, action, resource) group is always kept.
	"site/transfer.go",
	"analyticslog/block_state_postgres.go",
	"audit/audittest/audittest.go", // integration-test helper only, not a production reader
	"audit/log.go",
	"auditlog/store.go",
	"cachecontrol/job_command_receipt.go",
	"cachecontrol/lifecycle.go",
	"cachecontrol/store.go",
	"cachecontrolhttp/reader.go",
	"cnameallocation/store.go",
	"controlupgrade/create_store.go",
	"controlupgrade/runtime_action.go",
	"dashboard/store.go",
	// integration-test fixture (build tag integration): reads the chain head
	// to append a row, which archiving always keeps
	"edgepublish/fixture_shared_integration.go",
	"errorpagecontrol/asset.go",
	"errorpagecontrol/reconcile.go",
	"identity/platform_admin_recovery.go",
	"identitysessionhttp/store.go",
	"jobhttp/command_postgres.go",
	"node/registration_store.go",
	"nodepresence/configuration_scopes.go",
	"notification/settlement.go",
	"notificationcontrol/store.go",
	"observabilitylog/store.go",
	"retentioncleanup/audit_archive.go",
	"site/conditional_origin.go",
}

func TestAuditEventReadersAreReviewedForArchiving(t *testing.T) {
	root, err := filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}
	reader := regexp.MustCompile(`(FROM|JOIN)\s+audit_events\b`)
	var found []string
	err = filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil || entry.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return err
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if reader.Match(raw) {
			relative, _ := filepath.Rel(root, path)
			found = append(found, filepath.ToSlash(relative))
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	slices.Sort(found)
	expected := slices.Clone(reviewedAuditReaders)
	slices.Sort(expected)
	if !slices.Equal(found, expected) {
		t.Fatalf("audit_events readers changed; review them against the archive pin rules.\nfound:    %v\nreviewed: %v", found, expected)
	}
}
