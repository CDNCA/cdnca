package migrations

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

const (
	migration226UpSHA227   = "ec27c02f2461808e26f872011d6cdf6810100160039ddaeef30abddd3eaf845b"
	migration226DownSHA227 = "ffde321f4610b9be49f9ce3d4a8f962fed6e8b75964c35c95008de0b3ff75327"
	migration227UpSHA      = "8c0eb0c65e2b1e0d08f27bbaca740284b1206c4be4da3fa9f34512921a166bf0"
	migration227DownSHA    = "23fa7c4cdf4018cff88f666186007360f6921a4aec6e93676aca9a2773d1d130"
)

func TestNodeLineGroupMetadata227Contract(t *testing.T) {
	files := map[string]struct {
		name string
		sha  string
	}{
		"226 up":   {"226_system_configuration_tls_protocols.up.sql", migration226UpSHA227},
		"226 down": {"226_system_configuration_tls_protocols.down.sql", migration226DownSHA227},
		"227 up":   {"227_node_line_group_metadata.up.sql", migration227UpSHA},
		"227 down": {"227_node_line_group_metadata.down.sql", migration227DownSHA},
	}
	contents := make(map[string][]byte, len(files))
	for label, file := range files {
		payload, err := FS.ReadFile(file.name)
		if err != nil {
			t.Fatalf("read %s: %v", label, err)
		}
		contents[label] = payload
		if got := nodeLineGroupMetadata227SHA(payload); got != file.sha {
			t.Fatalf("migration %s checksum = %s, want %s", label, got, file.sha)
		}
	}

	up := string(contents["227 up"])
	for _, required := range []string{
		"(SELECT count(*) FROM schema_migrations) <> 226",
		"version = 226 AND migration_id = '226_system_configuration_tls_protocols'",
		"checksum_sha256 = '" + migration226UpSHA227 + "'",
		"down_checksum_sha256 = '" + migration226DownSHA227 + "'",
		"ADD COLUMN region text NOT NULL DEFAULT ''",
		"ADD COLUMN resolved_value text NOT NULL DEFAULT ''",
		"ADD COLUMN note text NOT NULL DEFAULT ''",
		"ADD COLUMN sort_order integer NOT NULL DEFAULT 100",
		"'lg-' || replace(id::text, '-', '')",
		"'lg-' || replace(line_group_id::text, '-', '')",
		"node_line_groups_scope_resolved_value_unique UNIQUE (tenant_scope_id, resolved_value)",
		"node_line_group_revisions_endpoint_count_bounds CHECK (endpoint_count BETWEEN 0 AND 512)",
		"NEW.region IS NOT DISTINCT FROM OLD.region",
		"NEW.resolved_value IS NOT DISTINCT FROM OLD.resolved_value",
		"NEW.note IS NOT DISTINCT FROM OLD.note",
		"NEW.sort_order IS NOT DISTINCT FROM OLD.sort_order",
		"snapshot_region IS DISTINCT FROM NEW.region",
		"snapshot_resolved_value IS DISTINCT FROM NEW.resolved_value",
		"expected_count IS DISTINCT FROM actual_health_count THEN",
		"jsonb_build_object(",
		"FROM node_line_group_revisions revision",
		"request.target_group_id = revision.line_group_id",
		"revision.revision = (request.response_body->'group'->>'revision')::bigint",
		"?& ARRAY['region', 'resolved_value', 'note', 'sort_order']",
		"USING ERRCODE = 'P2272'",
		"USING ERRCODE = 'P2270'",
	} {
		if !strings.Contains(up, required) {
			t.Errorf("up migration missing %q", required)
		}
	}
	if strings.Contains(up, "actual_count < 1") {
		t.Fatal("up migration still rejects an empty current line-group revision")
	}
	receiptBackfill := up[strings.Index(up, "UPDATE node_scheduling_write_requests request"):]
	if strings.Contains(receiptBackfill, "FROM node_line_groups line_group") {
		t.Fatal("historical idempotency receipts are backfilled from the mutable current group projection")
	}

	down := string(contents["227 down"])
	for _, required := range []string{
		"(SELECT count(*) FROM schema_migrations) <> 227",
		"version = 227 AND migration_id = '227_node_line_group_metadata'",
		"checksum_sha256 = '" + migration227UpSHA + "'",
		"endpoint_count = 0",
		"resolved_value <> 'lg-' || replace(id::text, '-', '')",
		"resolved_value <> 'lg-' || replace(line_group_id::text, '-', '')",
		"USING ERRCODE = 'P2271'",
		"DROP CONSTRAINT node_line_groups_scope_resolved_value_unique",
		"node_line_group_revisions_endpoint_count_check CHECK (endpoint_count BETWEEN 1 AND 512)",
		"DROP COLUMN resolved_value",
	} {
		if !strings.Contains(down, required) {
			t.Errorf("down migration missing %q", required)
		}
	}

	combined := strings.ToUpper(up + down)
	for _, forbidden := range []string{
		" CASCADE", "\nTRUNCATE ", "DROP SCHEMA", "DELETE FROM SCHEMA_MIGRATIONS",
		"__UP_SHA256__", "__DOWN_SHA256__",
	} {
		if strings.Contains(combined, forbidden) {
			t.Errorf("migration contains forbidden token %q", forbidden)
		}
	}
}

func nodeLineGroupMetadata227SHA(payload []byte) string {
	digest := sha256.Sum256(payload)
	return hex.EncodeToString(digest[:])
}
