// Package artifactsynctest seeds artifactsync state directly for tests of
// the packages that read downloaded artifacts (IP library lookups, library
// gates). It bypasses verification on purpose: tests use it to store bytes
// that do not match their entry as well.
package artifactsynctest

import (
	"encoding/json"
	"testing"

	"github.com/cdnca/cdnca/libs/entitlement/artifactcatalog"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// SeedDownloaded records entry as an active catalog entry downloaded at its
// revision with content as its bytes (stored under entry.SHA256, len(content)
// bytes). The local revision only moves forward (migration trigger).
func SeedDownloaded(t testing.TB, pool *pgxpool.Pool, entry artifactcatalog.Entry, content []byte) {
	t.Helper()
	var capability []byte
	if entry.RequiresCapability != nil {
		capability, _ = json.Marshal(entry.RequiresCapability)
	}
	if entry.Encryption == "" {
		entry.Encryption = artifactcatalog.EncryptionNone
	}
	ctx := t.Context()
	for _, statement := range []struct {
		query string
		args  []any
	}{
		{`INSERT INTO artifact_catalog_entries(artifact_id,kind,version,revision,sha256,size,media_type,requires_feature,
			requires_capability,resident,encryption,status,delivery_id,first_seen_at,updated_at)
			VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,'active',$12,now(),now())
			ON CONFLICT (artifact_id) DO UPDATE SET version=EXCLUDED.version,revision=EXCLUDED.revision,sha256=EXCLUDED.sha256,
			size=EXCLUDED.size,requires_feature=EXCLUDED.requires_feature,requires_capability=EXCLUDED.requires_capability,
			status='active',withdrawn_at=NULL,updated_at=now()`,
			[]any{entry.ArtifactID, entry.Kind, entry.Version, int64(entry.Revision), entry.SHA256, int64(len(content)),
				entry.MediaType, entry.RequiresFeature, capability, entry.Resident, entry.Encryption, uuid.New()}},
		{`INSERT INTO artifact_objects(sha256,size,content,stored_at) VALUES($1,$2,$3,now()) ON CONFLICT (sha256) DO NOTHING`,
			[]any{entry.SHA256, int64(len(content)), content}},
		{`INSERT INTO local_artifacts(artifact_id,current_revision,current_sha256,current_version,current_requires_capability,
			downloaded_at,updated_at) VALUES($1,$2,$3,$4,$5,now(),now())
			ON CONFLICT (artifact_id) DO UPDATE SET current_revision=EXCLUDED.current_revision,current_sha256=EXCLUDED.current_sha256,
			current_version=EXCLUDED.current_version,current_requires_capability=EXCLUDED.current_requires_capability,
			downloaded_at=EXCLUDED.downloaded_at,updated_at=EXCLUDED.updated_at`,
			[]any{entry.ArtifactID, int64(entry.Revision), entry.SHA256, entry.Version, capability}},
	} {
		if _, err := pool.Exec(ctx, statement.query, statement.args...); err != nil {
			t.Fatalf("seed downloaded artifact %s: %v", entry.ArtifactID, err)
		}
	}
}

// IPIntelBase is an ipintel/base entry at revision whose bytes are content
// (sha256 is the entry digest to store them under).
func IPIntelBase(revision uint64, buildID, sha256 string, capabilityVersion int) artifactcatalog.Entry {
	return artifactcatalog.Entry{ArtifactID: artifactcatalog.IPIntelBaseID, Kind: artifactcatalog.KindIPIntel,
		MediaType: artifactcatalog.MediaTypeIPIntel, Encryption: artifactcatalog.EncryptionNone, Resident: true,
		Revision: revision, Version: buildID, SHA256: sha256,
		RequiresCapability: &artifactcatalog.Capability{Name: "IP_INTEL", MinVersion: capabilityVersion}}
}
