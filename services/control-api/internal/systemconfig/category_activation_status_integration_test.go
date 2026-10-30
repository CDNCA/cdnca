package systemconfig

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func TestActivationStatusJSONContract(t *testing.T) {
	fixture := newSystemConfigFixture(t)
	manager, err := NewCategoryManager(fixture.service, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx := t.Context()
	t.Run("no publications is an empty array without writes", func(t *testing.T) {
		items, err := manager.ActivationStatus(ctx, fixture.platform, 1)
		if err != nil {
			t.Fatal(err)
		}
		body, err := json.Marshal(map[string]any{"revision": int64(1), "publications": items})
		if err != nil || string(body) != `{"publications":[],"revision":1}` {
			t.Fatalf("publication response = %s, err=%v; want an empty JSON array", body, err)
		}
		for _, table := range []string{"system_configuration_streams", "system_configuration_revisions", "system_configuration_edge_publications", "audit_events"} {
			if countRows(t, fixture.pool, table) != 0 {
				t.Fatalf("activation status read wrote to %s", table)
			}
		}
	})

	// Seed a valid historical publication under the formal schema, including its
	// required audit. A queued rollout is not evidence of a node execution ACK.
	draft, err := fixture.service.CreateDraft(ctx, fixture.platform,
		createDraftRequest(0, "status-draft", ProjectBootstrapConfiguration()))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.service.RecordPreflight(ctx, fixture.platform,
		passingPreflight(draft.Revision, draft.SnapshotSHA256, "status-preflight")); err != nil {
		t.Fatal(err)
	}
	publicationID, configID, rolloutID, requestID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	snapshot := []byte(`{"version":1}`)
	digest := sha256.Sum256(snapshot)
	now := systemConfigTestNow
	if err := pgx.BeginFunc(ctx, fixture.pool, func(tx pgx.Tx) error {
		for _, statement := range []struct {
			query string
			args  []any
		}{
			{`INSERT INTO edge_configuration_scopes(scope_id,source_revision,updated_at) VALUES($1,1,$2)`,
				[]any{fixture.tenant.ScopeID, now}},
			{`INSERT INTO config_versions(id,configuration_scope_id,canonical_snapshot,canonical_snapshot_sha256,
				generator_name,generator_version,status,idempotency_key,request_digest,created_at,published_at)
				VALUES($1,$2,$3,$4,'status-test','1','releasable','status-config',$4,$5,$5)`,
				[]any{configID, fixture.tenant.ScopeID, snapshot, digest[:], now}},
			{`INSERT INTO rollouts(id,configuration_scope_id,config_version_id,action,status,idempotency_key,
				request_digest,request_id,correlation_id,activation_timeout_ms,observation_window_ms,
				required_consecutive_successes,deadline_at,created_at,queued_at,updated_at,contract_version)
				VALUES($1,$2,$3,'apply','queued','status-rollout',$4,$5,$5,1000,1000,1,$6,$7,$7,$7,1)`,
				[]any{rolloutID, fixture.tenant.ScopeID, configID, digest[:], requestID, now.Add(time.Hour), now}},
			{`INSERT INTO edge_config_publications(id,configuration_scope_id,source_revision,idempotency_key,
				request_digest,request_id,correlation_id,canonical_snapshot_sha256,artifact_sha256,
				config_version_id,rollout_id,node_count,created_at,expected_source_revision,actor_user_id,
				actor_scope_id,target_kind,target_snapshot_sha256,contract_version)
				VALUES($1,$2,1,'status-publication',$3,$4,$4,$3,$3,$5,$6,1,$7,1,$8,$9,'explicit',$3,1)`,
				[]any{publicationID, fixture.tenant.ScopeID, digest[:], requestID, configID, rolloutID, now,
					fixture.platform.UserID, fixture.platform.ScopeID}},
			{`INSERT INTO system_configuration_edge_publications(platform_scope_id,system_revision,
				system_snapshot_sha256,tenant_scope_id,tenant_source_revision,publication_id,config_version_id,
				rollout_id,artifact_sha256,reason_code,created_at)
				SELECT platform_scope_id,revision,snapshot_sha256,$3,1,$4,$5,$6,$7,'system_configuration_activated',$8
				FROM system_configuration_revisions WHERE platform_scope_id=$1 AND revision=$2`,
				[]any{fixture.platform.ScopeID, draft.Revision, fixture.tenant.ScopeID, publicationID,
					configID, rolloutID, digest[:], now}},
		} {
			if _, err := tx.Exec(ctx, statement.query, statement.args...); err != nil {
				return err
			}
		}
		return fixture.service.auditor.Append(ctx, tx, audit.Event{
			ScopeID: fixture.platform.ScopeID, ActorUserID: &fixture.platform.UserID,
			Action: "edge_publication.publish", ResourceType: "edge_config_publication",
			ResourceID: publicationID.String(), RequestID: requestID.String(), Result: "success",
			Payload: map[string]any{},
		})
	}); err != nil {
		t.Fatal(err)
	}
	t.Run("historical publication retains every field", func(t *testing.T) {
		items, err := manager.ActivationStatus(ctx, fixture.platform, draft.Revision)
		if err != nil || len(items) != 1 || !items[0].CreatedAt.Equal(now) {
			t.Fatalf("historical publications = %#v, err=%v", items, err)
		}
		want := []ActivationStatus{{
			TenantScopeID: fixture.tenant.ScopeID.String(), TenantSourceRevision: 1,
			PublicationID: publicationID.String(), ConfigVersionID: configID.String(),
			RolloutID: rolloutID.String(), RolloutState: "queued", ArtifactSHA256: hex.EncodeToString(digest[:]),
			ReasonCode: "system_configuration_activated", CreatedAt: items[0].CreatedAt,
		}}
		if !reflect.DeepEqual(items, want) {
			t.Fatalf("historical publications = %#v, want %#v", items, want)
		}
		body, err := json.Marshal(map[string]any{"revision": draft.Revision, "publications": items})
		if err != nil {
			t.Fatal(err)
		}
		var response struct {
			Revision     int64             `json:"revision"`
			Publications []json.RawMessage `json:"publications"`
		}
		if err := json.Unmarshal(body, &response); err != nil || response.Revision != draft.Revision || len(response.Publications) != 1 {
			t.Fatalf("historical JSON response = %s, err=%v", body, err)
		}
	})
	t.Run("tenant cannot read platform publication", func(t *testing.T) {
		if items, err := manager.ActivationStatus(ctx, fixture.tenant, draft.Revision); !errors.Is(err, ErrPermissionDenied) || items != nil {
			t.Fatalf("tenant publications = %#v, err=%v", items, err)
		}
	})
	t.Run("revoked read permission still fails closed", func(t *testing.T) {
		if _, err := fixture.pool.Exec(ctx, `DELETE FROM role_permissions
			WHERE role_id IN (SELECT role_id FROM role_assignments WHERE scope_id=$1 AND user_id=$2)
			AND permission_name='system_configuration.read'`, fixture.platform.ScopeID, fixture.platform.UserID); err != nil {
			t.Fatal(err)
		}
		if items, err := manager.ActivationStatus(ctx, fixture.platform, draft.Revision); !errors.Is(err, ErrPermissionDenied) || items != nil {
			t.Fatalf("revoked publications = %#v, err=%v", items, err)
		}
	})
}
