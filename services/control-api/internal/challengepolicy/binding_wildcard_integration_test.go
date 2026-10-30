//go:build integration

package challengepolicy

import (
	"context"
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/challengepublication"
	"github.com/cdnca/cdnca/services/control-api/internal/edgepublish"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// A wildcard site ("*.x.example") binds the JS challenge of a policy for one
// host under the wildcard (053), then switches to another host's policy; the
// binding names the active policy's host. An exact site still binds only its
// domain. (Before 345 and this change the first stage failed: ErrConflict.)
func TestStageChallengeBindingOnWildcardSite(t *testing.T) {
	fixture := newFixture(t, allowGate())
	ctx := context.Background()
	wildcardSite := insertSite(t, fixture.pool, fixture.tenantA, fixture.ownerA.UserID, "*.wild-b.example")
	www := createServicePolicy(t, fixture, wildcardSite, "www.wild-b.example", "wild-www")
	api := createServicePolicy(t, fixture, wildcardSite, "api.wild-b.example", "wild-api")
	exact := createServicePolicy(t, fixture, fixture.siteA, siteDomain(t, fixture, fixture.siteA), "exact")
	var tenantID uuid.UUID
	if err := fixture.pool.QueryRow(ctx, `SELECT tenant_id FROM access_scopes WHERE id=$1`, fixture.tenantA).Scan(&tenantID); err != nil {
		t.Fatal(err)
	}
	stage := func(policy Policy, key string) (int64, error) {
		secret := seedChallengeSecretRollout(t, fixture, key)
		request := challengepublication.BindingRequest{
			TenantScopeID: fixture.tenantA, TenantID: tenantID, SiteID: policy.SiteID, Host: policy.Host,
			PolicyID: policy.ID, PolicyRevision: policy.Revision, Secret: secret,
			Actor:          edgepublish.Actor{ScopeID: fixture.ownerA.ScopeID, UserID: fixture.ownerA.UserID},
			IdempotencyKey: key, RequestID: key, CorrelationID: key,
		}
		var revision int64
		err := pgx.BeginFunc(ctx, fixture.pool, func(tx pgx.Tx) error {
			var stageErr error
			revision, stageErr = stageChallengeBinding(ctx, tx, request, sha256.Sum256([]byte(key)), fixture.now)
			return stageErr
		})
		return revision, err
	}
	if revision, err := stage(www, "bind-www"); err != nil || revision != 1 {
		t.Fatalf("wildcard site binding = (%d, %v)", revision, err)
	}
	if revision, err := stage(api, "bind-api"); err != nil || revision != 2 {
		t.Fatalf("wildcard site switch to another host's policy = (%d, %v)", revision, err)
	}
	var host string
	if err := fixture.pool.QueryRow(ctx, `SELECT host FROM challenge_site_bindings_138 WHERE site_id=$1`,
		wildcardSite).Scan(&host); err != nil || host != "api.wild-b.example" {
		t.Fatalf("wildcard binding host = %q, %v", host, err)
	}
	if revision, err := stage(exact, "bind-exact"); err != nil || revision != 1 {
		t.Fatalf("exact site binding = (%d, %v)", revision, err)
	}
	// A host the site does not serve never stages (the policy cannot exist
	// either: 053); a forged request is refused before any write.
	forged := www
	forged.Host = "www.other.example"
	if _, err := stage(forged, "bind-forged"); !errors.Is(err, ErrConflict) {
		t.Fatalf("forged host: %v, want ErrConflict", err)
	}
}

func siteDomain(t *testing.T, fixture *testFixture, siteID uuid.UUID) string {
	t.Helper()
	var domain string
	if err := fixture.pool.QueryRow(context.Background(), `SELECT domain FROM sites WHERE id=$1`, siteID).Scan(&domain); err != nil {
		t.Fatal(err)
	}
	return domain
}

// seedChallengeSecretRollout records the secret rollout and config version a
// binding revision references (their own publication is out of scope here).
func seedChallengeSecretRollout(t *testing.T, fixture *testFixture, key string) challengepublication.SecretPublication {
	t.Helper()
	ctx := context.Background()
	configID, rolloutID := uuid.New(), uuid.New()
	digest := sha256.Sum256([]byte(key))
	if err := pgx.BeginFunc(ctx, fixture.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SET LOCAL session_replication_role = replica`); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO config_versions(id,configuration_scope_id,canonical_snapshot,
			canonical_snapshot_sha256,generator_name,generator_version,status,idempotency_key,request_digest,created_at,published_at)
			VALUES($1,$2,'{}',$3,'challenge-secret','1.0.0','releasable',$4,$3,$5,$5)`,
			configID, fixture.tenantA, digest[:], "secret-"+key, fixture.now); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO rollouts(id,configuration_scope_id,config_version_id,action,status,
			idempotency_key,request_digest,request_id,correlation_id,activation_timeout_ms,observation_window_ms,
			required_consecutive_successes,deadline_at,created_at,queued_at,updated_at)
			VALUES($1,$2,$3,'apply','completed',$4,$5,$6,$7,60000,60000,1,$8,$9,$9,$9)`,
			rolloutID, fixture.tenantA, configID, "secret-"+key, digest[:], uuid.New(), uuid.New(), fixture.now.Add(time.Hour), fixture.now)
		return err
	}); err != nil {
		t.Fatalf("seed secret rollout: %v", err)
	}
	return challengepublication.SecretPublication{RolloutID: rolloutID, ConfigVersionID: configID, Revision: 1}
}
