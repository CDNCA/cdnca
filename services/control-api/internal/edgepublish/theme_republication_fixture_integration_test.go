//go:build integration

package edgepublish

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"io"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/errorpagecontrol"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Theme republication fixtures: a second manual tenant
// scope in the same database, an error page publisher with the real snapshot
// compiler, and the platform administrator who activates themes.

type themeContentStore struct{}

func (themeContentStore) Capabilities() errorpagecontrol.ObjectStoreCapabilities {
	return errorpagecontrol.ObjectStoreCapabilities{ImmutableStaging: true, ConditionalFinalize: true,
		TrustedMetadata: true, ImmutableReads: true, PreservesStagingAlias: true}
}
func (themeContentStore) PutStaging(context.Context, errorpagecontrol.ObjectRef, []byte, string) (errorpagecontrol.ObjectInfo, error) {
	return errorpagecontrol.ObjectInfo{}, errorpagecontrol.ErrUnavailable
}
func (themeContentStore) Open(context.Context, errorpagecontrol.ObjectRef, string) (io.ReadCloser, error) {
	return nil, errorpagecontrol.ErrObjectNotFound
}
func (themeContentStore) Finalize(context.Context, errorpagecontrol.ObjectRef, errorpagecontrol.ObjectRef, errorpagecontrol.ObjectInfo) (errorpagecontrol.ObjectInfo, error) {
	return errorpagecontrol.ObjectInfo{}, errorpagecontrol.ErrUnavailable
}
func (themeContentStore) Stat(context.Context, errorpagecontrol.ObjectRef) (errorpagecontrol.ObjectInfo, error) {
	return errorpagecontrol.ObjectInfo{}, errorpagecontrol.ErrObjectNotFound
}
func (themeContentStore) Delete(context.Context, errorpagecontrol.ObjectRef) error { return nil }

type themeBundleSigner struct{ key ed25519.PrivateKey }

func (themeBundleSigner) SigningKeyID() string { return "theme-republish-test" }
func (signer themeBundleSigner) SigningPublicKey() ed25519.PublicKey {
	return signer.key.Public().(ed25519.PublicKey)
}
func (signer themeBundleSigner) Sign(_ context.Context, body []byte) ([]byte, error) {
	return ed25519.Sign(signer.key, body), nil
}

// EnableErrorPagePublisher gives the scope's system republisher an error page
// publisher (as the production runtime does) and returns it.
func (scope *SystemRepublishScope) EnableErrorPagePublisher(t *testing.T) *ErrorPagePublisher {
	t.Helper()
	publisher := scope.NewErrorPagePublisher(t)
	if err := scope.republisher.WithErrorPagePublisher(publisher); err != nil {
		t.Fatal(err)
	}
	return publisher
}

// NewErrorPagePublisher is an error page publisher with the real snapshot
// compiler, not given to the system republisher.
func (scope *SystemRepublishScope) NewErrorPagePublisher(t *testing.T) *ErrorPagePublisher {
	t.Helper()
	compiler, err := errorpagecontrol.NewProductionSnapshotCompiler(themeContentStore{},
		themeBundleSigner{key: ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x5a}, ed25519.SeedSize))})
	if err != nil {
		t.Fatal(err)
	}
	publisher, err := NewErrorPagePublisher(scope.fixture.service, compiler)
	if err != nil {
		t.Fatal(err)
	}
	return publisher
}

// SeedErrorPagePublication records the first error page publication revision
// (what a platform error page rule change does), so tenant scopes can publish.
func (scope *SystemRepublishScope) SeedErrorPagePublication(t *testing.T) {
	t.Helper()
	if err := pgx.BeginFunc(t.Context(), scope.Pool, func(tx pgx.Tx) error {
		_, err := errorpagecontrol.AppendThemePublication(t.Context(), tx, scope.fixture.platformUserID,
			scope.fixture.platformScopeID, "seed-error-pages", "seed-error-pages", publishTestClock)
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

// PlatformAdmin is the platform scope and a platform user who may manage the
// system configuration (themes).
func (scope *SystemRepublishScope) PlatformAdmin(t *testing.T) (uuid.UUID, uuid.UUID) {
	t.Helper()
	if _, err := scope.Pool.Exec(t.Context(), `INSERT INTO role_permissions(role_id,permission_name)
		SELECT assignment.role_id,permission.name FROM role_assignments assignment
		CROSS JOIN (VALUES ('system_configuration.read'),('system_configuration.manage')) permission(name)
		WHERE assignment.scope_id=$1 AND assignment.user_id=$2 ON CONFLICT DO NOTHING`,
		scope.fixture.platformScopeID, scope.fixture.platformUserID); err != nil {
		t.Fatal(err)
	}
	return scope.fixture.platformScopeID, scope.fixture.platformUserID
}

// PublishErrorPages publishes the scope's error pages as the platform
// operator, the way a tenant's first error page publish reaches the nodes.
func (scope *SystemRepublishScope) PublishErrorPages(t *testing.T, publisher *ErrorPagePublisher, key string,
	nodeIDs ...uuid.UUID) ErrorPagePublishResult {
	t.Helper()
	request := scope.fixture.publishRequest(key, nodeIDs[0])
	request.NodeIDs = append([]uuid.UUID(nil), nodeIDs...)
	result, err := publisher.Publish(t.Context(), ErrorPagePublishRequest{PublishRequest: request, TenantID: scope.fixture.tenantID})
	if err != nil {
		t.Fatalf("publish error pages: %v", err)
	}
	return result
}

// SecondScope is another manual tenant scope of the same database, with its
// own system republisher.
func (scope *SystemRepublishScope) SecondScope(t *testing.T) *SystemRepublishScope {
	t.Helper()
	second := seedSecondPublishTenant(t, scope.fixture)
	republisher, err := NewSystemRepublisher(second.service, SystemRepublisherConfig{
		WorkerID: "syspub-test-b", LeaseDuration: time.Minute, RetryDelay: 0,
	})
	if err != nil {
		t.Fatal(err)
	}
	return &SystemRepublishScope{Pool: second.pool, ScopeID: second.scopeID, UserID: second.userID,
		fixture: second, republisher: republisher}
}

// ErrorPageRollouts is the scope's error page rollouts in publication revision
// order (the fixture clock is fixed, so created_at does not order them), with
// the publication revision their snapshot binds and their target nodes.
type ErrorPageRollout struct {
	ID       uuid.UUID
	Snapshot []byte
	NodeIDs  []uuid.UUID
}

func (scope *SystemRepublishScope) ErrorPageRollouts(t *testing.T) []ErrorPageRollout {
	t.Helper()
	rows, err := scope.Pool.Query(t.Context(), `SELECT rollout.id,artifact.wire_bytes,
		ARRAY(SELECT DISTINCT node_id FROM node_deployments WHERE rollout_id=rollout.id ORDER BY node_id)
		FROM rollouts rollout JOIN configuration_artifacts artifact ON artifact.config_version_id=rollout.config_version_id
		 AND artifact.ordinal=1 AND artifact.media_type=$2
		WHERE rollout.configuration_scope_id=$1
		ORDER BY (convert_from(artifact.wire_bytes,'UTF8')::jsonb->'binding'->>'publication_revision')::bigint,rollout.id`,
		scope.ScopeID, errorpagecontrol.ProductionSnapshotMediaType)
	if err != nil {
		t.Fatal(err)
	}
	items, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (ErrorPageRollout, error) {
		var item ErrorPageRollout
		return item, row.Scan(&item.ID, &item.Snapshot, &item.NodeIDs)
	})
	if err != nil {
		t.Fatal(err)
	}
	return items
}

// RunWithErrors runs the republisher once and returns RunOnce's error.
func (scope *SystemRepublishScope) RunWithErrors(t *testing.T) (bool, error) {
	t.Helper()
	return scope.republisher.RunOnce(t.Context())
}

// TenantIdentity is the scope's tenant and its tenant_owner user (PA-26).
func (scope *SystemRepublishScope) TenantIdentity() (tenantID, scopeID, userID uuid.UUID) {
	return scope.fixture.tenantID, scope.fixture.scopeID, scope.fixture.userID
}
