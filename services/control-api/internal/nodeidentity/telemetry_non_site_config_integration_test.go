//go:build integration

package nodeidentity

import (
	"context"
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// A node's healthy deployments also carry configurations that are no site
// runtime: the node artifact set (artifactsetdist, platform scope, no tenant)
// and its segments. They name no site, so they must not take part in
// telemetry authorization. 1.0.35 (73, 10-21): every Connect of a freshly
// initialized node failed Unavailable once its artifact set was healthy.
func TestAuthorizationIgnoresNonSiteRuntimeDeployments(t *testing.T) {
	for _, test := range []struct {
		name     string
		platform bool
	}{{"platform node", true}, {"tenant node", false}} {
		t.Run(test.name, func(t *testing.T) {
			pool := openIdentityTestDatabase(t, true)
			now := time.Date(2026, 9, 12, 12, 0, 0, 0, time.UTC)
			clock := &identityTestClock{value: now}
			service := newIdentityTestService(t, pool, newIdentityTestCA(t, now), clock)
			var node identityFixture
			if test.platform {
				node = seedIdentityPlatformNode(t, pool, now, "active", "initial_enrollment")
			} else {
				node = seedIdentityNode(t, pool, now, "active", "initial_enrollment")
			}
			platform := seedIdentityPlatformNode(t, pool, now, "active", "initial_enrollment")
			authorize := validAuthorizeRequest(t, testCSR(t, false))
			authorize.EnrollmentToken = node.token
			authorization, err := service.Authorize(context.Background(), authorize)
			if err != nil {
				t.Fatal(err)
			}
			completion, err := service.Complete(context.Background(), CompleteRequest{
				RequestID: uuid.NewString(), AuthorizationID: authorization.ID,
				GatewayWorkloadIdentity: authorize.GatewayWorkloadIdentity, GatewayInstanceID: authorize.GatewayInstanceID,
			})
			if err != nil {
				t.Fatal(err)
			}
			// The platform-scope artifact set and one of its segments, as
			// artifactsetdist publishes them, each healthy on the node.
			deployer := identityFixture{nodeID: node.nodeID, scopeID: platform.scopeID}
			for index, snapshot := range []string{
				`{"schema":"cdnca.edge.artifact-set/v1","node_id":"` + node.nodeID.String() + `","revision":1,"items":[]}`,
				`{"segment_sha256":"216fe9facc6322a180b56bee67e3544ca7f84bbcca8e24862cc52b39e093cb07","size":798}`,
			} {
				configID := seedNonSiteConfig(t, pool, platform.scopeID, []byte(snapshot), now)
				seedTelemetryDeploymentFact(t, pool, deployer, configID, uuid.Nil, "apply", "healthy", "healthy",
					now.Add(time.Duration(index-2)*time.Minute))
			}

			snapshot, err := service.GetAuthorization(context.Background(), GetAuthorizationRequest{
				NodeID: node.nodeID, CertificateSerialNumber: completion.Certificate.SerialNumber,
				CertificateSHA256:       certificateDERDigest(t, completion.Certificate),
				GatewayWorkloadIdentity: authorize.GatewayWorkloadIdentity, GatewayInstanceID: authorize.GatewayInstanceID,
			})
			if err != nil {
				t.Fatalf("GetAuthorization() error = %v", err)
			}
			if !snapshot.ConnectionAllowed || len(snapshot.TelemetrySites) != 0 || len(snapshot.TelemetryExcludedScopes) != 0 {
				t.Fatalf("authorization = %#v", snapshot)
			}
		})
	}
}

// An unknown site runtime still fails closed, and the error says why.
func TestAuthorizationRefusesUnknownSiteRuntimeWithReason(t *testing.T) {
	pool := openIdentityTestDatabase(t, true)
	now := time.Date(2026, 9, 12, 12, 0, 0, 0, time.UTC)
	clock := &identityTestClock{value: now}
	service := newIdentityTestService(t, pool, newIdentityTestCA(t, now), clock)
	node := seedIdentityNode(t, pool, now, "active", "initial_enrollment")
	authorize := validAuthorizeRequest(t, testCSR(t, false))
	authorize.EnrollmentToken = node.token
	authorization, err := service.Authorize(context.Background(), authorize)
	if err != nil {
		t.Fatal(err)
	}
	completion, err := service.Complete(context.Background(), CompleteRequest{
		RequestID: uuid.NewString(), AuthorizationID: authorization.ID,
		GatewayWorkloadIdentity: authorize.GatewayWorkloadIdentity, GatewayInstanceID: authorize.GatewayInstanceID,
	})
	if err != nil {
		t.Fatal(err)
	}
	configID := seedNonSiteConfig(t, pool, node.scopeID,
		[]byte(`{"schema":"cdnca.edge.site-runtime/v9","configuration_scope_id":"`+node.scopeID.String()+`"}`), now)
	seedTelemetryDeploymentFact(t, pool, node, configID, uuid.Nil, "apply", "healthy", "healthy", now.Add(-time.Minute))

	_, err = service.GetAuthorization(context.Background(), GetAuthorizationRequest{
		NodeID: node.nodeID, CertificateSerialNumber: completion.Certificate.SerialNumber,
		CertificateSHA256:       certificateDERDigest(t, completion.Certificate),
		GatewayWorkloadIdentity: authorize.GatewayWorkloadIdentity, GatewayInstanceID: authorize.GatewayInstanceID,
	})
	var reason *TelemetrySnapshotError
	if !errors.Is(err, ErrPersistence) || !errors.As(err, &reason) || reason.ConfigVersionID != configID {
		t.Fatalf("GetAuthorization() error = %v, want a telemetry snapshot error naming %s", err, configID)
	}
}

func seedNonSiteConfig(t *testing.T, pool *pgxpool.Pool, scopeID uuid.UUID, snapshot []byte, at time.Time) uuid.UUID {
	t.Helper()
	configID := uuid.New()
	digest := sha256.Sum256(snapshot)
	if _, err := pool.Exec(context.Background(), `INSERT INTO config_versions
		(id,configuration_scope_id,canonical_snapshot,canonical_snapshot_sha256,generator_name,generator_version,
		 status,idempotency_key,request_digest,created_at,published_at)
		VALUES($1,$2,$3,$4,'node-artifact-set','1','releasable',$5,$6,$7,$7)`,
		configID, scopeID, snapshot, digest[:], "non-site-"+configID.String(), bytesOf(32, 5), at.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	return configID
}
