//go:build integration

package edgepublish

import (
	"context"
	"crypto/ed25519"
	"sort"
	"strconv"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/cdnca/cdnca/services/control-api/internal/edgedeployment"
	"github.com/cdnca/cdnca/services/control-api/internal/edgepublish/capabilitytest"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// E2EPublisherForTest is the production publication service over a migrated
// schema with the facts a publication needs (tenant and platform identities,
// a sold package, an installed entitlement), on the wall clock: the
// cross-process harnesses (tests/dynroute-e2e) publish to a real agent.
// Integration builds only; not part of the service.
type E2EPublisherForTest struct {
	Pool            *pgxpool.Pool
	Service         *Service
	TenantID        uuid.UUID
	ScopeID         uuid.UUID
	UserID          uuid.UUID
	PlatformScopeID uuid.UUID
	PlatformUserID  uuid.UUID
	signer          *testSigner
}

// wallClockEntitlement allows every publication, evaluated when asked.
type wallClockEntitlement struct{}

func (wallClockEntitlement) AuthorizePublication(_ context.Context, _ pgx.Tx, request EntitlementRequest) (EntitlementDecision, error) {
	return EntitlementDecision{Allowed: true, LocallyVerified: true, Status: EntitlementStatusValid, LeaseSerial: 1,
		EvaluatedAt: request.EvaluatedAt}, nil
}

func NewE2EPublisherForTest(t *testing.T, pool *pgxpool.Pool, signerKeyID string) *E2EPublisherForTest {
	t.Helper()
	tenantID, scopeID, userID, platformScopeID, platformUserID := seedPublishIdentity(t, pool)
	seedPublishPackage(t, pool, scopeID, userID, platformScopeID, platformUserID)
	installPublishEntitlement(t, pool)
	deployments, err := edgedeployment.NewStore(pool)
	if err != nil {
		t.Fatal(err)
	}
	signer := newTestSigner(t, signerKeyID)
	config := DefaultConfig()
	config.EntitlementAuthorizer = wallClockEntitlement{}
	service, err := newServiceWithWriteAuthorizer(pool, deployments, signer, config, fixtureWriteAuthorizer{})
	if err != nil {
		t.Fatal(err)
	}
	return &E2EPublisherForTest{Pool: pool, Service: service, TenantID: tenantID, ScopeID: scopeID, UserID: userID,
		PlatformScopeID: platformScopeID, PlatformUserID: platformUserID, signer: signer}
}

// Signer signs the publications (and may sign node artifact sets): its key
// goes into the agent's trust file.
func (publisher *E2EPublisherForTest) Signer() interface {
	KeyID() string
	PublicKey() ed25519.PublicKey
	Sign(context.Context, []byte) ([]byte, error)
} {
	return publisher.signer
}

// DynamicRoutingNodeFeaturesForTest is what a 1.0.35 dynamic routing agent
// declares at enrollment (site_runtime 9).
// (same set as the package tests' v2DefaultNodeFeatures, site_runtime 9).
func DynamicRoutingNodeFeaturesForTest() []*agentv1.Capability {
	features := []*agentv1.Capability{{Name: agentv1.CapabilityName_CAPABILITY_NAME_SITE_RUNTIME,
		ApiVersion: edgeconfig.DynamicRoutingSiteRuntimeVersion}}
	for name, version := range map[agentv1.CapabilityName]uint32{
		agentv1.CapabilityName_CAPABILITY_NAME_HTTP_1_1: 1, agentv1.CapabilityName_CAPABILITY_NAME_HTTP_2: 1,
		agentv1.CapabilityName_CAPABILITY_NAME_WEBSOCKET: 1, agentv1.CapabilityName_CAPABILITY_NAME_IPV4: 1,
		agentv1.CapabilityName_CAPABILITY_NAME_IPV6: 1, agentv1.CapabilityName_CAPABILITY_NAME_SITE_QUIC: 1,
		agentv1.CapabilityName_CAPABILITY_NAME_TCP_PROXY: 6, agentv1.CapabilityName_CAPABILITY_NAME_UDP_PROXY: 6,
		agentv1.CapabilityName_CAPABILITY_NAME_PROXY_PROTOCOL: 1, agentv1.CapabilityName_CAPABILITY_NAME_CC: 4,
		agentv1.CapabilityName_CAPABILITY_NAME_WAF: 1, agentv1.CapabilityName_CAPABILITY_NAME_ATOMIC_RELEASE: 1,
		agentv1.CapabilityName_CAPABILITY_NAME_CONFIG_PRECHECK: 1,
	} {
		features = append(features, &agentv1.Capability{Name: name, ApiVersion: version})
	}
	sort.Slice(features, func(i, j int) bool { return features[i].Name < features[j].Name })
	return features
}

// AddDynamicRoutingNode registers nodeID in the tenant scope with a real
// enrollment (Authorize + Complete) declaring site_runtime 9; it returns the
// node's artifact private key and key ID.
func (publisher *E2EPublisherForTest) AddDynamicRoutingNode(t *testing.T, nodeID uuid.UUID) ([]byte, string) {
	t.Helper()
	insertPublishNode(t, publisher.Pool, publisher.ScopeID, publisher.UserID, nodeID, "dynroute-e2e")
	identity := capabilitytest.SeedNodePublicationIdentityForTest(t, publisher.Pool, publisher.ScopeID, publisher.UserID, nodeID,
		&agentv1.AgentCapabilities{AgentVersion: "1.0.35-e2e", BuildId: "dynroute-e2e", OperatingSystem: "linux",
			Architecture: "arm64", Features: DynamicRoutingNodeFeaturesForTest()}, time.Now().Add(-time.Minute), true)
	return identity.ArtifactPrivateKey, identity.Authorization.ArtifactEncryptionKeyID
}

// CreateSite adds an enabled HTTP site on port whose only origin is
// originHost:originPort.
func (publisher *E2EPublisherForTest) CreateSite(t *testing.T, domain string, port int, originHost string, originPort int) uuid.UUID {
	t.Helper()
	siteID, now := uuid.New(), time.Now().UTC()
	origin := originHost + ":" + strconv.Itoa(originPort)
	err := pgx.BeginFunc(t.Context(), publisher.Pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(t.Context(), `
			WITH allocated AS (
				INSERT INTO site_display_id_sequences(scope_id,next_value,updated_at) VALUES($2,2,$10)
				ON CONFLICT(scope_id) DO UPDATE SET next_value=site_display_id_sequences.next_value+1,updated_at=EXCLUDED.updated_at
				RETURNING next_value-1 AS display_id
			)
			INSERT INTO sites (id,display_id,scope_id,owner_user_id,domain,http_ports,https_ports,origins,origin_hosts,
				https_enabled,enabled,status,created_by_user_id,updated_by_user_id,created_at,updated_at)
			SELECT $1,allocated.display_id,$2,$3,$4,$5,$6,$7,$8,$9,true,'active',$3,$3,$10,$10 FROM allocated`,
			siteID, publisher.ScopeID, publisher.UserID, domain, []string{strconv.Itoa(port)}, []string{},
			[]string{origin}, []string{originHost}, false, now); err != nil {
			return err
		}
		if _, err := tx.Exec(t.Context(), `INSERT INTO site_origin_pools(site_id,balance_method,failover_tries,
			connect_timeout_ms,read_timeout_ms,updated_at) VALUES($1,'round_robin',1,3000,30000,$2)`, siteID, now); err != nil {
			return err
		}
		_, err := tx.Exec(t.Context(), `INSERT INTO site_origins(site_id,position,host,port,weight,enabled)
			VALUES($1,1,$2,$3,1,true)`, siteID, originHost, originPort)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return siteID
}

// Publish publishes the scope's current source revision to nodeID as a site
// runtime v2 release (site objects; site_runtime 9 targets get v9).
func (publisher *E2EPublisherForTest) Publish(ctx context.Context, key string, nodeID uuid.UUID) (PublishResult, error) {
	var revision int64 = 1
	if err := publisher.Pool.QueryRow(ctx, `SELECT source_revision FROM edge_configuration_scopes WHERE scope_id=$1`,
		publisher.ScopeID).Scan(&revision); err != nil && err != pgx.ErrNoRows {
		return PublishResult{}, err
	}
	return publisher.Service.Publish(ctx, PublishRequest{
		Actor:                Actor{UserID: publisher.PlatformUserID, ScopeID: publisher.PlatformScopeID, ScopeKind: ScopeKindPlatform},
		ConfigurationScopeID: publisher.ScopeID, ExpectedSourceRevision: revision, SiteRuntimeSchema: siteRuntimeV2Schema,
		NodeIDs: []uuid.UUID{nodeID}, MaxAttempts: 1,
		HealthCheck: edgedeployment.HealthCheckPolicy{ActivationTimeout: time.Minute, ObservationWindow: 5 * time.Second,
			RequiredConsecutiveSuccesses: 2},
		Deadline: time.Now().Add(time.Hour), IdempotencyKey: key, RequestID: uuid.NewString(), CorrelationID: uuid.NewString(),
	})
}
