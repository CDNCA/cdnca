//go:build integration

package edgepublish

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"runtime"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/edgeconfig/siteobject"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/cdnca/cdnca/services/control-api/internal/edgedeployment"
	"github.com/cdnca/cdnca/services/control-api/internal/edgepublish/capabilitytest"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestSiteRuntimeV2PublishRealEntryPointRollsBackEveryAtomicStage(t *testing.T) {
	for _, stage := range []string{"outbox", "publication", "audit"} {
		t.Run(stage, func(t *testing.T) {
			fixture := newPublishFixture(t)
			fixture.createSite(t, "runtime-v2-"+stage+".example.test", 80, false)
			seedSiteRuntimeV2Capabilities(t, fixture, "", siteRuntimeV2NodeFeatures())
			service := fixture.service
			switch stage {
			case "outbox":
				installSiteRuntimeV2FailureTrigger(t, fixture.pool, "edge_command_outbox", "runtime_v2_outbox")
			case "publication":
				installSiteRuntimeV2FailureTrigger(t, fixture.pool, "edge_config_publications", "runtime_v2_publication")
			case "audit":
				service = fixture.newService(t,
					&testEntitlementAuthorizer{decision: validTestEntitlementDecision()}, failingAuditAppender{})
			}
			if _, err := service.Publish(t.Context(), siteRuntimeV2PublishRequest(
				fixture, "runtime-v2-"+stage, fixture.nodeID, "cdnca.edge.site-runtime/v2")); err == nil {
				t.Fatalf("real Publish accepted injected %s failure", stage)
			}
			assertPublishState(t, fixture.pool, 0, 0, 0, 0, 0)
			var successfulAudits int
			if err := fixture.pool.QueryRow(t.Context(), `SELECT count(*) FROM audit_events
				WHERE action='edge_publication.publish' AND result='success'`).Scan(&successfulAudits); err != nil {
				t.Fatal(err)
			}
			if successfulAudits != 0 {
				t.Fatalf("%s failure committed %d success audits", stage, successfulAudits)
			}
		})
	}
}

func TestSiteRuntimeV2ManualPublishLocksScopeBeforeReadingFinalSource(t *testing.T) {
	fixture := newPublishFixture(t)
	site := fixture.createSite(t, "runtime-v2-manual-lock.example.test", 80, false)
	seedSiteRuntimeV2Capabilities(t, fixture, "", siteRuntimeV2NodeFeatures())
	blocker, err := fixture.pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = blocker.Rollback(context.Background()) }()
	var blockerPID int32
	if err := blocker.QueryRow(t.Context(), `SELECT pg_backend_pid()`).Scan(&blockerPID); err != nil {
		t.Fatal(err)
	}
	var lockedRevision int64
	if err := blocker.QueryRow(t.Context(), `SELECT source_revision FROM edge_configuration_scopes
		WHERE scope_id=$1 FOR UPDATE`, fixture.scopeID).Scan(&lockedRevision); err != nil {
		t.Fatal(err)
	}

	type publishOutcome struct {
		result PublishResult
		err    error
	}
	done := make(chan publishOutcome, 1)
	request := siteRuntimeV2PublishRequest(fixture, "runtime-v2-manual-lock", fixture.nodeID, "cdnca.edge.site-runtime/v2")
	request.ExpectedSourceRevision = lockedRevision + 1
	go func() {
		result, publishErr := fixture.service.Publish(context.Background(), request)
		done <- publishOutcome{result: result, err: publishErr}
	}()
	waitErr := waitForSiteRuntimeV2Blocker(t.Context(), fixture.pool, blockerPID)
	lockErr := pgx.BeginFunc(t.Context(), fixture.pool, func(tx pgx.Tx) error {
		var exists bool
		return tx.QueryRow(t.Context(), `SELECT true FROM sites WHERE id=$1 FOR UPDATE NOWAIT`, site.Site.ID).
			Scan(&exists)
	})
	if _, err := blocker.Exec(t.Context(), `UPDATE edge_configuration_scopes SET source_revision=$2
		WHERE scope_id=$1`, fixture.scopeID, lockedRevision+1); err != nil {
		t.Fatal(err)
	}
	if err := blocker.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	outcome := <-done
	if waitErr != nil {
		t.Fatal(waitErr)
	}
	if lockErr != nil {
		t.Fatalf("Publish read site facts before acquiring the scope lock: %v", lockErr)
	}
	if outcome.err != nil {
		t.Fatal(outcome.err)
	}
	if outcome.result.SourceRevision != lockedRevision+1 {
		t.Fatalf("Publish source revision=%d, final locked revision=%d", outcome.result.SourceRevision, lockedRevision+1)
	}
	assertSiteRuntimeV2PublishedSnapshot(t, fixture.pool, outcome.result)
}

func TestSiteRuntimeV2PublishCASHasOneRealPGWinner(t *testing.T) {
	fixture := newPublishFixture(t)
	fixture.createSite(t, "runtime-v2-publish-cas.example.test", 80, false)
	seedSiteRuntimeV2Capabilities(t, fixture, "", siteRuntimeV2NodeFeatures())
	before := fixture.sourceRevision()
	requests := []PublishRequest{
		siteRuntimeV2PublishRequest(fixture, "runtime-v2-cas-a", fixture.nodeID, "cdnca.edge.site-runtime/v2"),
		siteRuntimeV2PublishRequest(fixture, "runtime-v2-cas-b", fixture.nodeID, "cdnca.edge.site-runtime/v2"),
	}
	start := make(chan struct{})
	type result struct {
		publication PublishResult
		err         error
	}
	results := make(chan result, len(requests))
	for _, request := range requests {
		request := request
		go func() {
			<-start
			publication, err := fixture.service.Publish(context.Background(), request)
			results <- result{publication: publication, err: err}
		}()
	}
	close(start)

	var winner PublishResult
	winners, losers := 0, 0
	for range requests {
		result := <-results
		if result.err == nil {
			winners++
			winner = result.publication
			continue
		}
		if errors.Is(result.err, ErrRevisionConflict) {
			losers++
			continue
		}
		t.Fatalf("unexpected concurrent Publish error: %v", result.err)
	}
	if winners != 1 || losers != 1 {
		t.Fatalf("concurrent Publish winners/losers=%d/%d", winners, losers)
	}
	assertPublishState(t, fixture.pool, 1, 1, 1, 1, 1)
	if after := fixture.sourceRevision(); after != before || winner.SourceRevision != before {
		t.Fatalf("loser changed current source revision: before=%d after=%d winner=%d", before, after, winner.SourceRevision)
	}
	assertSiteRuntimeV2PublishedSnapshot(t, fixture.pool, winner)
}

func TestSiteRuntimeV2PublishReplayConflictAndStalePreserveExactPGFacts(t *testing.T) {
	fixture := newPublishFixture(t)
	site := fixture.createSiteWithPortSets(t, "runtime-v2-replay.example.test", []string{"80"}, []string{"443"}, true)
	seedSiteRuntimeV2CertificateBinding(t, fixture, site.Site)
	seedSiteRuntimeV2Capabilities(t, fixture, "metadata-is-not-tls", siteRuntimeV2NodeFeatures())
	request := siteRuntimeV2PublishRequest(
		fixture, "runtime-v2-replay-conflict-stale", fixture.nodeID, "cdnca.edge.site-runtime/v2")
	first, err := fixture.service.Publish(t.Context(), request)
	if err != nil {
		t.Fatal(err)
	}
	finishPublishDeployment(t, fixture, first, &first.ConfigVersionID, nil)
	before := readSiteRuntimeV2PublishState(t, fixture, first)

	replayRequest := request
	replayRequest.RequestID = uuid.NewString()
	replayRequest.CorrelationID = uuid.NewString()
	replay, err := fixture.service.Publish(t.Context(), replayRequest)
	if err != nil || !replay.Replayed || replay.PublicationID != first.PublicationID ||
		replay.ConfigVersionID != first.ConfigVersionID || replay.RolloutID != first.RolloutID {
		t.Fatalf("same-digest Publish replay=%+v err=%v first=%+v", replay, err, first)
	}
	if after := readSiteRuntimeV2PublishState(t, fixture, first); after != before {
		t.Fatalf("same-digest replay changed PG facts: before=%+v after=%+v", before, after)
	}

	changed := request
	changed.Deadline = changed.Deadline.Add(time.Second)
	if _, err := fixture.service.Publish(t.Context(), changed); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("changed-digest Publish error=%v", err)
	}
	if after := readSiteRuntimeV2PublishState(t, fixture, first); after != before {
		t.Fatalf("changed-digest conflict changed PG facts: before=%+v after=%+v", before, after)
	}

	fixture.createSite(t, "runtime-v2-newer-source.example.test", 8080, false)
	stale := siteRuntimeV2PublishRequest(fixture, "runtime-v2-stale", fixture.nodeID, "cdnca.edge.site-runtime/v2")
	stale.ExpectedSourceRevision = first.SourceRevision
	if _, err := fixture.service.Publish(t.Context(), stale); !errors.Is(err, ErrRevisionConflict) {
		t.Fatalf("stale lower-revision Publish error=%v", err)
	}
	if after := readSiteRuntimeV2PublishState(t, fixture, first); after != before {
		t.Fatalf("stale Publish changed current/persisted facts: before=%+v after=%+v", before, after)
	}
}

func TestSiteRuntimeV2PublishRejectsEveryMissingDurableCapabilityBeforePersistence(t *testing.T) {
	for index, test := range []struct {
		name    string
		missing agentv1.CapabilityName
	}{
		{name: "http1", missing: agentv1.CapabilityName_CAPABILITY_NAME_HTTP_1_1},
		{name: "http2", missing: agentv1.CapabilityName_CAPABILITY_NAME_HTTP_2},
		{name: "http3", missing: agentv1.CapabilityName_CAPABILITY_NAME_SITE_QUIC},
		{name: "websocket", missing: agentv1.CapabilityName_CAPABILITY_NAME_WEBSOCKET},
		{name: "ipv4", missing: agentv1.CapabilityName_CAPABILITY_NAME_IPV4},
		{name: "ipv6", missing: agentv1.CapabilityName_CAPABILITY_NAME_IPV6},
		{name: "site-runtime-v2", missing: agentv1.CapabilityName_CAPABILITY_NAME_SITE_RUNTIME},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newPublishFixture(t)
			site := fixture.createSiteWithPortSets(t, "runtime-v2-capability-"+test.name+".example.test",
				[]string{"80"}, []string{"443"}, true)
			seedSiteRuntimeV2CertificateBinding(t, fixture, site.Site)
			features := siteRuntimeV2NodeFeatures()
			filtered := features[:0:0]
			for _, feature := range features {
				if feature.Name != test.missing {
					filtered = append(filtered, feature)
				}
			}
			openrestyVersion := ""
			if index%2 != 0 {
				openrestyVersion = "not-a-tls-capability"
			}
			seedSiteRuntimeV2Capabilities(t, fixture, openrestyVersion, filtered)
			if _, err := fixture.service.Publish(t.Context(),
				siteRuntimeV2PublishRequest(fixture, "runtime-v2-missing-"+test.name, fixture.nodeID,
					"cdnca.edge.site-runtime/v2")); err == nil {
				t.Fatal("Publish accepted a target missing the durable capability")
			}
			assertPublishState(t, fixture.pool, 0, 0, 0, 0, 0)
			var audits int
			if err := fixture.pool.QueryRow(t.Context(), `SELECT count(*) FROM audit_events
				WHERE action='edge_publication.publish'`).Scan(&audits); err != nil {
				t.Fatal(err)
			}
			if audits != 0 {
				t.Fatalf("incapable target committed %d publication audits", audits)
			}
		})
	}
}

func TestSiteRuntimeV2PublishRejectsEveryInvalidTLSBindingBeforePersistence(t *testing.T) {
	tests := []struct {
		name string
		seed func(*testing.T, *publishFixture, fixtureSite)
	}{
		{name: "absent", seed: func(*testing.T, *publishFixture, fixtureSite) {}},
		{name: "wrong-site", seed: func(t *testing.T, fixture *publishFixture, _ fixtureSite) {
			other := fixture.createSiteWithPortSets(t, "runtime-v2-other-site.example.test",
				[]string{"80"}, []string{"443"}, true)
			seedSiteRuntimeV2CertificateBinding(t, fixture, other.Site)
		}},
		{name: "wrong-scope", seed: seedSiteRuntimeV2ForeignScopeBinding},
		{name: "wrong-certificate-version", seed: seedSiteRuntimeV2InactiveVersionBinding},
		{name: "expired", seed: seedSiteRuntimeV2ExpiredBinding},
		{name: "revoked", seed: seedSiteRuntimeV2RevokedBinding},
	}
	for index, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newPublishFixture(t)
			site := fixture.createSiteWithPortSets(t, "runtime-v2-invalid-tls-"+test.name+".example.test",
				[]string{"80"}, []string{"443"}, true)
			test.seed(t, fixture, site.Site)
			openrestyVersion := ""
			if index%2 != 0 {
				openrestyVersion = "metadata-is-not-tls"
			}
			seedSiteRuntimeV2Capabilities(t, fixture, openrestyVersion, siteRuntimeV2NodeFeatures())
			if _, err := fixture.service.Publish(t.Context(), siteRuntimeV2PublishRequest(
				fixture, "runtime-v2-invalid-tls-"+test.name, fixture.nodeID,
				"cdnca.edge.site-runtime/v2")); err == nil {
				t.Fatal("Publish accepted an invalid immutable certificate/config binding")
			}
			assertPublishState(t, fixture.pool, 0, 0, 0, 0, 0)
			var audits int
			if err := fixture.pool.QueryRow(t.Context(), `SELECT count(*) FROM audit_events
				WHERE action='edge_publication.publish'`).Scan(&audits); err != nil {
				t.Fatal(err)
			}
			if audits != 0 {
				t.Fatalf("invalid TLS binding committed %d publication audits", audits)
			}
		})
	}
}

func TestSiteRuntimeV2TLSBindingDoesNotDependOnOpenrestyMetadata(t *testing.T) {
	for _, openrestyVersion := range []string{"", "metadata-is-not-tls"} {
		name := "empty"
		if openrestyVersion != "" {
			name = "variant"
		}
		t.Run(name, func(t *testing.T) {
			fixture := newPublishFixture(t)
			site := fixture.createSiteWithPortSets(t, "runtime-v2-tls-metadata-"+name+".example.test",
				[]string{"80"}, []string{"443"}, true)
			seedSiteRuntimeV2CertificateBinding(t, fixture, site.Site)
			seedSiteRuntimeV2Capabilities(t, fixture, openrestyVersion, siteRuntimeV2NodeFeatures())
			result, err := fixture.service.Publish(t.Context(), siteRuntimeV2PublishRequest(
				fixture, "runtime-v2-tls-metadata-"+name, fixture.nodeID, "cdnca.edge.site-runtime/v2"))
			if err != nil {
				t.Fatalf("exact immutable TLS binding rejected for OpenrestyVersion %q: %v", openrestyVersion, err)
			}
			assertSiteRuntimeV2PublishedSnapshot(t, fixture.pool, result)
		})
	}
}

func TestSiteRuntimeV2CapablePublishPersistsApprovedS0BytesAndIdentity(t *testing.T) {
	fixture := newSiteRuntimeV2OracleFixture(t)
	site := seedSiteRuntimeV2OracleSite(t, fixture)
	seedSiteRuntimeV2CertificateBindingWithOptions(t, fixture, site.Site, siteRuntimeV2CertificateSeedOptions{
		assetID:   uuid.MustParse("018f47a2-5b9c-7d31-8a60-104c9c0b7114"),
		versionID: uuid.MustParse("018f47a2-5b9c-7d31-8a60-104c9c0b7104"),
	})
	seedSiteRuntimeV2Capabilities(t, fixture, "metadata-is-not-tls", siteRuntimeV2NodeFeatures())
	result, err := fixture.service.Publish(t.Context(), siteRuntimeV2PublishRequest(
		fixture, "runtime-v2-capable", fixture.nodeID, "cdnca.edge.site-runtime/v2"))
	if err != nil {
		t.Fatal(err)
	}
	assertSiteRuntimeV2ApprovedArtifact(t, fixture.pool, result)

	finishPublishDeployment(t, fixture, result, &result.ConfigVersionID, nil)
	before := readSiteRuntimeV2PublishState(t, fixture, result)
	fixture.createSite(t, "runtime-v2-future-schema-source.example.test", 8080, false)
	const futureSchema = "cdnca.edge.site-runtime/v3"
	if _, err := fixture.service.Publish(t.Context(), siteRuntimeV2PublishRequest(
		fixture, "runtime-v2-rejected-future-schema", fixture.nodeID, futureSchema)); err == nil {
		t.Fatalf("real Publish accepted unsupported future site runtime schema %q", futureSchema)
	}
	if after := readSiteRuntimeV2PublishState(t, fixture, result); after != before {
		t.Fatalf("unsupported future schema changed current/persisted facts: before=%+v after=%+v", before, after)
	}
}

func installSiteRuntimeV2FailureTrigger(t *testing.T, pool *pgxpool.Pool, table, suffix string) {
	t.Helper()
	function := "fail_" + suffix
	trigger := suffix + "_failure"
	query := fmt.Sprintf(`CREATE FUNCTION %s() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN RAISE EXCEPTION 'injected site runtime v2 failure'; END $$;
		CREATE TRIGGER %s BEFORE INSERT ON %s FOR EACH ROW EXECUTE FUNCTION %s()`,
		pgx.Identifier{function}.Sanitize(), pgx.Identifier{trigger}.Sanitize(),
		pgx.Identifier{table}.Sanitize(), pgx.Identifier{function}.Sanitize())
	if _, err := pool.Exec(t.Context(), query); err != nil {
		t.Fatal(err)
	}
}

func waitForSiteRuntimeV2Blocker(ctx context.Context, pool *pgxpool.Pool, blockerPID int32) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	for ctx.Err() == nil {
		var blocked bool
		if err := pool.QueryRow(ctx, `SELECT EXISTS(
			SELECT 1 FROM pg_stat_activity WHERE $1 = ANY(pg_blocking_pids(pid))
		)`, blockerPID).Scan(&blocked); err != nil {
			return err
		}
		if blocked {
			return nil
		}
		runtime.Gosched()
	}
	return fmt.Errorf("Publish did not block on the scope row: %w", ctx.Err())
}

func assertSiteRuntimeV2PublishedSnapshot(t *testing.T, pool *pgxpool.Pool, result PublishResult) {
	t.Helper()
	var encoded []byte
	if err := pool.QueryRow(t.Context(), `SELECT canonical_snapshot FROM config_versions WHERE id=$1`,
		result.ConfigVersionID).Scan(&encoded); err != nil {
		t.Fatal(err)
	}
	var identity struct {
		Schema         string `json:"schema"`
		SourceRevision int64  `json:"source_revision"`
	}
	if err := json.Unmarshal(encoded, &identity); err != nil {
		t.Fatal(err)
	}
	if identity.Schema != "cdnca.edge.site-runtime/v2" || identity.SourceRevision != result.SourceRevision {
		t.Fatalf("published identity=%q/%d result=%d", identity.Schema, identity.SourceRevision, result.SourceRevision)
	}
}

type siteRuntimeV2PublishState struct {
	configVersionID uuid.UUID
	rolloutID       uuid.UUID
	publicationID   uuid.UUID
	currentConfigID uuid.UUID
	requestDigest   [sha256.Size]byte
	canonicalDigest [sha256.Size]byte
	artifactDigest  [sha256.Size]byte
	configs         int
	rollouts        int
	deployments     int
	outbox          int
	publications    int
	audits          int
}

func readSiteRuntimeV2PublishState(
	t *testing.T,
	fixture *publishFixture,
	result PublishResult,
) siteRuntimeV2PublishState {
	t.Helper()
	state := siteRuntimeV2PublishState{
		configVersionID: result.ConfigVersionID,
		rolloutID:       result.RolloutID,
		publicationID:   result.PublicationID,
	}
	var requestDigest, canonicalDigest, artifactDigest []byte
	if err := fixture.pool.QueryRow(t.Context(), `SELECT publication.request_digest,
		config.canonical_snapshot_sha256,artifact.sha256,
		(SELECT count(*) FROM config_versions),
		(SELECT count(*) FROM rollouts),
		(SELECT count(*) FROM node_deployments),
		(SELECT count(*) FROM edge_command_outbox),
		(SELECT count(*) FROM edge_config_publications),
		(SELECT count(*) FROM audit_events WHERE action='edge_publication.publish'),
		COALESCE(state.current_config_version_id,'00000000-0000-0000-0000-000000000000'::uuid)
		FROM edge_config_publications publication
		JOIN config_versions config ON config.id=publication.config_version_id
		JOIN configuration_artifacts artifact ON artifact.config_version_id=config.id AND artifact.kind='configuration'
		JOIN node_config_state state ON state.node_id=$2
		WHERE publication.id=$1`, result.PublicationID, fixture.nodeID).Scan(
		&requestDigest, &canonicalDigest, &artifactDigest, &state.configs, &state.rollouts,
		&state.deployments, &state.outbox, &state.publications, &state.audits, &state.currentConfigID); err != nil {
		t.Fatal(err)
	}
	for name, value := range map[string]struct {
		source []byte
		target *[sha256.Size]byte
	}{
		"request":   {requestDigest, &state.requestDigest},
		"canonical": {canonicalDigest, &state.canonicalDigest},
		"artifact":  {artifactDigest, &state.artifactDigest},
	} {
		if len(value.source) != sha256.Size {
			t.Fatalf("%s digest has %d bytes", name, len(value.source))
		}
		copy(value.target[:], value.source)
	}
	return state
}

func siteRuntimeV2PublishRequest(
	fixture *publishFixture,
	key string,
	nodeID uuid.UUID,
	schema string,
) PublishRequest {
	request := fixture.publishRequest(key, nodeID)
	request.SiteRuntimeSchema = schema
	return request
}

func newSiteRuntimeV2OracleFixture(t *testing.T) *publishFixture {
	t.Helper()
	ids := struct {
		tenant, scope, user, tenantRole, platformScope, platformUser, platformRole, node uuid.UUID
	}{
		tenant:        uuid.MustParse("018f47a2-5b9c-7d31-8a60-104c9c0b7200"),
		scope:         uuid.MustParse("018f47a2-5b9c-7d31-8a60-104c9c0b7101"),
		user:          uuid.MustParse("018f47a2-5b9c-7d31-8a60-104c9c0b7202"),
		tenantRole:    uuid.MustParse("018f47a2-5b9c-7d31-8a60-104c9c0b7203"),
		platformScope: uuid.MustParse("018f47a2-5b9c-7d31-8a60-104c9c0b7301"),
		platformUser:  uuid.MustParse("018f47a2-5b9c-7d31-8a60-104c9c0b7302"),
		platformRole:  uuid.MustParse("018f47a2-5b9c-7d31-8a60-104c9c0b7303"),
		node:          uuid.MustParse("018f47a2-5b9c-7d31-8a60-104c9c0b7105"),
	}
	pool := openPublishTestDatabase(t, true)
	if _, err := pool.Exec(t.Context(), `
		INSERT INTO tenants(id,display_name) VALUES($1,'Site runtime v2 oracle tenant');
		INSERT INTO access_scopes(id,kind,tenant_id) VALUES($2,'tenant',$1);
		INSERT INTO users(id,username,display_name,password_hash)
			VALUES($3,'runtime-v2-oracle-user','Site runtime v2 oracle user','not-used');
		INSERT INTO memberships(scope_id,user_id) VALUES($2,$3);
		INSERT INTO roles(id,scope_id,name,description,system_role)
			VALUES($4,$2,'tenant_owner','Site runtime v2 oracle tenant role',true);
		INSERT INTO role_permissions(role_id,permission_name) VALUES($4,'sites.manage') ON CONFLICT DO NOTHING;
		INSERT INTO role_assignments(scope_id,user_id,role_id) VALUES($2,$3,$4);
		INSERT INTO access_scopes(id,kind) VALUES($5,'platform');
		INSERT INTO users(id,username,display_name,password_hash)
			VALUES($6,'runtime-v2-oracle-owner','Site runtime v2 oracle owner','not-used');
		INSERT INTO memberships(scope_id,user_id) VALUES($5,$6);
		INSERT INTO roles(id,scope_id,name,description,system_role)
			VALUES($7,$5,'platform_owner','Site runtime v2 oracle platform owner',true);
		INSERT INTO role_permissions(role_id,permission_name)
			SELECT $7,name FROM permissions WHERE name IN ('edge_publications.read','edge_publications.manage');
		INSERT INTO role_assignments(scope_id,user_id,role_id) VALUES($5,$6,$7)`, pgx.QueryExecModeSimpleProtocol,
		ids.tenant, ids.scope, ids.user, ids.tenantRole, ids.platformScope, ids.platformUser, ids.platformRole); err != nil {
		t.Fatal(err)
	}
	installPublishEntitlement(t, pool)
	seedPublishNode(t, pool, ids.scope, ids.user, ids.node)
	deploymentStore, err := edgedeployment.NewStoreWithClock(pool, func() time.Time { return publishTestClock })
	if err != nil {
		t.Fatal(err)
	}
	signer := newTestSigner(t, "edge-publish-artifact-key")
	config := DefaultConfig()
	config.Clock = func() time.Time { return publishTestClock }
	config.EntitlementAuthorizer = &testEntitlementAuthorizer{decision: validTestEntitlementDecision()}
	service, err := newServiceWithWriteAuthorizer(pool, deploymentStore, signer, config, fixtureWriteAuthorizer{})
	if err != nil {
		t.Fatal(err)
	}
	// The oracle registers its node itself (seedSiteRuntimeV2Capabilities):
	// no nodeKeys, so publishRequest never registers one.
	return &publishFixture{
		t:    t,
		pool: pool, service: service, signer: signer,
		tenantID: ids.tenant, scopeID: ids.scope, userID: ids.user,
		platformScopeID: ids.platformScope, platformUserID: ids.platformUser, nodeID: ids.node,
	}
}

func seedSiteRuntimeV2OracleSite(t *testing.T, fixture *publishFixture) fixtureSiteResult {
	t.Helper()
	site := fixtureSite{
		ID:       uuid.MustParse("018f47a2-5b9c-7d31-8a60-104c9c0b7103"),
		Domain:   "runtime-v2-capable.example.test",
		Revision: 7,
	}
	if _, err := fixture.pool.Exec(t.Context(), `
		INSERT INTO site_display_id_sequences(scope_id,next_value,updated_at) VALUES($2,2,$5);
		INSERT INTO sites(
			id,display_id,scope_id,owner_user_id,domain,http_ports,https_ports,origins,origin_hosts,
			https_enabled,enabled,status,revision,created_by_user_id,updated_by_user_id,
			created_at,updated_at
		) VALUES($1,1,$2,$3,$4,ARRAY['80'],ARRAY['443'],ARRAY['203.0.113.10:8080'],
			ARRAY['203.0.113.10'],true,true,'active',7,$3,$3,$5,$5);
		INSERT INTO site_origin_pools(site_id,balance_method,failover_tries,connect_timeout_ms,read_timeout_ms,updated_at)
			VALUES($1,'round_robin',1,3000,30000,$5);
		INSERT INTO site_origins(site_id,position,host,port,weight,enabled)
			VALUES($1,1,'203.0.113.10',8080,1,true);
		UPDATE edge_configuration_scopes SET source_revision=41,updated_at=$5 WHERE scope_id=$2`,
		pgx.QueryExecModeSimpleProtocol, site.ID, fixture.scopeID, fixture.userID, site.Domain, publishTestClock); err != nil {
		t.Fatal(err)
	}
	return fixtureSiteResult{Site: site}
}

func seedSiteRuntimeV2Capabilities(
	t *testing.T,
	fixture *publishFixture,
	openrestyVersion string,
	features []*agentv1.Capability,
) {
	t.Helper()
	key := capabilitytest.SeedNodePublicationIdentityForTest(t, fixture.pool, fixture.scopeID, fixture.userID,
		fixture.nodeID, &agentv1.AgentCapabilities{
			AgentVersion: "1.0.0", BuildId: "site-runtime-v2-integration", OperatingSystem: "linux",
			Architecture: "amd64", OpenrestyVersion: openrestyVersion, Features: features,
		}, publishTestClock.Add(-10*time.Minute), true).ArtifactPrivateKey
	if fixture.nodeKeys != nil {
		fixture.nodeKeys[fixture.nodeID] = key
	}
}

func seedSiteRuntimeV2CertificateBinding(
	t *testing.T,
	fixture *publishFixture,
	site fixtureSite,
) uuid.UUID {
	t.Helper()
	return seedSiteRuntimeV2CertificateBindingWithOptions(
		t, fixture, site, siteRuntimeV2CertificateSeedOptions{}).versionID
}

type siteRuntimeV2CertificateSeedOptions struct {
	scopeID                 uuid.UUID
	userID                  uuid.UUID
	assetID                 uuid.UUID
	versionID               uuid.UUID
	notBefore               time.Time
	notAfter                time.Time
	activatedAt             time.Time
	changedAt               time.Time
	bypassBindingValidation bool
	// sans are the certificate's names; empty: the site domain.
	sans []string
}

type siteRuntimeV2CertificateSeed struct {
	scopeID   uuid.UUID
	userID    uuid.UUID
	assetID   uuid.UUID
	versionID uuid.UUID
}

func seedSiteRuntimeV2CertificateBindingWithOptions(
	t *testing.T,
	fixture *publishFixture,
	site fixtureSite,
	options siteRuntimeV2CertificateSeedOptions,
) siteRuntimeV2CertificateSeed {
	t.Helper()
	seeded := siteRuntimeV2CertificateSeed{
		scopeID: options.scopeID, userID: options.userID,
		assetID: options.assetID, versionID: options.versionID,
	}
	if seeded.scopeID == uuid.Nil {
		seeded.scopeID = fixture.scopeID
	}
	if seeded.userID == uuid.Nil {
		seeded.userID = fixture.userID
	}
	if seeded.assetID == uuid.Nil {
		seeded.assetID = uuid.New()
	}
	if seeded.versionID == uuid.Nil {
		seeded.versionID = uuid.New()
	}
	if options.notBefore.IsZero() {
		options.notBefore = publishTestClock.Add(-time.Hour)
	}
	if options.notAfter.IsZero() {
		options.notAfter = publishTestClock.Add(24 * time.Hour)
	}
	if options.activatedAt.IsZero() {
		options.activatedAt = publishTestClock.Add(-30 * time.Second)
	}
	if options.changedAt.IsZero() {
		options.changedAt = publishTestClock
	}
	if len(options.sans) == 0 {
		options.sans = []string{site.Domain}
	}
	seed := sha256.Sum256([]byte(seeded.versionID.String()))
	privateKeyReference := "site-runtime-v2:" + seeded.versionID.String()
	tx, err := fixture.pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if _, err := tx.Exec(t.Context(), `INSERT INTO certificate_assets(
			tenant_scope_id,id,name,source,revision,created_by_scope_id,created_by_user_id,
			updated_by_scope_id,updated_by_user_id,created_at,updated_at
		) VALUES($1,$2,$3,'uploaded',1,$1,$4,$1,$4,$5,$5)`, seeded.scopeID, seeded.assetID,
		"site-runtime-v2-"+seeded.assetID.String(), seeded.userID, options.activatedAt.Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(t.Context(), `INSERT INTO certificate_asset_versions(
		tenant_scope_id,id,asset_id,actor_scope_id,version,initial_status,fingerprint_sha256,certificate_pem,
		public_key_sha256,private_key_reference,private_key_aad_sha256,sans,leaf_subject,serial_number,
		public_key_algorithm,public_key_bits,signature_algorithm,not_before,not_after,
		imported_by_user_id,imported_at
	) VALUES($1,$2,$3,$1,1,'default',$4,$5,$4,$6,$4,$7,$8,$9,'ed25519',256,'ed25519',$10,$11,$12,$13)`,
		seeded.scopeID, seeded.versionID, seeded.assetID, seed[:], []byte("site-runtime-v2-test-certificate"),
		privateKeyReference, options.sans, "CN="+site.Domain, fmt.Sprintf("%x", seeded.versionID[:]),
		options.notBefore, options.notAfter, seeded.userID, options.activatedAt.Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(t.Context(), `INSERT INTO certificate_asset_private_key_envelope_facts(
		tenant_scope_id,asset_id,version_id,actor_scope_id,sequence,certificate_fingerprint_sha256,
		certificate_public_key_sha256,private_key_reference,aad_sha256,private_key_ciphertext,
		private_key_key_id,private_key_nonce,private_key_metadata,change_kind,request_id,
		changed_by_user_id,changed_at
	) VALUES($1,$2,$3,$1,1,$4,$4,$5,$4,$6,'site-runtime-v2-test-key',$7,'{}'::jsonb,
			'initial',$8,$9,$10)`, seeded.scopeID, seeded.assetID, seeded.versionID, seed[:], privateKeyReference,
		bytes.Repeat([]byte{0x01}, 16), bytes.Repeat([]byte{0x02}, 12),
		"site-runtime-v2-envelope-"+seeded.versionID.String(), seeded.userID, options.activatedAt.Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(t.Context(), `UPDATE certificate_assets SET revision=2,updated_at=$3,
			updated_by_user_id=$4 WHERE tenant_scope_id=$1 AND id=$2`, seeded.scopeID, seeded.assetID,
		options.activatedAt, seeded.userID); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(t.Context(), `INSERT INTO certificate_asset_activation_facts(
		tenant_scope_id,asset_id,actor_scope_id,sequence,version_id,previous_version_id,expected_asset_revision,
		resulting_asset_revision,request_id,activated_by_user_id,activated_at
		) VALUES($1,$2,$1,1,$3,NULL,1,2,$4,$5,$6)`, seeded.scopeID, seeded.assetID, seeded.versionID,
		"site-runtime-v2-activate-"+seeded.versionID.String(), seeded.userID, options.activatedAt); err != nil {
		t.Fatal(err)
	}
	if options.bypassBindingValidation {
		if _, err := tx.Exec(t.Context(), `ALTER TABLE certificate_site_binding_facts
			DISABLE TRIGGER certificate_site_bindings_immutable`); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := tx.Exec(t.Context(), `INSERT INTO certificate_site_binding_facts(
		tenant_scope_id,site_id,sequence,action,asset_id,version_id,is_default,expected_revision,
		resulting_revision,request_id,actor_scope_id,changed_by_user_id,changed_at
		) VALUES($1,$2,1,'bind',$3,$4,true,0,1,$5,$1,$6,$7)`, seeded.scopeID, site.ID, seeded.assetID,
		seeded.versionID, "site-runtime-v2-bind-"+site.ID.String(), seeded.userID, options.changedAt); err != nil {
		t.Fatal(err)
	}
	insertSiteRuntimeV2PublicationIntent(t, tx, seeded.scopeID, site.ID, 1)
	if options.bypassBindingValidation {
		if _, err := tx.Exec(t.Context(), `ALTER TABLE certificate_site_binding_facts
			ENABLE TRIGGER certificate_site_bindings_immutable`); err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	return seeded
}

// insertSiteRuntimeV2PublicationIntent appends the same-transaction
// publication intent migration 116 requires for each binding revision. It is
// copied from the binding fact and uses the legacy (sessionless) actor form.
func insertSiteRuntimeV2PublicationIntent(t *testing.T, tx pgx.Tx, scopeID, siteID uuid.UUID, revision int64) {
	t.Helper()
	if _, err := tx.Exec(t.Context(), `INSERT INTO certificate_publication_intents(
			tenant_scope_id,site_id,binding_revision,operation,asset_id,version_id,is_default,
			request_id,actor_scope_id,actor_user_id,deadline_at
		) SELECT tenant_scope_id,site_id,sequence,
			CASE action WHEN 'bind' THEN 'publish' ELSE 'unpublish' END,
			asset_id,version_id,is_default,request_id,actor_scope_id,changed_by_user_id,
			transaction_timestamp()+interval '1 hour'
		FROM certificate_site_binding_facts
		WHERE tenant_scope_id=$1 AND site_id=$2 AND sequence=$3`, scopeID, siteID, revision); err != nil {
		t.Fatal(err)
	}
	// Fire the deferred intent check now: callers that suspended a binding
	// trigger cannot re-enable it while trigger events are pending.
	if _, err := tx.Exec(t.Context(), `SET CONSTRAINTS ALL IMMEDIATE`); err != nil {
		t.Fatal(err)
	}
}

func seedSiteRuntimeV2ForeignScopeBinding(t *testing.T, fixture *publishFixture, site fixtureSite) {
	t.Helper()
	tenantID, scopeID, userID := uuid.New(), uuid.New(), uuid.New()
	username := "runtime-v2-foreign-" + userID.String()[:8]
	if _, err := fixture.pool.Exec(t.Context(), `
		INSERT INTO tenants(id,display_name) VALUES($1,'Site runtime v2 foreign tenant');
		INSERT INTO access_scopes(id,kind,tenant_id) VALUES($2,'tenant',$1);
		INSERT INTO users(id,username,display_name,password_hash)
			VALUES($3,$4,'Site runtime v2 foreign user','not-used');
		INSERT INTO memberships(scope_id,user_id) VALUES($2,$3)`, pgx.QueryExecModeSimpleProtocol,
		tenantID, scopeID, userID, username); err != nil {
		t.Fatal(err)
	}
	seedSiteRuntimeV2CertificateBindingWithOptions(t, fixture, site, siteRuntimeV2CertificateSeedOptions{
		scopeID: scopeID, userID: userID, bypassBindingValidation: true,
	})
}

func seedSiteRuntimeV2InactiveVersionBinding(t *testing.T, fixture *publishFixture, site fixtureSite) {
	t.Helper()
	active := seedSiteRuntimeV2CertificateBindingWithOptions(
		t, fixture, site, siteRuntimeV2CertificateSeedOptions{})
	inactiveVersionID := uuid.New()
	seed := sha256.Sum256([]byte(inactiveVersionID.String()))
	privateKeyReference := "site-runtime-v2:" + inactiveVersionID.String()
	tx, err := fixture.pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if _, err := tx.Exec(t.Context(), `INSERT INTO certificate_asset_versions(
			tenant_scope_id,id,asset_id,actor_scope_id,version,initial_status,fingerprint_sha256,certificate_pem,
			public_key_sha256,private_key_reference,private_key_aad_sha256,sans,leaf_subject,serial_number,
			public_key_algorithm,public_key_bits,signature_algorithm,not_before,not_after,
			imported_by_user_id,imported_at
		) VALUES($1,$2,$3,$1,2,'pending_activation',$4,$5,$4,$6,$4,$7,$8,$9,'ed25519',256,'ed25519',$10,$11,$12,$13)`,
		active.scopeID, inactiveVersionID, active.assetID, seed[:], []byte("site-runtime-v2-inactive-certificate"),
		privateKeyReference, []string{site.Domain}, "CN="+site.Domain, fmt.Sprintf("%x", inactiveVersionID[:]),
		publishTestClock.Add(-time.Hour), publishTestClock.Add(24*time.Hour), active.userID,
		publishTestClock.Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(t.Context(), `INSERT INTO certificate_asset_private_key_envelope_facts(
			tenant_scope_id,asset_id,version_id,actor_scope_id,sequence,certificate_fingerprint_sha256,
			certificate_public_key_sha256,private_key_reference,aad_sha256,private_key_ciphertext,
			private_key_key_id,private_key_nonce,private_key_metadata,change_kind,request_id,
			changed_by_user_id,changed_at
		) VALUES($1,$2,$3,$1,1,$4,$4,$5,$4,$6,'site-runtime-v2-test-key',$7,'{}'::jsonb,
			'initial',$8,$9,$10)`, active.scopeID, active.assetID, inactiveVersionID, seed[:], privateKeyReference,
		bytes.Repeat([]byte{0x01}, 16), bytes.Repeat([]byte{0x02}, 12),
		"site-runtime-v2-envelope-"+inactiveVersionID.String(), active.userID,
		publishTestClock.Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(t.Context(), `ALTER TABLE certificate_site_binding_facts
		DISABLE TRIGGER certificate_site_bindings_immutable`); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(t.Context(), `INSERT INTO certificate_site_binding_facts(
			tenant_scope_id,site_id,sequence,action,asset_id,version_id,is_default,expected_revision,
			resulting_revision,request_id,actor_scope_id,changed_by_user_id,changed_at
		) VALUES($1,$2,2,'bind',$3,$4,true,1,2,$5,$1,$6,$7)`, active.scopeID, site.ID,
		active.assetID, inactiveVersionID, "site-runtime-v2-bind-inactive-"+site.ID.String(),
		active.userID, publishTestClock); err != nil {
		t.Fatal(err)
	}
	insertSiteRuntimeV2PublicationIntent(t, tx, active.scopeID, site.ID, 2)
	if _, err := tx.Exec(t.Context(), `ALTER TABLE certificate_site_binding_facts
		ENABLE TRIGGER certificate_site_bindings_immutable`); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
}

func seedSiteRuntimeV2ExpiredBinding(t *testing.T, fixture *publishFixture, site fixtureSite) {
	t.Helper()
	seedSiteRuntimeV2CertificateBindingWithOptions(t, fixture, site, siteRuntimeV2CertificateSeedOptions{
		notBefore:   publishTestClock.Add(-4 * time.Hour),
		notAfter:    publishTestClock.Add(-time.Hour),
		activatedAt: publishTestClock.Add(-3 * time.Hour),
		changedAt:   publishTestClock.Add(-2 * time.Hour),
	})
}

func seedSiteRuntimeV2RevokedBinding(t *testing.T, fixture *publishFixture, site fixtureSite) {
	t.Helper()
	seeded := seedSiteRuntimeV2CertificateBindingWithOptions(
		t, fixture, site, siteRuntimeV2CertificateSeedOptions{})
	tx, err := fixture.pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if _, err := tx.Exec(t.Context(), `UPDATE certificate_assets SET revision=3,updated_at=$3,
		updated_by_user_id=$4 WHERE tenant_scope_id=$1 AND id=$2`, seeded.scopeID, seeded.assetID,
		publishTestClock, seeded.userID); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(t.Context(), `ALTER TABLE certificate_asset_revocation_facts
		DISABLE TRIGGER certificate_asset_revocations_immutable`); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(t.Context(), `INSERT INTO certificate_asset_revocation_facts(
			tenant_scope_id,asset_id,version_id,actor_scope_id,expected_asset_revision,resulting_asset_revision,
			reason,request_id,revoked_by_user_id,revoked_at
		) VALUES($1,$2,$3,$1,2,3,'site runtime v2 regression',$6,$4,$5)`,
		seeded.scopeID, seeded.assetID, seeded.versionID, seeded.userID, publishTestClock,
		"site-runtime-v2-revoke-"+seeded.versionID.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(t.Context(), `ALTER TABLE certificate_asset_revocation_facts
		ENABLE TRIGGER certificate_asset_revocations_immutable`); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
}

func assertSiteRuntimeV2ApprovedArtifact(t *testing.T, pool *pgxpool.Pool, result PublishResult) {
	t.Helper()
	const (
		wantCanonical = `{"config_version_id":"a9f85495-dc8d-53ab-bac6-597baa7b57ec","configuration_scope_id":"018f47a2-5b9c-7d31-8a60-104c9c0b7101","lazy_certificates":{"cache_max":10000},"required_capabilities":[{"api_version":1,"name":"http1"},{"api_version":1,"name":"http2"},{"api_version":1,"name":"http3"},{"api_version":1,"name":"ipv4"},{"api_version":1,"name":"ipv6"},{"api_version":7,"name":"site_runtime"},{"api_version":1,"name":"websocket"}],"schema":"cdnca.edge.site-runtime/v2","sites":[{"cache":{"domain":"runtime-v2-capable.example.test","policy":{"disk_quota_bytes":0,"mode":"disabled","query_mode":"ignore","query_names":[],"revision":0,"rules":[],"vary_headers":[]},"tenant_id":"018f47a2-5b9c-7d31-8a60-104c9c0b7200"},"default_pool_id":"primary","domains":["runtime-v2-capable.example.test"],"id":"018f47a2-5b9c-7d31-8a60-104c9c0b7103","l2":{"enabled":false,"failure_threshold":3,"max_hops":1,"probe_interval_ms":10000,"recovery_threshold":3,"single_half_open_probe":true},"listeners":[{"address_family":"dual_stack","id":"public-80","port":80,"position":0,"protocols":["http1"]},{"address_family":"dual_stack","id":"public-443","port":443,"position":1,"protocols":["http1","http2","http3"],"tls":{"certificate_version_id":"018f47a2-5b9c-7d31-8a60-104c9c0b7104","protocols":["TLSv1.2","TLSv1.3"]}}],"origin_pools":[{"algorithm":"round_robin","id":"primary","kind":"origin","origins":[{"host":"203.0.113.10","id":"origin-0","port":8080,"position":0,"scheme":"http","tier":"origin","weight":1}],"position":0,"retry":{"bodyless_only":true,"connect_timeout_ms":3000,"max_attempts":2,"methods":["GET","HEAD"],"read_timeout_ms":30000,"response_not_started":true,"retry_on":["connect_error","connect_timeout","read_timeout","http_502","http_503","http_504"],"total_budget_ms":60000}}],"range":true,"revision":7,"websocket":true}],"source_revision":41}`
		wantDigestHex = "8b98549b3735e91beeb1e5cf87045fe7f993a5105faec193e86253e786ea01ec"
		wantConfigID  = "a9f85495-dc8d-53ab-bac6-597baa7b57ec"
	)
	want := []byte(wantCanonical)
	wantDigest := sha256.Sum256(want)
	if fmt.Sprintf("%x", wantDigest) != wantDigestHex {
		t.Fatalf("test-owned S0 oracle digest drifted: got %x want %s", wantDigest, wantDigestHex)
	}
	if result.ConfigVersionID != uuid.MustParse(wantConfigID) {
		t.Fatalf("config ID=%s want deterministic %s", result.ConfigVersionID, wantConfigID)
	}
	// Site runtime v8: one signed plaintext root naming the canonical
	// document, plus the node's HPKE key envelope (which carries no part of
	// the document).
	var canonical, root, envelope, rootDigest []byte
	var rootID, envelopeID uuid.UUID
	var recipientKeyID string
	if err := pool.QueryRow(t.Context(), `SELECT config.canonical_snapshot,root.id,root.wire_bytes,root.sha256,
		envelope.id,envelope.wire_bytes,envelope.recipient_key_id
		FROM config_versions config
		JOIN configuration_artifacts root ON root.config_version_id=config.id AND root.media_type=$2
		  AND root.encryption_algorithm='none' AND root.recipient_key_id IS NULL
		JOIN configuration_artifacts envelope ON envelope.config_version_id=config.id AND envelope.media_type=$3
		  AND envelope.encryption_algorithm='hpke_x25519_hkdf_sha256_aes_256_gcm'
		WHERE config.id=$1`, result.ConfigVersionID, siteobject.RootMediaTypeV2, siteobject.KeyMediaType).
		Scan(&canonical, &rootID, &root, &rootDigest, &envelopeID, &envelope, &recipientKeyID); err != nil {
		t.Fatal(err)
	}
	parsed, err := siteobject.ParseRootV2(root)
	wireDigest := sha256.Sum256(root)
	if err != nil || !bytes.Equal(canonical, want) || rootID == uuid.Nil || envelopeID == uuid.Nil ||
		parsed.DocumentSHA256 != wantDigestHex || parsed.ConfigVersionID != wantConfigID ||
		!regexp.MustCompile(`^x25519:[0-9a-f]{64}$`).MatchString(recipientKeyID) ||
		bytes.Contains(envelope, canonical) || bytes.Contains(root, canonical) ||
		!bytes.Equal(rootDigest, wireDigest[:]) || result.CanonicalSnapshotSHA256 != wantDigest {
		t.Fatalf("approved S0/v8 identity canonical=%t root=%s envelope=%s recipient=%q root digest=%x document=%s (%v)",
			bytes.Equal(canonical, want), rootID, envelopeID, recipientKeyID, wireDigest, parsed.DocumentSHA256, err)
	}
}

// Site runtime v1 is gone (1.0.35): a request naming it is refused before
// anything is persisted.
func TestSiteRuntimeV1PublishIsRefused(t *testing.T) {
	fixture := newPublishFixture(t)
	fixture.createSite(t, "runtime-v1-refused.example.test", 80, false)
	request := siteRuntimeV2PublishRequest(fixture, "runtime-v1-refused", fixture.nodeID, "cdnca.edge.site-runtime/v1")
	if _, err := fixture.service.Publish(t.Context(), request); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("site-runtime/v1 Publish = %v, want ErrInvalidInput", err)
	}
	assertPublishState(t, fixture.pool, 0, 0, 0, 0, 0)
}
