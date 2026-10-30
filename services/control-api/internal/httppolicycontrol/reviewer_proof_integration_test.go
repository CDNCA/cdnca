package httppolicycontrol

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/entitlement"
	"github.com/cdnca/cdnca/services/control-api/internal/entitlementguard"
	"github.com/cdnca/cdnca/services/control-api/internal/entitlementguard/guardtest"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

type reviewerLeaseFixture struct {
	fixture    *integrationFixture
	trust      *entitlementguard.TrustStore
	privateKey ed25519.PrivateKey
	now        time.Time
}

type reviewerPreparedOperation struct {
	name   string
	invoke func(context.Context, *Service, string, int) (WriteResult, error)
}

type httpPolicyReviewerFacts struct {
	policies         string
	revisions        string
	publicationHeads string
	writes           string
	audits           string
}

func TestHTTPPolicyEntitlementAdapterQuotaAndReplayProof(t *testing.T) {
	t.Run("at_limit_enabled_create", func(t *testing.T) {
		proof := newReviewerLeaseFixture(t)
		installReviewerLease(t, proof, 1, 3)
		result, err := proof.fixture.service.Create(context.Background(), proof.fixture.ownerA, CreateRequest{
			TargetScopeID: proof.fixture.tenantA, SiteID: proof.fixture.siteA, Enabled: true,
			Config: validTestConfig(), WriteMetadata: testMetadata("quota-at-limit"),
		})
		if err != nil || !result.Policy.Enabled {
			t.Fatalf("at-limit enabled create = (%#v, %v)", result, err)
		}
		assertReviewerActiveSiteCount(t, proof.fixture.pool, 3)
	})

	t.Run("over_limit_enabled_create", func(t *testing.T) {
		// A policy on an existing site adds no domain (Delta 0): since FX06 it
		// stays allowed after the lease quota is lowered below the current
		// usage (entitlementguard.check); the lease state and feature apply.
		proof := newReviewerLeaseFixture(t)
		installReviewerLease(t, proof, 1, 2)
		result, err := proof.fixture.service.Create(context.Background(), proof.fixture.ownerA, CreateRequest{
			TargetScopeID: proof.fixture.tenantA, SiteID: proof.fixture.siteA, Enabled: true,
			Config: validTestConfig(), WriteMetadata: testMetadata("quota-over-limit"),
		})
		if err != nil || !result.Policy.Enabled {
			t.Fatalf("over-limit enabled create = (%#v, %v)", result, err)
		}
		assertReviewerActiveSiteCount(t, proof.fixture.pool, 3)
		var policies int
		if err := proof.fixture.pool.QueryRow(context.Background(),
			`SELECT count(*) FROM http_policies WHERE site_id=$1`, proof.fixture.siteA).Scan(&policies); err != nil || policies != 1 {
			t.Fatalf("over-limit policy count = %d, error = %v", policies, err)
		}
	})

	t.Run("disabled_create_and_reenable_at_limit", func(t *testing.T) {
		proof := newReviewerLeaseFixture(t)
		installReviewerLease(t, proof, 1, 3)
		created, err := proof.fixture.service.Create(context.Background(), proof.fixture.ownerA, CreateRequest{
			TargetScopeID: proof.fixture.tenantA, SiteID: proof.fixture.siteA, Enabled: false,
			Config: validTestConfig(), WriteMetadata: testMetadata("quota-disabled-create"),
		})
		if err != nil || created.Policy.Enabled {
			t.Fatalf("disabled create = (%#v, %v)", created, err)
		}
		enabled, err := proof.fixture.service.SetEnabled(context.Background(), proof.fixture.ownerA, StateRequest{
			TargetScopeID: proof.fixture.tenantA, ID: created.Policy.ID,
			ExpectedRevision: created.Policy.Revision, Enabled: true,
			WriteMetadata: testMetadata("quota-reenable"),
		})
		if err != nil || !enabled.Policy.Enabled {
			t.Fatalf("reenable at limit = (%#v, %v)", enabled, err)
		}
		assertReviewerActiveSiteCount(t, proof.fixture.pool, 3)
	})

	t.Run("transient_unavailable_completed_replay", func(t *testing.T) {
		proof := newReviewerLeaseFixture(t)
		request := CreateRequest{
			TargetScopeID: proof.fixture.tenantA, SiteID: proof.fixture.siteA, Enabled: true,
			Config: validTestConfig(), WriteMetadata: testMetadata("transient-unavailable"),
		}
		if _, err := proof.fixture.service.Create(context.Background(), proof.fixture.ownerA, request); !errors.Is(err, ErrEntitlementUnavailable) {
			t.Fatalf("fresh transient unavailable error = %v", err)
		}
		installReviewerLease(t, proof, 1, 3)
		beforeReplay := readHTTPPolicyReviewerFacts(t, proof.fixture.pool)
		if _, err := proof.fixture.service.Create(context.Background(), proof.fixture.ownerA, request); !errors.Is(err, ErrEntitlementUnavailable) {
			t.Fatalf("completed unavailable replay error = %v", err)
		}
		assertHTTPPolicyReviewerFacts(t, proof.fixture.pool, beforeReplay)
		request.WriteMetadata = testMetadata("transient-recovered-fresh")
		if _, err := proof.fixture.service.Create(context.Background(), proof.fixture.ownerA, request); err != nil {
			t.Fatalf("fresh request after entitlement recovery = %v", err)
		}
	})
}

func TestHTTPPolicyPublicationTransactionBoundsProof(t *testing.T) {
	t.Run("max_sites_plus_one_rolls_back", func(t *testing.T) {
		fixture := newIntegrationFixture(t, allowTestGate())
		for index := 0; index < MaxSites; index++ {
			siteID := insertTestSite(t, fixture.pool, fixture.tenantA, fixture.ownerA.UserID,
				fmt.Sprintf("publication-site-%03d.example.test", index))
			createServicePolicy(t, fixture, siteID, fmt.Sprintf("publication-site-%03d", index))
		}
		overflowSite := insertTestSite(t, fixture.pool, fixture.tenantA, fixture.ownerA.UserID,
			"publication-site-overflow.example.test")
		before := readHTTPPolicyReviewerFacts(t, fixture.pool)
		if _, err := fixture.service.Create(context.Background(), fixture.ownerA, CreateRequest{
			TargetScopeID: fixture.tenantA, SiteID: overflowSite, Enabled: true,
			Config: validTestConfig(), WriteMetadata: testMetadata("publication-site-overflow"),
		}); !errors.Is(err, ErrConflict) {
			t.Fatalf("MaxSites+1 create error = %v", err)
		}
		assertHTTPPolicyReviewerFacts(t, fixture.pool, before)
	})

	t.Run("snapshot_bytes_at_limit_succeeds", func(t *testing.T) {
		fixture := newIntegrationFixture(t, allowTestGate())
		config := reviewerSnapshotBoundaryConfig(t, fixture.siteA, MaxPolicyBytes)
		if _, err := fixture.service.Create(context.Background(), fixture.ownerA, CreateRequest{
			TargetScopeID: fixture.tenantA, SiteID: fixture.siteA, Enabled: true,
			Config: config, WriteMetadata: testMetadata("publication-byte-limit"),
		}); err != nil {
			t.Fatalf("1MiB publication create = %v", err)
		}
	})

	t.Run("snapshot_bytes_plus_one_rolls_back", func(t *testing.T) {
		fixture := newIntegrationFixture(t, allowTestGate())
		config := reviewerSnapshotBoundaryConfig(t, fixture.siteA, MaxPolicyBytes+1)
		before := readHTTPPolicyReviewerFacts(t, fixture.pool)
		if _, err := fixture.service.Create(context.Background(), fixture.ownerA, CreateRequest{
			TargetScopeID: fixture.tenantA, SiteID: fixture.siteA, Enabled: true,
			Config: config, WriteMetadata: testMetadata("publication-byte-overflow"),
		}); !errors.Is(err, ErrConflict) {
			t.Fatalf("1MiB+ publication create error = %v", err)
		}
		assertHTTPPolicyReviewerFacts(t, fixture.pool, before)
	})

	for _, action := range []string{"disable", "delete"} {
		t.Run("last_policy_"+action+"_keeps_preview_conflict", func(t *testing.T) {
			fixture := newIntegrationFixture(t, allowTestGate())
			policy := createServicePolicy(t, fixture, fixture.siteA, "last-policy-"+action+"-seed")
			var err error
			if action == "disable" {
				_, err = fixture.service.SetEnabled(context.Background(), fixture.ownerA, StateRequest{
					TargetScopeID: fixture.tenantA, ID: policy.ID, ExpectedRevision: policy.Revision,
					Enabled: false, WriteMetadata: testMetadata("last-policy-disable"),
				})
			} else {
				_, err = fixture.service.Delete(context.Background(), fixture.ownerA, DeleteRequest{
					TargetScopeID: fixture.tenantA, ID: policy.ID, ExpectedRevision: policy.Revision,
					WriteMetadata: testMetadata("last-policy-delete"),
				})
			}
			if err != nil {
				t.Fatalf("last policy %s mutation = %v", action, err)
			}
			beforePreview := readHTTPPolicyReviewerFacts(t, fixture.pool)
			for attempt := 0; attempt < 2; attempt++ {
				response := fixture.request(t, "owner-a", http.MethodGet,
					collectionPath(fixture.tenantA)+"/publication-preview", nil, "", "")
				assertHTTPError(t, response, http.StatusConflict, "resource_conflict")
			}
			assertHTTPPolicyReviewerFacts(t, fixture.pool, beforePreview)
		})
	}
}

func TestHTTPPolicyWriteOperationTransactionProof(t *testing.T) {
	for _, operationName := range []string{"create", "update", "enable", "disable", "delete"} {
		t.Run(operationName+"/changed_completed_replay", func(t *testing.T) {
			fixture := newIntegrationFixture(t, allowTestGate())
			operation := prepareReviewerOperation(t, fixture, operationName)
			key := "changed-replay-" + operationName
			first, err := operation.invoke(context.Background(), fixture.service, key, 0)
			if err != nil || first.Replayed {
				t.Fatalf("first write = (%#v, %v)", first, err)
			}
			replayed, err := operation.invoke(context.Background(), fixture.service, key, 0)
			if err != nil || !replayed.Replayed {
				t.Fatalf("completed replay = (%#v, %v)", replayed, err)
			}
			beforeConflict := readHTTPPolicyReviewerFacts(t, fixture.pool)
			if _, err := operation.invoke(context.Background(), fixture.service, key, 1); !errors.Is(err, ErrIdempotencyConflict) {
				t.Fatalf("changed completed replay error = %v", err)
			}
			assertHTTPPolicyReviewerFacts(t, fixture.pool, beforeConflict)
		})

		t.Run(operationName+"/audit_failure_rolls_back", func(t *testing.T) {
			fixture := newIntegrationFixture(t, allowTestGate())
			operation := prepareReviewerOperation(t, fixture, operationName)
			store, err := newStoreWithDependencies(
				fixture.pool, func() time.Time { return fixture.now }, allowTestGate(), failingAudit{}, databaseTxAuthorizer{})
			if err != nil {
				t.Fatal(err)
			}
			before := readHTTPPolicyReviewerFacts(t, fixture.pool)
			if _, err := operation.invoke(context.Background(), NewService(store), "audit-failure-"+operationName, 0); !errors.Is(err, ErrUnavailable) {
				t.Fatalf("audit failure error = %v", err)
			}
			assertHTTPPolicyReviewerFacts(t, fixture.pool, before)
		})

		t.Run(operationName+"/concurrent_single_winner", func(t *testing.T) {
			fixture := newIntegrationFixture(t, allowTestGate())
			operation := prepareReviewerOperation(t, fixture, operationName)
			before := readHTTPPolicyFactCounts(t, fixture.pool)
			beforePublication := reviewerPublicationRevisionTotal(t, fixture.pool)
			start := make(chan struct{})
			results := make(chan authorizationResult, 2)
			var wait sync.WaitGroup
			for index := 0; index < 2; index++ {
				wait.Add(1)
				go func(index int) {
					defer wait.Done()
					<-start
					result, err := operation.invoke(context.Background(), fixture.service,
						fmt.Sprintf("single-winner-%s-%d", operationName, index), 0)
					results <- authorizationResult{result: result, err: err}
				}(index)
			}
			close(start)
			wait.Wait()
			close(results)
			successes, losers := 0, 0
			for result := range results {
				if result.err == nil {
					successes++
					continue
				}
				if reviewerExpectedConcurrentLoss(operationName, result.err) {
					losers++
					continue
				}
				t.Fatalf("unexpected concurrent result = (%#v, %v)", result.result, result.err)
			}
			if successes != 1 || losers != 1 {
				t.Fatalf("concurrent successes=%d losers=%d", successes, losers)
			}
			after := readHTTPPolicyFactCounts(t, fixture.pool)
			policyDelta := 0
			if operationName == "create" {
				policyDelta = 1
			}
			if after.policies != before.policies+policyDelta || after.revisions != before.revisions+1 ||
				after.writes != before.writes+1 || after.audits != before.audits+1 {
				t.Fatalf("single-winner facts before=%+v after=%+v", before, after)
			}
			if afterPublication := reviewerPublicationRevisionTotal(t, fixture.pool); afterPublication != beforePublication+1 {
				t.Fatalf("publication revision before=%d after=%d", beforePublication, afterPublication)
			}
		})
	}
}

func newReviewerLeaseFixture(t *testing.T) *reviewerLeaseFixture {
	t.Helper()
	pool := openHTTPPolicyTestPool(t)
	fixture := seedIntegrationFixture(t, pool)
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	trust, err := entitlementguard.NewTrustStore([]entitlementguard.VerificationKey{{
		KeyID: "http-policy-test-key", PublicKey: publicKey,
	}})
	if err != nil {
		t.Fatal(err)
	}
	proof := &reviewerLeaseFixture{
		fixture: fixture, trust: trust, privateKey: privateKey,
		now: httpPolicyTestBase.Add(9 * time.Minute),
	}
	store, err := newStoreWithAuthorizer(pool, func() time.Time { return proof.now }, trust, databaseTxAuthorizer{})
	if err != nil {
		t.Fatal(err)
	}
	fixture.service = NewService(store)
	return proof
}

func installReviewerLease(t *testing.T, proof *reviewerLeaseFixture, serial uint64, limit int64) {
	t.Helper()
	lease := entitlement.Lease{
		Schema: entitlement.SchemaV1, Audience: entitlement.ControlAudience,
		// Canonical UUIDs: a revocation set accepts nothing else.
		CustomerID: "6e1b0c5a-4c1f-4a52-9a0c-56d1f0c12001", InstallationID: "6e1b0c5a-4c1f-4a52-9a0c-56d1f0c12002",
		LicenseID: "6e1b0c5a-4c1f-4a52-9a0c-56d1f0c12003", Serial: serial,
		NotBefore: proof.now.Add(-time.Hour).Unix(), ExpiresAt: proof.now.Add(time.Hour).Unix(),
		GraceUntil: proof.now.Add(2 * time.Hour).Unix(),
		Version:    entitlement.VersionRange{Channel: "stable", Min: "0.1.0", Max: "1.0.0"},
		Features:   []entitlement.Feature{{Code: entitlementguard.FeatureSitesManage}},
		Quotas:     []entitlement.Quota{{Code: entitlementguard.QuotaDomainsCount, Limit: limit}},
	}
	signed, err := entitlement.Sign(context.Background(), lease, testLeaseSigner{private: proof.privateKey})
	if err != nil {
		t.Fatal(err)
	}
	var accepted bool
	if err := proof.fixture.pool.QueryRow(context.Background(),
		`SELECT EXISTS(SELECT 1 FROM entitlement_signing_keyset_lkg)`).Scan(&accepted); err != nil {
		t.Fatal(err)
	}
	if !accepted {
		guardtest.AcceptRevocation(t, proof.fixture.pool, proof.trust, testLeaseSigner{private: proof.privateKey}, lease, proof.now)
	}
	if _, err := entitlementguard.NewService(proof.fixture.pool, proof.trust).Install(context.Background(),
		entitlementguard.InstallBundle{InstallationID: lease.InstallationID, SignedLease: signed}, proof.now); err != nil {
		t.Fatal(err)
	}
}

func prepareReviewerOperation(t *testing.T, fixture *integrationFixture, name string) reviewerPreparedOperation {
	t.Helper()
	switch name {
	case "create":
		return reviewerPreparedOperation{name: name, invoke: func(ctx context.Context, service *Service, key string, variant int) (WriteResult, error) {
			config := validTestConfig()
			config.MaxUploadBytes += int64(variant)
			return service.Create(ctx, fixture.ownerA, CreateRequest{
				TargetScopeID: fixture.tenantA, SiteID: fixture.siteA, Enabled: true,
				Config: config, WriteMetadata: testMetadata(key),
			})
		}}
	case "update":
		policy := createServicePolicy(t, fixture, fixture.siteA, "reviewer-seed-update")
		return reviewerPreparedOperation{name: name, invoke: func(ctx context.Context, service *Service, key string, variant int) (WriteResult, error) {
			config := validTestConfig()
			config.MaxUploadBytes = 64 + int64(variant)
			return service.Update(ctx, fixture.ownerA, UpdateRequest{
				TargetScopeID: fixture.tenantA, ID: policy.ID, ExpectedRevision: policy.Revision,
				Config: config, WriteMetadata: testMetadata(key),
			})
		}}
	case "enable":
		created, err := fixture.service.Create(context.Background(), fixture.ownerA, CreateRequest{
			TargetScopeID: fixture.tenantA, SiteID: fixture.siteA, Enabled: false,
			Config: validTestConfig(), WriteMetadata: testMetadata("reviewer-seed-enable"),
		})
		if err != nil {
			t.Fatal(err)
		}
		return reviewerPreparedOperation{name: name, invoke: func(ctx context.Context, service *Service, key string, variant int) (WriteResult, error) {
			return service.SetEnabled(ctx, fixture.ownerA, StateRequest{
				TargetScopeID: fixture.tenantA, ID: created.Policy.ID,
				ExpectedRevision: created.Policy.Revision + int64(variant), Enabled: true,
				WriteMetadata: testMetadata(key),
			})
		}}
	case "disable":
		policy := createServicePolicy(t, fixture, fixture.siteA, "reviewer-seed-disable")
		return reviewerPreparedOperation{name: name, invoke: func(ctx context.Context, service *Service, key string, variant int) (WriteResult, error) {
			return service.SetEnabled(ctx, fixture.ownerA, StateRequest{
				TargetScopeID: fixture.tenantA, ID: policy.ID,
				ExpectedRevision: policy.Revision + int64(variant), Enabled: false,
				WriteMetadata: testMetadata(key),
			})
		}}
	case "delete":
		policy := createServicePolicy(t, fixture, fixture.siteA, "reviewer-seed-delete")
		return reviewerPreparedOperation{name: name, invoke: func(ctx context.Context, service *Service, key string, variant int) (WriteResult, error) {
			return service.Delete(ctx, fixture.ownerA, DeleteRequest{
				TargetScopeID: fixture.tenantA, ID: policy.ID,
				ExpectedRevision: policy.Revision + int64(variant), WriteMetadata: testMetadata(key),
			})
		}}
	default:
		t.Fatalf("unknown reviewer operation %q", name)
		return reviewerPreparedOperation{}
	}
}

func reviewerSnapshotBoundaryConfig(t *testing.T, siteID uuid.UUID, targetBytes int) Config {
	t.Helper()
	policyFor := func(config Config) Policy {
		return Policy{
			SiteID: siteID, MaxUploadBytes: config.MaxUploadBytes,
			RequestHeaders: config.RequestHeaders, ResponseHeaders: config.ResponseHeaders,
			Rewrites: config.Rewrites, RedirectAllowedHosts: config.RedirectAllowedHosts,
			Redirects: config.Redirects, CORS: config.CORS, Enabled: true,
		}
	}
	baseline, err := normalizeConfig(validTestConfig())
	if err != nil {
		t.Fatalf("normalize baseline config: %v", err)
	}
	baselinePolicy := policyFor(baseline)
	_, baselineCanonical, _, err := canonicalSnapshot(1, []Policy{baselinePolicy})
	if err != nil {
		t.Fatalf("canonical baseline snapshot: %v", err)
	}
	baselineConfig, err := json.Marshal(baseline)
	if err != nil {
		t.Fatal(err)
	}
	envelopeBytes := len(baselineCanonical) - len(baselineConfig)
	if envelopeBytes <= 0 || targetBytes <= envelopeBytes {
		t.Fatalf("snapshot envelope=%d target=%d", envelopeBytes, targetBytes)
	}
	targetConfigBytes := targetBytes - envelopeBytes

	actions := make([]HeaderAction, MaxHeaderActions)
	for actionIndex := range actions {
		values := make([]string, MaxHeaderValues)
		for valueIndex := range values {
			values[valueIndex] = strings.Repeat("v", MaxHeaderBytes)
		}
		actions[actionIndex] = HeaderAction{
			Kind: HeaderSet, Name: fmt.Sprintf("x-reviewer-%02d", actionIndex), Values: values,
		}
	}
	config := baseline
	config.RequestHeaders = actions
	encoded, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	shrink := len(encoded) - targetConfigBytes
	if shrink < 0 {
		t.Fatalf("maximum ASCII filler config bytes=%d target=%d", len(encoded), targetConfigBytes)
	}
	for actionIndex := len(config.RequestHeaders) - 1; actionIndex >= 0 && shrink > 0; actionIndex-- {
		for valueIndex := len(config.RequestHeaders[actionIndex].Values) - 1; valueIndex >= 0 && shrink > 0; valueIndex-- {
			value := config.RequestHeaders[actionIndex].Values[valueIndex]
			amount := min(shrink, len(value)-1)
			config.RequestHeaders[actionIndex].Values[valueIndex] = value[:len(value)-amount]
			shrink -= amount
		}
	}
	if shrink != 0 {
		t.Fatalf("could not construct boundary config, remaining shrink=%d", shrink)
	}
	normalized, err := normalizeConfig(config)
	if err != nil {
		t.Fatalf("normalize boundary config: %v", err)
	}
	encoded, err = json.Marshal(normalized)
	if err != nil || len(encoded) != targetConfigBytes {
		t.Fatalf("boundary config bytes=%d want=%d error=%v", len(encoded), targetConfigBytes, err)
	}
	policy := policyFor(normalized)
	raw, err := json.Marshal(EdgeSnapshot{
		SchemaVersion: EdgeSchemaVersion, PolicyVersion: 1, Sites: []EdgeSitePolicy{edgeSite(policy)},
	})
	if err != nil {
		t.Fatal(err)
	}
	raw = append(raw, '\n')
	if len(raw)-len(encoded) != envelopeBytes || len(raw) != targetBytes {
		t.Fatalf("snapshot bytes=%d config=%d envelope=%d want snapshot=%d envelope=%d",
			len(raw), len(encoded), len(raw)-len(encoded), targetBytes, envelopeBytes)
	}
	_, canonical, _, snapshotErr := canonicalSnapshot(1, []Policy{policy})
	if targetBytes == MaxPolicyBytes {
		if snapshotErr != nil || len(canonical) != targetBytes {
			t.Fatalf("max canonical snapshot bytes=%d error=%v", len(canonical), snapshotErr)
		}
	} else if targetBytes == MaxPolicyBytes+1 {
		if !errors.Is(snapshotErr, ErrConflict) {
			t.Fatalf("max+1 canonical snapshot error=%v", snapshotErr)
		}
	} else {
		t.Fatalf("unsupported reviewer snapshot target=%d", targetBytes)
	}
	return normalized
}

func readHTTPPolicyReviewerFacts(t *testing.T, pool *pgxpool.Pool) httpPolicyReviewerFacts {
	t.Helper()
	var facts httpPolicyReviewerFacts
	err := pool.QueryRow(context.Background(), `SELECT
		md5(COALESCE((SELECT jsonb_agg(to_jsonb(policy_row) ORDER BY policy_row.id)::text FROM http_policies policy_row), '[]')),
		md5(COALESCE((SELECT jsonb_agg(to_jsonb(revision_row) ORDER BY revision_row.policy_id, revision_row.revision)::text FROM http_policy_revisions revision_row), '[]')),
		md5(COALESCE((SELECT jsonb_agg(to_jsonb(head_row) ORDER BY head_row.tenant_scope_id)::text FROM http_policy_publication_heads head_row), '[]')),
		md5(COALESCE((SELECT jsonb_agg(to_jsonb(write_row) ORDER BY write_row.id)::text FROM http_policy_write_requests write_row), '[]')),
		md5(COALESCE((SELECT jsonb_agg(to_jsonb(audit_row) ORDER BY audit_row.scope_id, audit_row.stream_position)::text FROM audit_events audit_row), '[]'))`).Scan(
		&facts.policies, &facts.revisions, &facts.publicationHeads, &facts.writes, &facts.audits)
	if err != nil {
		t.Fatal(err)
	}
	return facts
}

func assertHTTPPolicyReviewerFacts(t *testing.T, pool *pgxpool.Pool, expected httpPolicyReviewerFacts) {
	t.Helper()
	if actual := readHTTPPolicyReviewerFacts(t, pool); actual != expected {
		t.Fatalf("HTTP policy facts changed: got=%+v want=%+v", actual, expected)
	}
}

func assertReviewerActiveSiteCount(t *testing.T, pool *pgxpool.Pool, expected int64) {
	t.Helper()
	var actual int64
	if err := pool.QueryRow(context.Background(),
		`SELECT count(*) FROM sites WHERE deleted_at IS NULL AND enabled=true`).Scan(&actual); err != nil {
		t.Fatal(err)
	}
	if actual != expected {
		t.Fatalf("active site count = %d, want %d", actual, expected)
	}
}

func reviewerPublicationRevisionTotal(t *testing.T, pool *pgxpool.Pool) int64 {
	t.Helper()
	var revision int64
	if err := pool.QueryRow(context.Background(),
		`SELECT COALESCE(sum(revision),0) FROM http_policy_publication_heads`).Scan(&revision); err != nil {
		t.Fatal(err)
	}
	return revision
}

func reviewerExpectedConcurrentLoss(operation string, err error) bool {
	switch operation {
	case "create":
		return errors.Is(err, ErrConflict)
	case "delete":
		return errors.Is(err, ErrNotFound)
	default:
		return errors.Is(err, ErrRevisionConflict)
	}
}
