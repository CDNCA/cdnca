package httpapi

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"net/http"
	"net/url"
	"reflect"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/apikeycredential"
	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/iamlock"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	kyc "github.com/cdnca/cdnca/services/control-api/internal/identityverification"
	"github.com/cdnca/cdnca/services/control-api/internal/sessioncredential"
	"github.com/google/uuid"
)

func TestIdentityUserVerificationProjectionHTTP(t *testing.T) {
	f := newUserMetadataHTTPFixture(t)
	user, body := f.create(t, "verification-none", nil, false)
	page := f.request(t, http.MethodGet, "/v1/admin/users?include=user_verification", "verification-list", nil, http.StatusOK)
	items := page["items"].([]any)
	if page["total"] != float64(1) || len(items) != 1 {
		t.Fatalf("unexpected verification page: %v", page)
	}
	listed := items[0].(map[string]any)
	if len(listed) != 16 || listed["id"] != user["id"] || !reflect.DeepEqual(listed["verification"], map[string]any{
		"personal_verified": false, "company_verified": false,
	}) {
		t.Fatalf("unexpected verification projection: %v", listed)
	}
	for _, tc := range []struct {
		include string
		keys    int
	}{
		{"", 15}, {"user_metadata", 16}, {"user_verification", 16},
		{"user_metadata,user_verification", 17}, {"user_verification,user_metadata", 17},
	} {
		query := ""
		if tc.include != "" {
			query = "?include=" + tc.include
		}
		result := f.request(t, http.MethodGet, "/v1/admin/users"+query, "shapes", nil, 200)
		item := result["items"].([]any)[0].(map[string]any)
		if len(item) != tc.keys {
			t.Fatalf("include %q shape: %v", tc.include, item)
		}
		if metadata, ok := item["metadata"]; ok && !reflect.DeepEqual(metadata, map[string]any{"remark": nil, "qq": nil}) {
			t.Fatalf("metadata shape: %v", metadata)
		}
	}
	for _, query := range []string{
		"include=", "include=user_verification,user_verification", "include=user_metadata,user_metadata",
		"include=user_metadata,", "include=,user_verification", "include=user_verification,unknown",
		"include=user_verification&include=user_metadata", "include=user_verification;ignored", "include=%zz",
		"real_name_status=", "real_name_status=all", "real_name_status=approved", "real_name_status=VERIFIED",
		"real_name_status=verified&real_name_status=unverified", "real_name_status=%20verified",
	} {
		f.request(t, http.MethodGet, "/v1/admin/users?"+query, "invalid-verification", nil, 400)
	}
	for _, route := range []struct{ method, path string }{
		{http.MethodGet, metadataUserPath(user)}, {http.MethodPost, "/v1/admin/users"},
		{http.MethodPatch, metadataUserPath(user)}, {http.MethodPatch, "/v1/admin/users"},
	} {
		f.request(t, route.method, route.path+"?include=user_verification", "invalid-write-projection", nil, 400)
	}
	assertLegacyMetadataUser(t, f.request(t, http.MethodGet, metadataUserPath(user), "detail", nil, 200))
	assertLegacyMetadataUser(t, f.request(t, http.MethodPost, "/v1/admin/users", "create-verification-none", body, 201))
	auth, _ := loginWithPassword(t, f.server.Client(), f.server.URL, user["username"].(string), tenantPassword)
	tenant := f
	tenant.admin = auth.AccessToken
	tenant.request(t, http.MethodGet, "/v1/admin/users?include=user_verification", "tenant-denied", nil, 403)
	// A platform membership without the management permission must not expose the projection.
	var platformScope uuid.UUID
	if err := f.pool.QueryRow(t.Context(), `SELECT id FROM access_scopes WHERE kind='platform'`).Scan(&platformScope); err != nil {
		t.Fatal(err)
	}
	hash, err := identity.HashPassword(testPassword)
	if err != nil {
		t.Fatal(err)
	}
	insertTestUser(t, f.pool, platformScope, "verification-platform-reader", "Reader", hash, "active")
	readerAuth, _ := loginWithPassword(t, f.server.Client(), f.server.URL, "verification-platform-reader", testPassword)
	reader := f
	reader.admin = readerAuth.AccessToken
	reader.request(t, http.MethodGet, "/v1/admin/users?include=user_verification", "platform-denied", nil, 403)
}

// Trusted test evidence is handed to the production service, then settled by the
// production worker. No approved case, identity binding, or settlement is inserted directly.
type verificationProjectionCommitter map[string]bool

func (c verificationProjectionCommitter) Commit(_ context.Context, request kyc.SettlementCommitRequest) (kyc.SettlementCommitResult, error) {
	if request.ResolverName != "projection-test" || !c[request.ResolverReference] {
		return kyc.SettlementCommitResult{}, fmt.Errorf("unrecognized test evidence")
	}
	return kyc.SettlementCommitResult{Outcome: kyc.SettlementCommitSucceeded}, nil
}

type verificationProjectionFixture struct {
	http     userMetadataHTTPFixture
	core     *kyc.Service
	worker   *kyc.SettlementWorker
	tokens   *identity.TokenManager
	evidence verificationProjectionCommitter
	now      time.Time
}

func newVerificationProjectionFixture(t *testing.T, f userMetadataHTTPFixture) *verificationProjectionFixture {
	t.Helper()
	v := &verificationProjectionFixture{http: f, evidence: verificationProjectionCommitter{}, now: time.Now().UTC().Add(-3 * time.Hour)}
	var err error
	v.tokens, err = identity.NewTokenManager("metadata-test-signing-key-at-least-thirty-two-bytes", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	sessions, err := sessioncredential.NewVerifier(v.tokens, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := apikeycredential.NewVerifier(bytes.Repeat([]byte{0x6d}, 32), time.Now)
	if err != nil {
		t.Fatal(err)
	}
	iam, err := iamlock.NewAuthorizer(sessions, keys)
	if err != nil {
		t.Fatal(err)
	}
	v.core, err = kyc.NewIAMService(f.pool, audit.New(f.pool), iam, kyc.Config{Clock: func() time.Time { return v.now }, ReviewTTL: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	v.worker, err = kyc.NewSettlementWorker(f.pool, audit.New(f.pool), v.evidence, kyc.SettlementWorkerConfig{Clock: func() time.Time { return v.now }})
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func (v *verificationProjectionFixture) actor(t *testing.T, username string) kyc.Actor {
	t.Helper()
	auth, _ := loginWithPassword(t, v.http.server.Client(), v.http.server.URL, username, tenantPassword)
	userID, scopeID, sessionID, err := v.tokens.Parse(auth.AccessToken)
	if err != nil {
		t.Fatal(err)
	}
	actor, err := kyc.NewSessionActor(userID, scopeID, "tenant", sessionID, auth.AccessToken)
	if err != nil {
		t.Fatal(err)
	}
	return actor
}

func (v *verificationProjectionFixture) actors(t *testing.T, user map[string]any) (kyc.Actor, kyc.Actor) {
	t.Helper()
	scope := uuid.MustParse(user["scope_id"].(string))
	// Seed scoped IAM test permissions; all identity decisions still use live session authorization.
	if _, err := v.http.pool.Exec(t.Context(), `INSERT INTO role_permissions(role_id,permission_name)
		SELECT role.id,permission.name FROM roles role CROSS JOIN permissions permission
		WHERE role.scope_id=$1 AND (
		  (role.name='tenant_viewer' AND permission.name='identity_verification.self.manage') OR
		  (role.name='tenant_owner' AND permission.name IN ('identity_verification.read','identity_verification.review')))
		ON CONFLICT DO NOTHING`, scope); err != nil {
		t.Fatal(err)
	}
	hash, err := identity.HashPassword(tenantPassword)
	if err != nil {
		t.Fatal(err)
	}
	name := "reviewer-" + user["display_id"].(string)
	reviewerID := insertTestUser(t, v.http.pool, scope, name, "Reviewer", hash, "active")
	if _, err := v.http.pool.Exec(t.Context(), `INSERT INTO role_assignments(scope_id,user_id,role_id)
		SELECT $1,$2,id FROM roles WHERE scope_id=$1 AND name='tenant_owner'`, scope, reviewerID); err != nil {
		t.Fatal(err)
	}
	return v.actor(t, user["username"].(string)), v.actor(t, name)
}

func (v *verificationProjectionFixture) draft(t *testing.T, actor kyc.Actor, kind, key string, fingerprint byte, personal byte) kyc.Case {
	t.Helper()
	v.now = v.now.Add(time.Second)
	request := kyc.CreateDraftRequest{Kind: kind, SubjectFingerprint: bytes.Repeat([]byte{fingerprint}, 32),
		ResolverName: "projection-test", ResolverReference: key, EvidenceClaimDigest: sha256.Sum256([]byte(key)), IdempotencyKey: key, RequestID: key}
	kinds := []string{kyc.MaterialIdentityDocument, kyc.MaterialLivenessEvidence}
	if kind == kyc.KindEnterprise {
		request.OrganizationName = "Private test organization"
		request.LegalPersonFingerprint = bytes.Repeat([]byte{0xf1}, 32)
		request.AgentFingerprint = bytes.Repeat([]byte{personal}, 32)
		request.AgentRelationship = kyc.RelationshipAuthorizedRepresentative
		kinds = []string{kyc.MaterialBusinessLicense, kyc.MaterialLegalIdentity, kyc.MaterialAgentIdentity, kyc.MaterialAuthorization}
	}
	for i, kind := range kinds {
		request.Materials = append(request.Materials, kyc.MaterialInput{Kind: kind, EnvelopeProvider: "kms", EnvelopeKeyID: "projection-test/key",
			EncryptedEnvelope: bytes.Repeat([]byte{byte(i + 1)}, 32), ObjectReference: fmt.Sprintf("private/%s/%d", key, i),
			ObjectSHA256: bytes.Repeat([]byte{byte(i + 1)}, 32), MIMEType: "image/jpeg", SizeBytes: 1024})
	}
	v.evidence[key] = true
	draft, err := v.core.CreateDraft(t.Context(), actor, request)
	if err != nil {
		t.Fatalf("%s draft: %v", key, err)
	}
	return draft
}

func projectionMutation(item kyc.Case, key string) kyc.MutationRequest {
	return kyc.MutationRequest{CaseID: item.ID, ExpectedRevision: item.Revision, IdempotencyKey: key, RequestID: key}
}

func (v *verificationProjectionFixture) submit(t *testing.T, actor kyc.Actor, item kyc.Case, key string) kyc.Case {
	t.Helper()
	processed, err := v.worker.RunOnce(t.Context())
	if err != nil || !processed {
		t.Fatalf("settle: processed=%t error=%v", processed, err)
	}
	item, err = v.core.Submit(t.Context(), actor, projectionMutation(item, key+"-submit"))
	if err != nil {
		t.Fatalf("%s submit: %v", key, err)
	}
	return item
}

func (v *verificationProjectionFixture) decide(t *testing.T, actor, reviewer kyc.Actor, item kyc.Case, key, decision string) kyc.Case {
	t.Helper()
	if item.Status == kyc.StatusDraft {
		item = v.submit(t, actor, item, key)
	}
	item, err := v.core.StartReview(t.Context(), reviewer, projectionMutation(item, key+"-start"))
	if err != nil {
		t.Fatal(err)
	}
	reason := kyc.ReasonEvidenceVerified
	if decision == kyc.DecisionReject {
		reason = kyc.ReasonEvidenceIncomplete
	}
	item, err = v.core.Review(t.Context(), reviewer, kyc.ReviewRequest{CaseID: item.ID, ExpectedRevision: item.Revision,
		Decision: decision, ReasonCode: reason, IdempotencyKey: key + "-decide", RequestID: key + "-decide"})
	if err != nil {
		t.Fatal(err)
	}
	return item
}

func assertVerificationProjection(t *testing.T, f userMetadataHTTPFixture, user map[string]any, personal, company bool) {
	t.Helper()
	page := f.request(t, http.MethodGet, "/v1/admin/users?include=user_verification&display_id="+user["display_id"].(string), "current-status", nil, 200)
	items := page["items"].([]any)
	if page["total"] != float64(1) || len(items) != 1 {
		t.Fatalf("status page: %v", page)
	}
	item := items[0].(map[string]any)
	if len(item) != 16 || !reflect.DeepEqual(item["verification"], map[string]any{"personal_verified": personal, "company_verified": company}) {
		t.Fatalf("status projection: %v", item)
	}
}

func TestIdentityUserVerificationEffectiveStatusHTTP(t *testing.T) {
	f := newUserMetadataHTTPFixture(t)
	v := newVerificationProjectionFixture(t, f)
	plain, _ := f.create(t, "verification-state-none", nil, false)
	personal, _ := f.create(t, "verification-state-personal", map[string]any{"display_name": "Personal Alpha", "email": "verified@example.test", "phone": "+8613800012345", "remark": "Alpha", "qq": "00123"}, false)
	company, _ := f.create(t, "verification-state-company", nil, false)
	group := f.request(t, http.MethodPost, "/v1/admin/user-groups", "verification-group", map[string]any{"name": "Verification group"}, 201)
	update := metadataUpdateBody(personal)
	update["group_id"] = group["id"]
	personal = f.request(t, http.MethodPatch, metadataUserPath(personal), "verification-group-user", update, 200)
	pa, pr := v.actors(t, personal)
	ca, cr := v.actors(t, company)
	p := v.draft(t, pa, kyc.KindPersonalInitial, "personal-initial", 0x31, 0)
	assertVerificationProjection(t, f, personal, false, false)
	p = v.submit(t, pa, p, "personal-initial")
	assertVerificationProjection(t, f, personal, false, false)
	v.decide(t, pa, pr, p, "personal-initial", kyc.DecisionApprove)
	v.decide(t, ca, cr, v.draft(t, ca, kyc.KindPersonalInitial, "company-personal", 0x32, 0), "company-personal", kyc.DecisionApprove)
	v.decide(t, ca, cr, v.draft(t, ca, kyc.KindEnterprise, "company-enterprise", 0x41, 0x32), "company-enterprise", kyc.DecisionApprove)
	assertVerificationProjection(t, f, plain, false, false)
	assertVerificationProjection(t, f, personal, true, false)
	assertVerificationProjection(t, f, company, true, true)
	// The same tenant's reviewer must not inherit the applicant's organization binding.
	page := f.request(t, http.MethodGet, "/v1/admin/users?include=user_verification&username=reviewer-"+company["display_id"].(string), "company-ownership", nil, 200)
	if !reflect.DeepEqual(page["items"].([]any)[0].(map[string]any)["verification"], map[string]any{"personal_verified": false, "company_verified": false}) {
		t.Fatal(page)
	}

	for _, tc := range []struct {
		query        string
		total, items int
	}{
		{"", 3, 3}, {"real_name_status=verified", 2, 2}, {"real_name_status=unverified", 1, 1},
		{"real_name_status=verified&limit=1", 2, 1}, {"real_name_status=verified&limit=1&page=99", 2, 0},
		{"real_name_status=unverified&limit=1&page=99", 1, 0},
	} {
		page := f.request(t, http.MethodGet, "/v1/admin/users?search=verification-state&"+tc.query, "status-filter", nil, 200)
		if page["total"] != float64(tc.total) || len(page["items"].([]any)) != tc.items {
			t.Fatalf("filter %s: %v", tc.query, page)
		}
		for _, item := range page["items"].([]any) {
			assertLegacyMetadataUser(t, item.(map[string]any))
		}
	}
	for _, field := range []struct{ name, match, miss string }{
		{"display_id", personal["display_id"].(string), plain["display_id"].(string)},
		{"username", "state-personal", "state-none"}, {"display_name", "Personal Alpha", "missing"},
		{"email", "verified@example.test", "missing"}, {"phone", "13800012345", "999999"},
		{"remark", "Alpha", "missing"}, {"qq", "00123", "999"}, {"status", "active", "disabled"},
		{"role", "tenant_viewer", "tenant_owner"},
		{"group_id", group["id"].(string), uuid.NewString()},
	} {
		for _, match := range []bool{true, false} {
			value := field.miss
			want := float64(0)
			if match {
				value = field.match
				want = 1
			}
			query := url.Values{"include": {"user_metadata,user_verification"}, "username": {"state-personal"}, "real_name_status": {"verified"}}
			query.Set(field.name, value)
			page := f.request(t, http.MethodGet, "/v1/admin/users?"+query.Encode(), "and-filter", nil, 200)
			if page["total"] != want {
				t.Fatalf("AND %s=%s: %v", field.name, value, page)
			}
		}
	}

	// An approved review's expires_at is its former review deadline, not an identity expiry.
	v.now = v.now.Add(2 * time.Hour)
	assertVerificationProjection(t, f, personal, true, false)
	assertVerificationProjection(t, f, company, true, true)
	latest := v.draft(t, pa, kyc.KindPersonalReverification, "personal-new", 0x31, 0)
	assertVerificationProjection(t, f, personal, false, false)
	latest = v.submit(t, pa, latest, "personal-new")
	assertVerificationProjection(t, f, personal, false, false)
	v.decide(t, pa, pr, latest, "personal-new", kyc.DecisionReject)
	assertVerificationProjection(t, f, personal, false, false)
	latest = v.submit(t, pa, v.draft(t, pa, kyc.KindPersonalReverification, "personal-expire", 0x31, 0), "personal-expire")
	v.now = v.now.Add(2 * time.Hour)
	if _, err := v.core.Expire(t.Context(), pa, projectionMutation(latest, "personal-expire-now")); err != nil {
		t.Fatal(err)
	}
	assertVerificationProjection(t, f, personal, false, false)
	v.decide(t, pa, pr, v.draft(t, pa, kyc.KindPersonalReverification, "personal-restored", 0x31, 0), "personal-restored", kyc.DecisionApprove)
	assertVerificationProjection(t, f, personal, true, false)
	companyPersonal := v.draft(t, ca, kyc.KindPersonalReverification, "company-personal-new", 0x32, 0)
	assertVerificationProjection(t, f, company, false, true)
	page = f.request(t, http.MethodGet, "/v1/admin/users?real_name_status=verified&display_id="+company["display_id"].(string), "company-only-verified", nil, 200)
	if page["total"] != float64(1) {
		t.Fatalf("company-only verified filter: %v", page)
	}
	if _, err := v.core.Withdraw(t.Context(), ca, projectionMutation(companyPersonal, "company-personal-withdraw")); err != nil {
		t.Fatal(err)
	}
	assertVerificationProjection(t, f, company, false, true)
	companyLatest := v.draft(t, ca, kyc.KindEnterprise, "company-latest", 0x42, 0x32)
	assertVerificationProjection(t, f, company, false, false)
	if _, err := v.core.Withdraw(t.Context(), ca, projectionMutation(companyLatest, "company-withdraw")); err != nil {
		t.Fatal(err)
	}
	assertVerificationProjection(t, f, company, false, false)

	// A failed facts query must remain an API error, never an all-unverified success.
	if _, err := f.pool.Exec(t.Context(), `ALTER TABLE identity_verified_persons RENAME TO verification_projection_unavailable`); err != nil {
		t.Fatal(err)
	}
	f.request(t, http.MethodGet, "/v1/admin/users?include=user_verification", "facts-unavailable", nil, 500)
	if _, err := f.pool.Exec(t.Context(), `ALTER TABLE verification_projection_unavailable RENAME TO identity_verified_persons`); err != nil {
		t.Fatal(err)
	}
	assertVerificationProjection(t, f, personal, true, false)
	// The same user ID in another tenant must not inherit its original tenant's identity facts.
	if _, err := f.pool.Exec(t.Context(), `INSERT INTO memberships(scope_id,user_id) VALUES($1,$2)`, plain["scope_id"], personal["id"]); err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Exec(t.Context(), `INSERT INTO role_assignments(scope_id,user_id,role_id)
		SELECT $1,$2,id FROM roles WHERE scope_id=$1 AND name='tenant_viewer'`, plain["scope_id"], personal["id"]); err != nil {
		t.Fatal(err)
	}
	page = f.request(t, http.MethodGet, "/v1/admin/users?include=user_verification&display_id="+personal["display_id"].(string), "tenant-isolation", nil, 200)
	if page["total"] != float64(2) || len(page["items"].([]any)) != 2 {
		t.Fatalf("tenant isolation page: %v", page)
	}
	for _, value := range page["items"].([]any) {
		item := value.(map[string]any)
		if !reflect.DeepEqual(item["verification"], map[string]any{"personal_verified": item["scope_id"] == personal["scope_id"], "company_verified": false}) {
			t.Fatalf("cross-tenant identity leak: %v", item)
		}
	}
}
