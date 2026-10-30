//go:build integration

package securityrulereport

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/entitlement/rulecatalog"
	"github.com/cdnca/cdnca/services/control-api/internal/database"
	"github.com/cdnca/cdnca/services/control-api/internal/securitypolicy"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type fakePolicies map[string][]securitypolicy.CustomPolicyReportItem

func (fake fakePolicies) ListCustomPoliciesForReport(_ context.Context, kind string) ([]securitypolicy.CustomPolicyReportItem, error) {
	return fake[kind], nil
}

func reportTestPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}
	ctx := t.Context()
	admin, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	schema := "custom_rule_report_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+pgx.Identifier{schema}.Sanitize()); err != nil {
		t.Fatal(err)
	}
	config, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	config.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		pool.Close()
		_, _ = admin.Exec(context.Background(), "DROP SCHEMA "+pgx.Identifier{schema}.Sanitize()+" CASCADE")
		admin.Close()
	})
	if err := database.Migrate(ctx, pool, "up"); err != nil {
		t.Fatal(err)
	}
	return pool
}

func TestCustomRuleReportCollectsTenantRulesHashesOwnersAndUploads(t *testing.T) {
	pool := reportTestPool(t)
	ctx := t.Context()
	tenantID, scopeID, userID := uuid.New(), uuid.New(), uuid.New()
	for _, statement := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO tenants(id,display_name) VALUES($1,'客户甲')`, []any{tenantID}},
		{`INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'tenant',$2)`, []any{scopeID, tenantID}},
		{`INSERT INTO users(id,username,display_name,password_hash) VALUES($1,'zhangsan','张三','x')`, []any{userID}},
		{`INSERT INTO memberships(scope_id,user_id) VALUES($1,$2)`, []any{scopeID, userID}},
		{`INSERT INTO cc_reference_matchers(id,scope_id,tenant_id,owner_user_id,name,field,operator,values,created_by_user_id,
			updated_by_user_id,created_at,updated_at) VALUES($1,$2,$3,$4,'登录页','path','prefix','["/login"]',$4,$4,now(),now())`,
			[]any{uuid.New(), scopeID, tenantID, userID}},
		{`INSERT INTO cc_reference_matchers(id,scope_id,tenant_id,owner_user_id,name,field,operator,values,created_by_user_id,
			updated_by_user_id,created_at,updated_at,system_rule,system_rule_id,system_rule_sort,system_rule_key)
			VALUES($1,$2,$3,$4,'系统匹配器','path','prefix','[]',$4,$4,now(),now(),true,'3',1,'cc.matcher.3')`,
			[]any{uuid.New(), scopeID, tenantID, userID}},
		{`INSERT INTO cc_reference_filters(id,scope_id,tenant_id,owner_user_id,name,filter_type,parameters,created_by_user_id,
			updated_by_user_id,created_at,updated_at) VALUES($1,$2,$3,$4,'限速','req_rate','{"within_second":10,"max_req":30}',$4,$4,now(),now())`,
			[]any{uuid.New(), scopeID, tenantID, userID}},
	} {
		if _, err := pool.Exec(ctx, statement.sql, statement.args...); err != nil {
			t.Fatalf("%s: %v", statement.sql, err)
		}
	}
	installationID := uuid.New()
	policies := fakePolicies{securitypolicy.KindCC: {{ID: uuid.New(), ScopeID: scopeID, OwnerID: userID, Name: "登录限速",
		Enabled: true, DefaultAction: "allow", Rules: []securitypolicy.Rule{}, Version: 3}}}
	collector := NewCollector(pool, policies)
	report, digest, err := collector.Collect(ctx, installationID)
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(report)
	if len(report.CCMatchers) != 1 || len(report.CCFilters) != 1 || len(report.CCRuleGroups) != 1 || len(report.WAFPolicies) != 0 ||
		strings.Contains(string(encoded), "系统匹配器") || strings.Contains(string(encoded), "张三") || strings.Contains(string(encoded), "zhangsan") ||
		!strings.Contains(string(encoded), rulecatalog.OwnerHash(installationID.String(), userID.String())) {
		t.Fatalf("collected report = %s", encoded)
	}

	_, private, _ := ed25519.GenerateKey(rand.Reader)
	public := private.Public().(ed25519.PublicKey)
	var received rulecatalog.ReportRequest
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		body, _ := io.ReadAll(request.Body)
		if request.URL.Path != rulecatalog.ReportPath || json.Unmarshal(body, &received) != nil {
			http.Error(response, `{"code":"invalid_request"}`, http.StatusBadRequest)
			return
		}
		_, gotDigest, err := rulecatalog.CanonicalReport(received.Report)
		signature, _ := base64.RawURLEncoding.DecodeString(received.Signature)
		if err != nil || !ed25519.Verify(public, rulecatalog.ReportProofMessage(received, gotDigest), signature) {
			http.Error(response, `{"code":"invalid_proof"}`, http.StatusUnauthorized)
			return
		}
		response.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(response).Encode(map[string]any{"schema": received.Schema, "installation_id": received.InstallationID,
			"sequence": received.Sequence, "request_id": received.RequestID, "signature": received.Signature,
			"report_digest": hex.EncodeToString(gotDigest[:])})
	}))
	defer server.Close()
	client, err := NewClient(server.URL, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_900_000_000, 0).UTC()
	store := NewStore(pool, func() time.Time { return now })
	reporter, err := NewReporter(Config{Collector: collector, Store: store, Client: client, InstallationID: installationID, PrivateKey: private})
	if err != nil {
		t.Fatal(err)
	}
	if err := reporter.ReportOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if received.Sequence != uint64(now.Unix()) || received.InstallationID != installationID.String() {
		t.Fatalf("first upload = %d %s", received.Sequence, received.InstallationID)
	}
	first := received
	received = rulecatalog.ReportRequest{}
	if err := reporter.ReportOnce(ctx); err != nil || received.RequestID != "" {
		t.Fatalf("unchanged report re-sent: %v %q", err, received.RequestID)
	}
	snapshot, send, err := store.Prepare(ctx, installationID, report, digest)
	if err != nil || send || snapshot.RequestID != first.RequestID {
		t.Fatalf("stored snapshot = %+v %v %v", snapshot.RequestID, send, err)
	}
	if _, err := pool.Exec(ctx, `UPDATE cc_reference_filters SET name='限速2',revision=2`); err != nil {
		t.Fatal(err)
	}
	if err := reporter.ReportOnce(ctx); err != nil || received.Sequence != first.Sequence+1 || received.RequestID == first.RequestID {
		t.Fatalf("changed report upload = %d, %v", received.Sequence, err)
	}
}
