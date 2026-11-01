package httpapi

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/google/uuid"
)

// A3-04 (site-audit 11-01): a stream whose automatic publication failed
// showed only "发布失败". The request's terminal code (written with the
// failed state) is the publish intent's failure_code on GET and list, and is
// null while the request has not failed.
func TestL4StreamPublishIntentFailureCodeHTTPFlow(t *testing.T) {
	pool := isolatedTestPool(t)
	passwordHash, err := identity.HashPassword(testPassword)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := identity.NewStore(pool).BootstrapPlatformUser(t.Context(), "failure-admin", "Failure Admin", passwordHash, "bootstrap-failure-admin"); err != nil {
		t.Fatal(err)
	}
	tenant := insertL4Tenant(t, pool, "Failure Tenant", "failure-owner", passwordHash, []string{"streams.read", "streams.manage"})
	tokens, err := identity.NewTokenManager("l4-failure-code-integration-test-secret-32-bytes", 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	identityService, err := identity.NewService(identity.NewStore(pool), tokens, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(New(pool, identityService, Config{CookieSecure: false, APIKeyPepper: bytes.Repeat([]byte{0x5a}, 32)}).Handler())
	t.Cleanup(server.Close)
	client := server.Client()
	ownerAuth, _ := loginOK(t, client, server.URL, "failure-owner")
	adminAuth, _ := loginOK(t, client, server.URL, "failure-admin")
	installL4AutomaticPolicy(t, pool, tenant)
	stream := createL4Forward(t, client, server.URL, ownerAuth.AccessToken, "failure-code-create", createStreamRequest{
		Fields: validStreamFields(tenant, "TCP failure", "tcp", 18400, "192.0.2.30"),
	})
	if stream.PublishIntent.FailureCode != nil {
		t.Fatalf("pending stream failure_code = %q", *stream.PublishIntent.FailureCode)
	}
	var requestID uuid.UUID
	if err := pool.QueryRow(t.Context(), `SELECT id FROM edge_automatic_publication_requests WHERE publish_intent_id=$1`,
		stream.PublishIntent.ID).Scan(&requestID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO edge_automatic_publication_request_state_facts
		(request_id,sequence,state,attempt,lease_owner,lease_token,lease_expires_at,occurred_at)
		VALUES($1,2,'leased',1,'failure-test',$2,clock_timestamp()+interval '1 minute',clock_timestamp())`, requestID, uuid.New()); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO edge_automatic_publication_request_state_facts
		(request_id,sequence,state,attempt,available_at,error_class,occurred_at)
		VALUES($1,3,'retry_wait',1,clock_timestamp()+interval '1 minute','publish_outcome_unknown',clock_timestamp())`, requestID); err != nil {
		t.Fatal(err)
	}
	// retry_wait carries an error class, not a terminal code.
	if got := getL4Forward(t, client, server.URL, stream.ID, ownerAuth.AccessToken); got.PublishIntent.State != "retrying" ||
		got.PublishIntent.FailureCode != nil {
		t.Fatalf("retrying intent = %+v", got.PublishIntent)
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO edge_automatic_publication_request_state_facts
		(request_id,sequence,state,attempt,lease_owner,lease_token,lease_expires_at,occurred_at)
		VALUES($1,4,'leased',2,'failure-test',$2,clock_timestamp()+interval '1 minute',clock_timestamp())`, requestID, uuid.New()); err != nil {
		t.Fatal(err)
	}
	// What edgeautopublish.FailAutomaticPublication appends when the target
	// nodes have not loaded the IP library a geo guard rule needs.
	if _, err := pool.Exec(t.Context(), `INSERT INTO edge_automatic_publication_request_state_facts
		(request_id,sequence,state,attempt,terminal_code,occurred_at)
		VALUES($1,5,'failed',2,'node_artifacts_syncing',clock_timestamp())`, requestID); err != nil {
		t.Fatal(err)
	}
	for _, token := range []string{ownerAuth.AccessToken, adminAuth.AccessToken} {
		got := getL4Forward(t, client, server.URL, stream.ID, token)
		if got.PublishIntent.State != "failed" || got.PublishIntent.FailureCode == nil ||
			*got.PublishIntent.FailureCode != "node_artifacts_syncing" || got.SyncState != "failed" {
			t.Fatalf("failed intent = %+v sync=%s", got.PublishIntent, got.SyncState)
		}
		list := listL4Forwards(t, client, server.URL+"/v1/streams?publication_state=failed", token)
		if list.Total != 1 || len(list.Items) != 1 || list.Items[0].PublishIntent.FailureCode == nil ||
			*list.Items[0].PublishIntent.FailureCode != "node_artifacts_syncing" {
			t.Fatalf("failed list = %+v", list)
		}
	}
	// The wire field is present (null) for every intent, as OpenAPI requires.
	response := l4Request(t, client, http.MethodGet, server.URL+"/v1/streams/"+stream.ID.String(), nil, ownerAuth.AccessToken, "", "")
	raw, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil || response.StatusCode != http.StatusOK {
		t.Fatalf("GET stream = %d %v", response.StatusCode, err)
	}
	var body struct {
		PublishIntent map[string]json.RawMessage `json:"publish_intent"`
	}
	if err := json.Unmarshal(raw, &body); err != nil {
		t.Fatal(err)
	}
	if string(body.PublishIntent["failure_code"]) != `"node_artifacts_syncing"` {
		t.Fatalf("publish_intent.failure_code = %s", body.PublishIntent["failure_code"])
	}
}
