package httpapi

import (
	"bytes"
	"errors"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/nodeporttransition"
	"github.com/cdnca/cdnca/services/control-api/migrations"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/protobuf/proto"
)

func TestNodePortTransitionRuntimeHTTP(t *testing.T) {
	pool := isolatedTestPool(t)
	embedded, err := fs.Glob(migrations.FS, "*.up.sql")
	if err != nil || len(embedded) == 0 {
		t.Fatalf("embedded migration files = %d, err=%v", len(embedded), err)
	}
	var migrationCount, migrationHead int
	if err := pool.QueryRow(t.Context(), `SELECT count(*),max(version) FROM schema_migrations`).Scan(&migrationCount, &migrationHead); err != nil || migrationCount != len(embedded) || migrationHead != len(embedded) {
		t.Fatalf("full migration chain = %d/%d, want %d, err=%v", migrationCount, migrationHead, len(embedded), err)
	}
	passwordHash, err := identity.HashPassword(testPassword)
	if err != nil {
		t.Fatal(err)
	}
	store := identity.NewStore(pool)
	owner, err := store.BootstrapPlatformUser(t.Context(), "portadmin", "Port Admin", passwordHash, "port-runtime-test")
	if err != nil {
		t.Fatal(err)
	}
	insertTestUser(t, pool, owner.ScopeID, "portviewer", "Port Viewer", passwordHash, "active")
	tokens, err := identity.NewTokenManager("node-port-runtime-at-least-thirty-two-bytes", 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	identityService, err := identity.NewService(store, tokens, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	var clock atomic.Int64
	clock.Store(now.UnixNano())
	start := func(t *testing.T, ready func() error) *httptest.Server {
		t.Helper()
		server := httptest.NewServer(New(pool, identityService, Config{
			APIKeyPepper: bytes.Repeat([]byte{0x52}, 32), Now: func() time.Time { return time.Unix(0, clock.Load()).UTC() },
			NodePortTransitionReady: ready,
		}).Handler())
		t.Cleanup(server.Close)
		return server
	}
	authServer := start(t, nil)
	admin, _ := loginOK(t, authServer.Client(), authServer.URL, "portadmin")
	viewer, _ := loginOK(t, authServer.Client(), authServer.URL, "portviewer")
	nodeID := seedNodePortRuntimeCertificate(t, pool, owner.ScopeID, owner.UserID, now)
	actionNodeID, transitionID := uuid.New(), uuid.New()
	insertPresenceNode(t, pool, owner.ScopeID, owner.UserID, actionNodeID, 2, "port-action", now)
	seedNodePortRuntimeTransition(t, pool, owner.ScopeID, owner.UserID, actionNodeID, transitionID, now)
	body := nodePortTransitionCreateBody{
		ExpectedNodeRevision:  1,
		OldEndpoint:           nodeporttransition.Endpoint{Address: "gateway.example.com:7443", ServerName: "gateway.example.com", ListenAddress: "0.0.0.0:7443"},
		NewEndpoint:           nodeporttransition.Endpoint{Address: "gateway.example.com:8443", ServerName: "gateway.example.com", ListenAddress: "0.0.0.0:8443"},
		CompatibilityDeadline: now.Add(time.Hour).Format(time.RFC3339), RollbackDeadline: now.Add(2 * time.Hour).Format(time.RFC3339),
	}
	createPath := "/v1/nodes/" + nodeID.String() + "/gateway-port-transitions"
	detailPath := "/v1/nodes/" + actionNodeID.String() + "/gateway-port-transitions/" + transitionID.String()
	writes := []string{createPath, detailPath + "/finalize", detailPath + "/rollback"}
	counts := func(t *testing.T) [2]int {
		t.Helper()
		var result [2]int
		if err := pool.QueryRow(t.Context(), `SELECT (SELECT count(*) FROM node_gateway_port_transitions), (SELECT count(*) FROM node_gateway_port_transition_command_outbox)`).Scan(&result[0], &result[1]); err != nil {
			t.Fatal(err)
		}
		return result
	}
	var available atomic.Bool
	var calls atomic.Int64
	ready := func() error {
		calls.Add(1)
		if !available.Load() {
			return errors.New("private dependency address and credentials must not leak")
		}
		return nil
	}

	for _, mode := range []string{"missing callback", "disabled", "runtime failure"} {
		t.Run(mode, func(t *testing.T) {
			callback := ready
			if mode == "missing callback" {
				callback = nil
			}
			available.Store(mode == "runtime failure")
			server := start(t, callback)
			available.Store(false)
			before, callsBefore := counts(t), calls.Load()
			for _, path := range writes {
				t.Run(path, func(t *testing.T) {
					requestID := uuid.NewString()
					response := nodeWriteRequest(t, server.Client(), http.MethodPost, server.URL+path, body, admin.AccessToken, requestID, "", requestID)
					defer response.Body.Close()
					content := readBody(response.Body)
					if response.StatusCode != http.StatusServiceUnavailable || !strings.Contains(content, `"code":"node_port_transition_runtime_unavailable"`) || !strings.Contains(content, requestID) || strings.Contains(content, "private dependency") {
						t.Fatalf("unavailable response=%d %s", response.StatusCode, content)
					}
				})
			}
			if after := counts(t); after != before {
				t.Errorf("unavailable runtime wrote transitions/outbox: before=%v after=%v", before, after)
			}
			if callback != nil && calls.Load()-callsBefore != int64(len(writes)) {
				t.Errorf("readiness calls=%d, want %d", calls.Load()-callsBefore, len(writes))
			}
		})
	}

	t.Run("permission precedes runtime", func(t *testing.T) {
		server := start(t, ready)
		before, callsBefore := counts(t), calls.Load()
		for _, auth := range []struct {
			token, code string
			status      int
		}{
			{"", "invalid_session", http.StatusUnauthorized}, {viewer.AccessToken, "permission_denied", http.StatusForbidden},
		} {
			for _, path := range writes {
				requestID := uuid.NewString()
				response := nodeWriteRequest(t, server.Client(), http.MethodPost, server.URL+path, body, auth.token, requestID, "", requestID)
				assertError(t, response, auth.status, auth.code, requestID)
				response.Body.Close()
			}
		}
		if calls.Load() != callsBefore || counts(t) != before {
			t.Fatal("permission denial reached runtime or wrote domain data")
		}
	})

	t.Run("unavailable runtime retains scoped reads", func(t *testing.T) {
		server := start(t, ready)
		callsBefore := calls.Load()
		response := doRequest(t, server.Client(), http.MethodGet, server.URL+detailPath, nil, nil, admin.AccessToken)
		var detail map[string]any
		decodeResponse(t, response, http.StatusOK, &detail)
		response.Body.Close()
		if detail["id"] != transitionID.String() || detail["state"] != "switched" {
			t.Fatalf("persisted transition=%v", detail)
		}
		otherScope, tenantID, otherNode, otherTransition := uuid.New(), uuid.New(), uuid.New(), uuid.New()
		if _, err := pool.Exec(t.Context(), `INSERT INTO tenants(id,display_name) VALUES($1,'Other')`, tenantID); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(t.Context(), `INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'tenant',$2)`, otherScope, tenantID); err != nil {
			t.Fatal(err)
		}
		insertPresenceNode(t, pool, otherScope, owner.UserID, otherNode, 1, "other-port", now)
		seedNodePortRuntimeTransition(t, pool, otherScope, owner.UserID, otherNode, otherTransition, now)
		for _, path := range []string{
			strings.Replace(detailPath, actionNodeID.String(), nodeID.String(), 1),
			"/v1/nodes/" + otherNode.String() + "/gateway-port-transitions/" + otherTransition.String(),
		} {
			response := doRequest(t, server.Client(), http.MethodGet, server.URL+path, nil, nil, admin.AccessToken)
			assertError(t, response, http.StatusNotFound, "node_port_transition_not_found", "")
			response.Body.Close()
		}
		if calls.Load() != callsBefore {
			t.Fatal("read route invoked runtime readiness")
		}
	})

	var createRequestID string
	var createdDetail map[string]any
	t.Run("recovery accepts canonical writes and replay", func(t *testing.T) {
		server := start(t, ready)
		before, callsBefore := counts(t), calls.Load()
		available.Store(true)
		for index, path := range writes {
			requestID := uuid.NewString()
			status := http.StatusAccepted
			if index == 0 {
				status = http.StatusCreated
				createRequestID = requestID
			}
			for replay := 0; replay < 2; replay++ {
				response := nodeWriteRequest(t, server.Client(), http.MethodPost, server.URL+path, body, admin.AccessToken, requestID, "", requestID)
				var detail map[string]any
				decodeResponse(t, response, status, &detail)
				response.Body.Close()
				if index == 0 && detail["state"] != "preparing" || index > 0 && detail["id"] != transitionID.String() {
					t.Fatalf("canonical response=%v", detail)
				}
				if index == 0 {
					createdDetail = detail
				}
			}
			var storedRequestID, storedKey string
			action := []string{"switch", "finalize", "rollback"}[index]
			if err := pool.QueryRow(t.Context(), `SELECT request_id,idempotency_key FROM node_gateway_port_transition_command_outbox WHERE action=$1 AND request_id=$2`, action, requestID).Scan(&storedRequestID, &storedKey); err != nil || storedRequestID != requestID || storedKey != requestID {
				t.Fatalf("canonical outbox identity=%s/%s err=%v", storedRequestID, storedKey, err)
			}
			if index == 0 {
				var certificateSHA string
				var payload []byte
				if err := pool.QueryRow(t.Context(), `SELECT t.certificate_sha256,o.payload
					FROM node_gateway_port_transitions t JOIN node_gateway_port_transition_command_outbox o ON o.transition_id=t.id
					WHERE t.request_id=$1 AND o.action='switch'`, requestID).Scan(&certificateSHA, &payload); err != nil {
					t.Fatal(err)
				}
				var command agentv1.GatewayPortTransitionCommand
				if err := proto.Unmarshal(payload, &command); err != nil {
					t.Fatal(err)
				}
				if certificateSHA != strings.Repeat("d", 64) || command.CertificateSha256 != certificateSHA {
					t.Errorf("HTTP creation must bind stored DER identity to outbox: transition=%s command=%s", certificateSHA, command.CertificateSha256)
				}
			}
		}
		if after := counts(t); after != [2]int{before[0] + 1, before[1] + 3} {
			t.Errorf("canonical writes/replays=%v -> %v", before, after)
		}
		available.Store(false)
		response := nodeWriteRequest(t, server.Client(), http.MethodPost, server.URL+writes[1], nil, admin.AccessToken, uuid.NewString(), "", uuid.NewString())
		assertError(t, response, http.StatusServiceUnavailable, "node_port_transition_runtime_unavailable", "")
		response.Body.Close()
		if calls.Load()-callsBefore != 7 {
			t.Errorf("readiness was cached: calls=%d", calls.Load()-callsBefore)
		}
	})

	t.Run("expired create replay preserves result and admission checks", func(t *testing.T) {
		if createRequestID == "" || createdDetail == nil {
			t.Fatal("accepted create receipt is required")
		}
		server := start(t, ready)
		before := counts(t)
		available.Store(true)
		t.Cleanup(func() { clock.Store(now.UnixNano()) })
		location := createPath + "/" + createdDetail["id"].(string)
		t.Run("new key conflicts with active operation", func(t *testing.T) {
			requestID := uuid.NewString()
			response := nodeWriteRequest(t, server.Client(), http.MethodPost, server.URL+createPath, body, admin.AccessToken, requestID, "", requestID)
			assertError(t, response, http.StatusConflict, "node_port_transition_conflict", requestID)
			response.Body.Close()
		})
		for _, test := range []struct {
			name string
			at   time.Time
		}{
			{"last minute", now.Add(59*time.Minute + time.Nanosecond)},
			{"compatibility deadline", now.Add(time.Hour)},
			{"after rollback deadline", now.Add(2*time.Hour + time.Second)},
		} {
			t.Run(test.name, func(t *testing.T) {
				clock.Store(test.at.UnixNano())
				response := nodeWriteRequest(t, server.Client(), http.MethodPost, server.URL+createPath, body, admin.AccessToken, createRequestID, "", createRequestID)
				var detail map[string]any
				decodeResponse(t, response, http.StatusCreated, &detail)
				response.Body.Close()
				if response.Header.Get("Location") != location || !reflect.DeepEqual(detail, createdDetail) {
					t.Fatalf("replay changed persisted result: location=%s detail=%v", response.Header.Get("Location"), detail)
				}
			})
		}
		changed := body
		changed.NewEndpoint.Address = "gateway.example.com:9443"
		changed.NewEndpoint.ListenAddress = "0.0.0.0:9443"
		response := nodeWriteRequest(t, server.Client(), http.MethodPost, server.URL+createPath, changed, admin.AccessToken, createRequestID, "", createRequestID)
		assertError(t, response, http.StatusConflict, "node_port_transition_conflict", createRequestID)
		response.Body.Close()
		newRequestID := uuid.NewString()
		response = nodeWriteRequest(t, server.Client(), http.MethodPost, server.URL+createPath, body, admin.AccessToken, newRequestID, "", newRequestID)
		assertError(t, response, http.StatusBadRequest, "node_port_transition_invalid", newRequestID)
		response.Body.Close()

		available.Store(false)
		callsBefore := calls.Load()
		for _, auth := range []struct {
			token, code string
			status      int
		}{
			{"", "invalid_session", http.StatusUnauthorized}, {viewer.AccessToken, "permission_denied", http.StatusForbidden},
		} {
			response := nodeWriteRequest(t, server.Client(), http.MethodPost, server.URL+createPath, body, auth.token, createRequestID, "", createRequestID)
			assertError(t, response, auth.status, auth.code, createRequestID)
			response.Body.Close()
		}
		if calls.Load() != callsBefore {
			t.Fatal("expired replay bypassed current permission checks")
		}
		response = nodeWriteRequest(t, server.Client(), http.MethodPost, server.URL+createPath, body, admin.AccessToken, createRequestID, "", createRequestID)
		assertError(t, response, http.StatusServiceUnavailable, "node_port_transition_runtime_unavailable", createRequestID)
		response.Body.Close()
		response = doRequest(t, server.Client(), http.MethodGet, server.URL+location, nil, nil, admin.AccessToken)
		var detail map[string]any
		decodeResponse(t, response, http.StatusOK, &detail)
		response.Body.Close()
		if !reflect.DeepEqual(detail, createdDetail) || counts(t) != before {
			t.Fatal("expired replay changed stored transition/outbox or lost scoped reads")
		}
	})
}

func seedNodePortRuntimeTransition(t *testing.T, pool *pgxpool.Pool, scope, user, node, id uuid.UUID, now time.Time) {
	t.Helper()
	if _, err := pool.Exec(t.Context(), `INSERT INTO node_gateway_port_transitions(id,scope_id,node_id,revision,expected_node_revision,old_endpoint,new_endpoint,server_name,old_listen_address,new_listen_address,compatibility_deadline,rollback_deadline,certificate_sha256,state,status_revision,active_endpoint,request_id,idempotency_key,request_sha256,created_by_user_id,created_at,updated_at)
		VALUES($1,$2,$3,1,1,'gateway.example.com:7443','gateway.example.com:8443','gateway.example.com','0.0.0.0:7443','0.0.0.0:8443',$4,$5,repeat('a',64),'switched',1,'gateway.example.com:8443',$6,$6,decode(repeat('a',64),'hex'),$7,$8,$8)`, id, scope, node, now.Add(time.Hour), now.Add(2*time.Hour), uuid.NewString(), user, now); err != nil {
		t.Fatal(err)
	}
}

func seedNodePortRuntimeCertificate(t *testing.T, pool *pgxpool.Pool, scope, user uuid.UUID, now time.Time) uuid.UUID {
	t.Helper()
	node, token, authorization, epoch := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	insertPresenceNode(t, pool, scope, user, node, 1, "port-create", now)
	statements := []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO control_installation_entitlement(installation_id) VALUES('port-runtime-test')`, nil},
		{`INSERT INTO node_ca_key_epochs(id,installation_id,epoch,key_id,ca_certificate_pem,ca_certificate_sha256,public_key_sha256,not_before,not_after,status,request_id,request_digest,created_by_scope_id,created_by_user_id,created_at)
		 VALUES($1,'port-runtime-test',1,'port-test','test',decode(repeat('a',64),'hex'),decode(repeat('b',64),'hex'),$2,$3,'active',$4,decode(repeat('c',64),'hex'),$5,$6,$2)`, []any{epoch, now, now.Add(24 * time.Hour), uuid.New(), scope, user}},
		{`INSERT INTO node_enrollment_tokens(id,node_id,purpose,token_hash,created_by_user_id,created_at,expires_at)
		 VALUES($1,$2,'initial_enrollment',decode(repeat('d',64),'hex'),$3,$4,$5)`, []any{token, node, user, now, now.Add(time.Hour)}},
		{`INSERT INTO node_enrollment_authorizations(id,token_id,node_id,purpose,request_id,request_digest,authorized_at)
		 VALUES($1,$2,$3,'initial_enrollment',$5,decode(repeat('e',64),'hex'),$4)`, []any{authorization, token, node, now, authorization.String()}},
		{`INSERT INTO node_identity_authorizations(id,token_id,node_id,purpose,request_id,request_digest,token_hash,csr_der,csr_sha256,machine_fingerprint_sha256,protocol_min_major,protocol_min_minor,protocol_max_major,protocol_max_minor,selected_protocol_major,selected_protocol_minor,capabilities_snapshot,capabilities_sha256,gateway_workload_identity,gateway_instance_id,artifact_key_id,artifact_public_key,status,authorized_at,expires_at)
		 VALUES($1,$2,$3,'initial_enrollment',$1,decode(repeat('e',64),'hex'),decode(repeat('d',64),'hex'),'test',decode(repeat('a',64),'hex'),decode(repeat('a',64),'hex'),1,0,1,0,1,0,'{}',decode(repeat('a',64),'hex'),'spiffe://cdn-platform/gateway/test','test','x25519:test',decode(repeat('a',64),'hex'),'authorized',$4,$5)`, []any{authorization, token, node, now, now.Add(time.Hour)}},
		{`INSERT INTO node_certificates(id,node_id,issuance_kind,enrollment_authorization_id,serial_number,csr_sha256,certificate_public_key_sha256,uri_san,not_before,not_after,renewal_at,leaf_certificate_pem,issuing_chain_pem,leaf_certificate_sha256,status,issued_at,owner_scope_id,installation_id,ca_epoch_id,leaf_der_sha256,rotation_status,lifecycle_revision,lifecycle_request_id,lifecycle_request_digest,lifecycle_bound_at)
		 VALUES($1,$2,'initial',$3,'abc',decode(repeat('a',64),'hex'),decode(repeat('b',64),'hex'),$4,$5,$6,$7,'test',ARRAY['test'::bytea],decode(repeat('c',64),'hex'),'active',$5,$8,'port-runtime-test',$9,decode(repeat('d',64),'hex'),'current',1,$10,decode(repeat('e',64),'hex'),$5)`, []any{uuid.New(), node, authorization, "spiffe://cdn-platform/node/" + node.String(), now, now.Add(24 * time.Hour), now.Add(12 * time.Hour), scope, epoch, uuid.New()}},
	}
	for _, statement := range statements {
		if _, err := pool.Exec(t.Context(), statement.sql, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	return node
}
