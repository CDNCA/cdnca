package httpapi

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	nodedomain "github.com/cdnca/cdnca/services/control-api/internal/node"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type registrationTestEnv struct {
	pool        *pgxpool.Pool
	url         string
	client      *http.Client
	scopeID     uuid.UUID
	adminID     uuid.UUID
	admin       string
	reader      string
	now         time.Time
	newServerAt func() string
	nextWindow  func()
}

func newRegistrationTestEnv(t *testing.T) registrationTestEnv {
	t.Helper()
	pool := isolatedTestPool(t)
	passwordHash, err := identity.HashPassword(testPassword)
	if err != nil {
		t.Fatal(err)
	}
	identityStore := identity.NewStore(pool)
	bootstrap, err := identityStore.BootstrapPlatformUser(t.Context(), "regadmin", "Registration Admin", passwordHash, "node-registration-bootstrap")
	if err != nil {
		t.Fatal(err)
	}
	readerID := insertTestUser(t, pool, bootstrap.ScopeID, "regreader", "Registration Reader", passwordHash, "active")
	grantNodePermissions(t, pool, bootstrap.ScopeID, readerID, "nodes.read")
	tokens, err := identity.NewTokenManager("node-registration-secret-at-least-thirty-two-bytes", 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	identityService, err := identity.NewService(identityStore, tokens, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	var offset atomic.Int64
	clock := func() time.Time { return now.Add(time.Duration(offset.Load())) }
	key := newSiteTestKey(t, "node-registration-key")
	trust := newSiteTestTrust(t, key)
	installNodeTestEntitlement(t, pool, trust, now, nodeTestLeaseOptions{serial: 1, limit: 100, key: key})
	start := func() string {
		server := httptest.NewServer(New(pool, identityService, Config{
			CookieSecure: false, APIKeyPepper: bytes.Repeat([]byte{0x52}, 32),
			Now: clock, EntitlementTrust: trust,
		}).Handler())
		t.Cleanup(server.Close)
		return server.URL
	}
	url := start()
	client := http.DefaultClient
	admin, _ := loginOK(t, client, url, "regadmin")
	reader, _ := loginOK(t, client, url, "regreader")
	return registrationTestEnv{pool: pool, url: url, client: client, scopeID: bootstrap.ScopeID, adminID: admin.Principal.UserID,
		admin: admin.AccessToken, reader: reader.AccessToken, now: now, newServerAt: start,
		// Rolls the registration rate-limit window without moving token or
		// certificate timestamps by more than a second per call.
		nextWindow: func() { offset.Add(int64(registrationLimitWindow)) }}
}

func (e registrationTestEnv) credential(t *testing.T, method, path string) nodedomain.RegistrationCredential {
	t.Helper()
	response := doRequest(t, e.client, method, e.url+path, nil, nil, e.admin)
	var credential nodedomain.RegistrationCredential
	decodeResponse(t, response, http.StatusOK, &credential)
	if response.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("credential Cache-Control = %q", response.Header.Get("Cache-Control"))
	}
	return credential
}

func registrationBody(credential, fingerprint, hostname string) map[string]any {
	return map[string]any{
		"credential": credential, "machine_fingerprint": fingerprint, "hostname": hostname,
		"os_name": "Ubuntu 24.04.1 LTS", "kernel_version": "6.8.0-45-generic", "architecture": "x86_64",
	}
}

func (e registrationTestEnv) register(t *testing.T, base string, body map[string]any, status int) nodedomain.RegisterResult {
	t.Helper()
	response := doRequest(t, e.client, http.MethodPost, base+"/v1/node-registrations", body, nil, "")
	var result nodedomain.RegisterResult
	decodeResponse(t, response, status, &result)
	return result
}

func TestNodeSelfRegistrationFlow(t *testing.T) {
	env := newRegistrationTestEnv(t)
	fingerprintA, fingerprintB := strings.Repeat("a1", 32), strings.Repeat("b2", 32)

	t.Run("credential requires nodes.manage on the platform", func(t *testing.T) {
		for path, method := range map[string]string{
			"/v1/nodes/registration-credential": http.MethodGet, "/v1/nodes/registration-credential/reset": http.MethodPost,
		} {
			anonymous := doRequest(t, env.client, method, env.url+path, nil, nil, "")
			assertError(t, anonymous, http.StatusUnauthorized, "invalid_session", "")
			denied := doRequest(t, env.client, method, env.url+path, nil, nil, env.reader)
			assertError(t, denied, http.StatusForbidden, "permission_denied", "")
		}
	})

	first := env.credential(t, http.MethodGet, "/v1/nodes/registration-credential")
	if !strings.HasPrefix(first.Credential, "nrk1.") || first.KeyID == uuid.Nil {
		t.Fatalf("credential = %+v", first)
	}
	if again := env.credential(t, http.MethodGet, "/v1/nodes/registration-credential"); again != first {
		t.Fatalf("credential is not reusable: %+v != %+v", again, first)
	}
	var nodesBefore int
	if err := env.pool.QueryRow(t.Context(), `SELECT count(*) FROM nodes`).Scan(&nodesBefore); err != nil || nodesBefore != 0 {
		t.Fatalf("viewing the install command created nodes: %d, %v", nodesBefore, err)
	}
	var stored string
	if err := env.pool.QueryRow(t.Context(), `SELECT payload::text FROM audit_events WHERE action='node.registration_credential.issue'`).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(stored, first.Credential) || strings.Contains(stored, first.Credential[len(first.Credential)-43:]) {
		t.Fatalf("audit payload stores the raw credential: %s", stored)
	}

	t.Run("invalid credentials and input are rejected", func(t *testing.T) {
		forged := "nrk1." + strings.Repeat("0", 32) + "." + strings.Repeat("A", 43)
		for _, credential := range []string{"", "nrk1.bad", forged, first.Credential[:len(first.Credential)-1] + "B"} {
			response := doRequest(t, env.client, http.MethodPost, env.url+"/v1/node-registrations",
				registrationBody(credential, fingerprintA, "edge-a"), nil, "")
			want, code := http.StatusUnauthorized, "invalid_registration_credential"
			if credential == "" {
				want, code = http.StatusBadRequest, "validation_error"
			}
			assertError(t, response, want, code, "")
		}
		bad := doRequest(t, env.client, http.MethodPost, env.url+"/v1/node-registrations",
			registrationBody(first.Credential, "XYZ", "edge-a"), nil, "")
		assertError(t, bad, http.StatusBadRequest, "validation_error", "")
	})

	created := env.register(t, env.url, registrationBody(first.Credential, fingerprintA, "edge-a"), http.StatusCreated)
	if created.Node.AdminState != nodedomain.StatePending || created.Node.Name != "edge-a" || created.Reused ||
		created.Node.Description != "Ubuntu 24.04.1 LTS · 6.8.0-45-generic · x86_64" || created.Node.IPv4 != nil ||
		!nodedomain.IsSelfRegisteredNodeID(created.Node.ID) {
		t.Fatalf("registered node = %+v", created.Node)
	}
	if created.EnrollmentToken.NodeID != created.Node.ID || created.EnrollmentToken.Purpose != nodedomain.PurposeInitial ||
		len(created.EnrollmentToken.Token) != 43 || !created.EnrollmentToken.ExpiresAt.Equal(env.now.Add(nodedomain.RegistrationTokenTTL)) {
		t.Fatalf("enrollment token = %+v", created.EnrollmentToken)
	}

	t.Run("same machine re-registers without a duplicate node", func(t *testing.T) {
		again := env.register(t, env.url, registrationBody(first.Credential, fingerprintA, "renamed-host"), http.StatusOK)
		if again.Node.ID != created.Node.ID || !again.Reused || again.EnrollmentToken.Token == created.EnrollmentToken.Token {
			t.Fatalf("re-registration = %+v", again)
		}
		other := env.register(t, env.url, registrationBody(first.Credential, fingerprintB, "edge-a"), http.StatusCreated)
		if other.Node.ID == created.Node.ID || other.Node.Name != fmt.Sprintf("edge-a-%s", other.Node.DisplayID) {
			t.Fatalf("second machine = %+v", other.Node)
		}
		var count int
		if err := env.pool.QueryRow(t.Context(), `SELECT count(*) FROM nodes`).Scan(&count); err != nil || count != 2 {
			t.Fatalf("node count = %d, %v", count, err)
		}
	})

	t.Run("reset invalidates copied commands", func(t *testing.T) {
		reset := env.credential(t, http.MethodPost, "/v1/nodes/registration-credential/reset")
		if reset.KeyID == first.KeyID || reset.Credential == first.Credential {
			t.Fatalf("reset returned the old credential: %+v", reset)
		}
		stale := doRequest(t, env.client, http.MethodPost, env.url+"/v1/node-registrations",
			registrationBody(first.Credential, fingerprintA, "edge-a"), nil, "")
		assertError(t, stale, http.StatusUnauthorized, "invalid_registration_credential", "")
		if current := env.credential(t, http.MethodGet, "/v1/nodes/registration-credential"); current != reset {
			t.Fatalf("current credential = %+v, want %+v", current, reset)
		}
		again := env.register(t, env.url, registrationBody(reset.Credential, fingerprintA, "edge-a"), http.StatusOK)
		if again.Node.ID != created.Node.ID {
			t.Fatalf("dedupe broke after reset: %s != %s", again.Node.ID, created.Node.ID)
		}
		first = reset
	})

	t.Run("pending node stays out of serving until initialized", func(t *testing.T) {
		env.nextWindow()
		path := env.url + "/v1/nodes/" + created.Node.ID.String()
		early := nodeWriteRequest(t, env.client, http.MethodPatch, path, map[string]any{"admin_state": "active"},
			env.admin, "init-before-enroll", `"1"`, "init-before-enroll")
		assertError(t, early, http.StatusConflict, "node_identity_required", "")

		seedRegisteredNodeCertificate(t, env, created.Node.ID)
		var state string
		var targets int
		if err := env.pool.QueryRow(t.Context(), `SELECT admin_state FROM nodes WHERE id=$1`, created.Node.ID).Scan(&state); err != nil || state != "pending" {
			t.Fatalf("enrolled self-registered node state = %q, %v", state, err)
		}
		if err := env.pool.QueryRow(t.Context(), `SELECT count(*) FROM nodes WHERE admin_state='active'`).Scan(&targets); err != nil || targets != 0 {
			t.Fatalf("active nodes before initialization = %d, %v", targets, err)
		}
		reused := doRequest(t, env.client, http.MethodPost, env.url+"/v1/node-registrations",
			registrationBody(first.Credential, fingerprintA, "edge-a"), nil, "")
		assertError(t, reused, http.StatusConflict, "node_already_registered", "")

		initialized := nodeWriteRequest(t, env.client, http.MethodPatch, path, map[string]any{"admin_state": "active"},
			env.admin, "init-after-enroll", `"1"`, "init-after-enroll")
		var node nodedomain.Node
		decodeResponse(t, initialized, http.StatusOK, &node)
		if node.AdminState != nodedomain.StateActive {
			t.Fatalf("initialized node = %+v", node)
		}
		active := doRequest(t, env.client, http.MethodPost, env.url+"/v1/node-registrations",
			registrationBody(first.Credential, fingerprintA, "edge-a"), nil, "")
		assertError(t, active, http.StatusConflict, "node_already_registered", "")
	})

	t.Run("deleted pending node can register again as a new node", func(t *testing.T) {
		env.nextWindow()
		other := env.register(t, env.url, registrationBody(first.Credential, fingerprintB, "edge-b"), http.StatusOK)
		deleted := nodeWriteRequest(t, env.client, http.MethodPatch, env.url+"/v1/nodes/"+other.Node.ID.String(),
			map[string]any{"admin_state": "retired"}, env.admin, "delete-pending", `"1"`, "delete-pending")
		decodeResponse(t, deleted, http.StatusOK, &nodedomain.Node{})
		fresh := env.register(t, env.url, registrationBody(first.Credential, fingerprintB, "edge-b"), http.StatusCreated)
		if fresh.Node.ID == other.Node.ID || fresh.Node.AdminState != nodedomain.StatePending {
			t.Fatalf("re-registration after delete = %+v", fresh.Node)
		}
	})

	t.Run("deleting an initialized node purges it and keeps the audit record", func(t *testing.T) {
		env.nextWindow()
		fingerprintC := strings.Repeat("c3", 32)
		item := env.register(t, env.url, registrationBody(first.Credential, fingerprintC, "edge-c"), http.StatusCreated)
		seedRegisteredNodeCertificate(t, env, item.Node.ID)
		path := env.url + "/v1/nodes/" + item.Node.ID.String()
		initialized := nodeWriteRequest(t, env.client, http.MethodPatch, path, map[string]any{"admin_state": "active"},
			env.admin, "delete-init", `"1"`, "delete-init")
		var active nodedomain.Node
		decodeResponse(t, initialized, http.StatusOK, &active)
		groupID := seedLineGroupEndpoint(t, env, item.Node.ID)

		inUse := nodeWriteRequest(t, env.client, http.MethodPatch, path, map[string]any{"admin_state": "retired"},
			env.admin, "delete-in-use", quoteVersion(active.Revision), "delete-in-use")
		assertError(t, inUse, http.StatusConflict, "node_in_use", "")
		batch := nodeWriteRequest(t, env.client, http.MethodPost, env.url+"/v1/nodes/batch-admin-state", map[string]any{
			"admin_state": "retired", "items": []map[string]any{{"id": item.Node.ID, "expected_revision": active.Revision}},
		}, env.admin, "delete-in-use-batch", "", "delete-in-use-batch")
		var batchResult nodedomain.BatchAdminStateResult
		decodeResponse(t, batch, http.StatusOK, &batchResult)
		if len(batchResult.Items) != 1 || batchResult.Items[0].Error == nil || batchResult.Items[0].Error.Code != "node_in_use" {
			t.Fatalf("batch delete of referenced node = %#v", batchResult)
		}

		if _, err := env.pool.Exec(t.Context(), `UPDATE node_line_groups
			SET deleted_at=now(),deleted_by_user_id=$2,updated_by_user_id=$2,updated_at=now() WHERE id=$1`,
			groupID, env.adminID); err != nil {
			t.Fatal(err)
		}
		deleted := nodeWriteRequest(t, env.client, http.MethodPatch, path, map[string]any{"admin_state": "retired"},
			env.admin, "delete-active", quoteVersion(active.Revision), "delete-active")
		var gone nodedomain.Node
		decodeResponse(t, deleted, http.StatusOK, &gone)
		if gone.ID != item.Node.ID || gone.AdminState != nodedomain.StateRetired {
			t.Fatalf("delete response = %+v", gone)
		}
		// The node row and every node-owned row are gone.
		if left := nodeOwnedRowsLeft(t, env, item.Node.ID); left != "" {
			t.Fatalf("rows left after delete: %s", left)
		}
		// The audit event outlives the node and names what was deleted.
		var payload map[string]any
		var actor uuid.UUID
		if err := env.pool.QueryRow(t.Context(), `SELECT payload, actor_user_id FROM audit_events
			WHERE action='node.delete' AND resource_type='node' AND resource_id=$1`, item.Node.ID.String()).Scan(&payload, &actor); err != nil {
			t.Fatalf("delete audit: %v", err)
		}
		revoked, _ := payload["revoked_certificates"].([]any)
		var certificate map[string]any
		if len(revoked) == 1 {
			certificate, _ = revoked[0].(map[string]any)
		}
		if actor != env.adminID || payload["node_id"] != item.Node.ID.String() || payload["display_id"] != active.DisplayID ||
			payload["name"] != "edge-c" || payload["from_state"] != "active" || payload["deleted_by_user_id"] != env.adminID.String() ||
			payload["deleted_at"] == nil || payload["purged"] != true || certificate == nil || certificate["id"] == "" ||
			certificate["serial_number"] != registeredCertificateSerial(item.Node.ID) {
			t.Fatalf("delete audit payload = %#v actor=%s", payload, actor)
		}

		listed := getNodePage(t, env.client, env.url+"/v1/nodes?limit=100", env.admin)
		for _, listedNode := range listed.Items {
			if listedNode.ID == item.Node.ID {
				t.Fatalf("node list still includes deleted node %s", listedNode.ID)
			}
		}
		retiredFilter := doRequest(t, env.client, http.MethodGet, env.url+"/v1/nodes?status=retired&limit=100", nil, nil, env.admin)
		assertError(t, retiredFilter, http.StatusBadRequest, "validation_error", "")

		// Same machine, same host name: a new pending node under the original
		// name and a never-used node ID.
		again := env.register(t, env.url, registrationBody(first.Credential, fingerprintC, "edge-c"), http.StatusCreated)
		if again.Node.ID == item.Node.ID || again.Node.AdminState != nodedomain.StatePending || again.Reused || again.Node.Name != "edge-c" {
			t.Fatalf("re-registration after deleting an initialized node = %+v", again.Node)
		}
		var purged bool
		if err := env.pool.QueryRow(t.Context(), `SELECT EXISTS(SELECT 1 FROM node_purged_ids WHERE node_id=$1)`, item.Node.ID).Scan(&purged); err != nil || !purged {
			t.Fatalf("purged node ID recorded = %v, %v", purged, err)
		}
	})

	t.Run("batch delete reports each node and deletes the free ones", func(t *testing.T) {
		env.nextWindow()
		free := env.register(t, env.url, registrationBody(first.Credential, strings.Repeat("d4", 32), "edge-d"), http.StatusCreated)
		env.nextWindow()
		used := env.register(t, env.url, registrationBody(first.Credential, strings.Repeat("e5", 32), "edge-e"), http.StatusCreated)
		env.nextWindow()
		legacy := env.register(t, env.url, registrationBody(first.Credential, strings.Repeat("f6", 32), "edge-f"), http.StatusCreated)
		seedLineGroupEndpoint(t, env, used.Node.ID)
		// A row retired by a release before physical deletion.
		if _, err := env.pool.Exec(t.Context(), `UPDATE nodes SET admin_state='retired',revision=revision+1 WHERE id=$1`, legacy.Node.ID); err != nil {
			t.Fatal(err)
		}
		listed := getNodePage(t, env.client, env.url+"/v1/nodes?limit=100", env.admin)
		legacyListed := false
		for _, listedNode := range listed.Items {
			legacyListed = legacyListed || listedNode.ID == legacy.Node.ID
		}
		if !legacyListed {
			t.Fatal("legacy retired row is not listed, so it could never be deleted")
		}
		batch := nodeWriteRequest(t, env.client, http.MethodPost, env.url+"/v1/nodes/batch-admin-state", map[string]any{
			"admin_state": "retired", "items": []map[string]any{
				{"id": free.Node.ID, "expected_revision": free.Node.Revision},
				{"id": used.Node.ID, "expected_revision": used.Node.Revision},
				{"id": legacy.Node.ID, "expected_revision": legacy.Node.Revision + 1},
			},
		}, env.admin, "delete-batch-mixed", "", "delete-batch-mixed")
		var result nodedomain.BatchAdminStateResult
		decodeResponse(t, batch, http.StatusOK, &result)
		if len(result.Items) != 3 || result.Items[0].Status != "updated" || result.Items[0].Node == nil ||
			result.Items[1].Error == nil || result.Items[1].Error.Code != "node_in_use" || result.Items[2].Status != "updated" {
			t.Fatalf("batch delete = %#v", result)
		}
		for _, id := range []uuid.UUID{free.Node.ID, legacy.Node.ID} {
			if left := nodeOwnedRowsLeft(t, env, id); left != "" {
				t.Fatalf("rows left after batch delete of %s: %s", id, left)
			}
		}
		var remaining, audits int
		if err := env.pool.QueryRow(t.Context(), `SELECT count(*) FROM nodes WHERE id=$1`, used.Node.ID).Scan(&remaining); err != nil || remaining != 1 {
			t.Fatalf("node in use after batch = %d, %v", remaining, err)
		}
		if err := env.pool.QueryRow(t.Context(), `SELECT count(*) FROM audit_events WHERE action='node.delete' AND resource_id = ANY($1)`,
			[]string{free.Node.ID.String(), used.Node.ID.String(), legacy.Node.ID.String()}).Scan(&audits); err != nil || audits != 2 {
			t.Fatalf("batch delete audit events = %d, %v", audits, err)
		}
	})
}

// registeredCertificateSerial is the serial seedRegisteredNodeCertificate
// gives the node's certificate.
func registeredCertificateSerial(node uuid.UUID) string {
	digest := sha256.Sum256(node[:])
	return hex.EncodeToString(digest[:8])
}

// nodeOwnedRowsLeft lists the node row and every table that references nodes
// (directly or through node-owned rows) still holding a row for node.
func nodeOwnedRowsLeft(t *testing.T, env registrationTestEnv, node uuid.UUID) string {
	t.Helper()
	rows, err := env.pool.Query(t.Context(), `
		WITH RECURSIVE closure(relation) AS (
			SELECT conrelid FROM pg_constraint WHERE contype='f' AND confrelid=(current_schema()||'.nodes')::regclass
			UNION
			SELECT c.conrelid FROM pg_constraint c JOIN closure ON c.confrelid=closure.relation WHERE c.contype='f'
		)
		SELECT relation::regclass::text, attribute.attname FROM closure
		JOIN pg_attribute attribute ON attribute.attrelid=closure.relation
		WHERE attribute.attname IN ('node_id','target_node_id') AND NOT attribute.attisdropped
		UNION ALL SELECT 'nodes', 'id'`)
	if err != nil {
		t.Fatal(err)
	}
	type column struct{ table, name string }
	columns, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (column, error) {
		var item column
		return item, row.Scan(&item.table, &item.name)
	})
	if err != nil || len(columns) < 55 {
		t.Fatalf("node-owned columns = %d, %v", len(columns), err)
	}
	var left []string
	for _, item := range columns {
		var count int
		if err := env.pool.QueryRow(t.Context(), `SELECT count(*) FROM `+pgx.Identifier{item.table}.Sanitize()+
			` WHERE `+pgx.Identifier{item.name}.Sanitize()+`=$1`, node).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != 0 {
			left = append(left, fmt.Sprintf("%s=%d", item.table, count))
		}
	}
	return strings.Join(left, ",")
}

// seedLineGroupEndpoint seals revision 1 of a platform line group whose only
// endpoint points at the node.
func seedLineGroupEndpoint(t *testing.T, env registrationTestEnv, nodeID uuid.UUID) uuid.UUID {
	t.Helper()
	groupID := uuid.New()
	statements := []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO node_line_groups(id,tenant_scope_id,name,current_revision,created_by_user_id,updated_by_user_id,created_at,updated_at)
		 VALUES($1,$2,'delete-guard',1,$3,$3,now(),now())`, []any{groupID, env.scopeID, env.adminID}},
		{`INSERT INTO node_line_group_revisions(line_group_id,tenant_scope_id,revision,name,resolved_value,probe_interval_ms,
		 probe_timeout_ms,failure_threshold,recovery_threshold,failure_debounce_ms,recovery_debounce_ms,endpoint_count,
		 configuration_digest,created_by_user_id,created_at)
		 VALUES($1,$2,1,'delete-guard','lg-'||replace($1::uuid::text,'-',''),10000,3000,3,3,0,0,1,$3,$4,now())`,
			[]any{groupID, env.scopeID, make([]byte, 32), env.adminID}},
		{`INSERT INTO node_line_endpoints(id,node_id,tenant_scope_id,line_group_id,config_revision,address,address_family,port,
		 region,carrier,priority,weight,enabled) VALUES($1,$2,$3,$4,1,'192.0.2.10',4,80,'','',0,1,true)`,
			[]any{uuid.New(), nodeID, env.scopeID, groupID}},
		{`INSERT INTO node_line_endpoint_health(tenant_scope_id,line_group_id,config_revision,endpoint_id,status,
		 consecutive_successes,consecutive_failures,last_sequence,last_changed_at,row_revision,created_at,updated_at)
		 SELECT $1,$2,1,id,'unknown',0,0,0,now(),1,now(),now() FROM node_line_endpoints WHERE tenant_scope_id=$1 AND line_group_id=$2`,
			[]any{env.scopeID, groupID}},
		{`UPDATE node_line_group_revisions SET sealed_at=now() WHERE tenant_scope_id=$1 AND line_group_id=$2 AND revision=1`,
			[]any{env.scopeID, groupID}},
	}
	tx, err := env.pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(t.Context()) }()
	for _, statement := range statements {
		if _, err := tx.Exec(t.Context(), statement.sql, statement.args...); err != nil {
			t.Fatalf("seed line group: %v", err)
		}
	}
	if err := tx.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	return groupID
}

func TestNodeSelfRegistrationRateLimit(t *testing.T) {
	env := newRegistrationTestEnv(t)
	base := env.newServerAt()
	body := registrationBody("nrk1."+strings.Repeat("0", 32)+"."+strings.Repeat("A", 43), strings.Repeat("c3", 32), "edge")
	for range registrationLimitPerSource {
		response := doRequest(t, env.client, http.MethodPost, base+"/v1/node-registrations", body, nil, "")
		assertError(t, response, http.StatusUnauthorized, "invalid_registration_credential", "")
	}
	limited := doRequest(t, env.client, http.MethodPost, base+"/v1/node-registrations", body, nil, "")
	if limited.Header.Get("Retry-After") != "60" {
		t.Fatalf("Retry-After = %q", limited.Header.Get("Retry-After"))
	}
	assertError(t, limited, http.StatusTooManyRequests, "node_registration_rate_limited", "")
}

// fz-x13: an install interrupted after the Gateway enrollment committed
// fetches its issued identity with the registration credential; every miss is
// 404 and only this machine's material is returned.
func TestNodeRegistrationIdentityRecovery(t *testing.T) {
	env := newRegistrationTestEnv(t)
	credential := env.credential(t, http.MethodGet, "/v1/nodes/registration-credential").Credential
	fingerprintA, fingerprintB := strings.Repeat("a1", 32), strings.Repeat("b2", 32)
	seededCSR := strings.Repeat("aa", 32) // seedRegisteredNodeCertificate's csr_sha256
	fetch := func(credential, fingerprint, csr string) *http.Response {
		return doRequest(t, env.client, http.MethodPost, env.url+"/v1/node-registrations/identity",
			map[string]any{"credential": credential, "machine_fingerprint": fingerprint, "csr_sha256": csr}, nil, "")
	}
	created := env.register(t, env.url, registrationBody(credential, fingerprintA, "edge-a"), http.StatusCreated)
	other := env.register(t, env.url, registrationBody(credential, fingerprintB, "edge-b"), http.StatusCreated)
	assertError(t, fetch(credential, fingerprintA, seededCSR), http.StatusNotFound, "node_identity_not_found", "")

	seedRegisteredNodeCertificate(t, env, created.Node.ID)
	seedRegisteredNodeCertificate(t, env, other.Node.ID)
	response := fetch(credential, fingerprintA, seededCSR)
	var recovered nodeRegistrationIdentityResponse
	decodeResponse(t, response, http.StatusOK, &recovered)
	if response.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("Cache-Control = %q", response.Header.Get("Cache-Control"))
	}
	if recovered.NodeID != created.Node.ID.String() || recovered.SelectedProtocolVersion.Major != 1 ||
		recovered.ArtifactEncryptionKeyID != "x25519:test" || string(recovered.Certificate.LeafCertificatePEM) != "test" ||
		len(recovered.Certificate.IssuingChainPEM) != 1 || recovered.Certificate.SerialNumber == "" {
		t.Fatalf("recovered identity = %+v", recovered)
	}
	env.nextWindow()
	assertError(t, fetch(credential, fingerprintA, strings.Repeat("ab", 32)), http.StatusNotFound, "node_identity_not_found", "")
	assertError(t, fetch(credential, strings.Repeat("c3", 32), seededCSR), http.StatusNotFound, "node_identity_not_found", "")
	forged := "nrk1." + strings.Repeat("0", 32) + "." + strings.Repeat("A", 43)
	assertError(t, fetch(forged, fingerprintA, seededCSR), http.StatusUnauthorized, "invalid_registration_credential", "")
	if second := fetch(credential, fingerprintB, seededCSR); second.StatusCode == http.StatusOK {
		var item nodeRegistrationIdentityResponse
		decodeResponse(t, second, http.StatusOK, &item)
		if item.NodeID != other.Node.ID.String() {
			t.Fatalf("machine B received node %s", item.NodeID)
		}
	} else {
		t.Fatalf("machine B status = %d", second.StatusCode)
	}
	var success, denied int
	if err := env.pool.QueryRow(t.Context(), `SELECT count(*) FILTER (WHERE result='success'), count(*) FILTER (WHERE result='denied')
		FROM audit_events WHERE action='node.registration.identity_fetch' AND resource_id=$1`, created.Node.ID.String()).Scan(&success, &denied); err != nil ||
		success != 1 || denied != 2 {
		t.Fatalf("identity fetch audit success=%d denied=%d, %v", success, denied, err)
	}
}

// seedRegisteredNodeCertificate simulates a completed Gateway enrollment for
// the registered node (identity authorization plus a live current certificate).
func seedRegisteredNodeCertificate(t *testing.T, env registrationTestEnv, node uuid.UUID) {
	t.Helper()
	var token uuid.UUID
	if err := env.pool.QueryRow(t.Context(), `SELECT id FROM node_enrollment_tokens WHERE node_id=$1 ORDER BY created_at DESC LIMIT 1`, node).Scan(&token); err != nil {
		t.Fatal(err)
	}
	now, scope, user := env.now, env.scopeID, env.adminID
	authorization, epoch, certificate := uuid.New(), uuid.New(), uuid.New()
	existingEpoch := false
	var installation string
	if err := env.pool.QueryRow(t.Context(), `SELECT installation_id FROM control_installation_entitlement WHERE singleton`).Scan(&installation); err != nil {
		t.Fatal(err)
	}
	// One active CA epoch per installation: later calls reuse the first one.
	if err := env.pool.QueryRow(t.Context(), `SELECT id FROM node_ca_key_epochs WHERE installation_id=$1 AND status='active'`,
		installation).Scan(&epoch); err != nil && !errors.Is(err, pgx.ErrNoRows) {
		t.Fatal(err)
	} else if err == nil {
		existingEpoch = true
	}
	// Serial and certificate digests are unique per certificate.
	nodeDigest := sha256.Sum256(node[:])
	serial := hex.EncodeToString(nodeDigest[:8])
	leafSHA, leafDER := sha256.Sum256(append([]byte("leaf"), node[:]...)), sha256.Sum256(append([]byte("der"), node[:]...))
	statements := []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO node_ca_key_epochs(id,installation_id,epoch,key_id,ca_certificate_pem,ca_certificate_sha256,public_key_sha256,not_before,not_after,status,request_id,request_digest,created_by_scope_id,created_by_user_id,created_at)
		 SELECT $1,$7,1,'registration-test','test',decode(repeat('a',64),'hex'),decode(repeat('b',64),'hex'),$2,$3,'active',$4,decode(repeat('c',64),'hex'),$5,$6,$2
		 WHERE NOT $8`, []any{epoch, now, now.Add(24 * time.Hour), uuid.New(), scope, user, installation, existingEpoch}},
		{`INSERT INTO node_enrollment_authorizations(id,token_id,node_id,purpose,request_id,request_digest,authorized_at)
		 VALUES($1,$2,$3,'initial_enrollment',$5,decode(repeat('e',64),'hex'),$4)`, []any{authorization, token, node, now, authorization.String()}},
		{`INSERT INTO node_identity_authorizations(id,token_id,node_id,purpose,request_id,request_digest,token_hash,csr_der,csr_sha256,machine_fingerprint_sha256,protocol_min_major,protocol_min_minor,protocol_max_major,protocol_max_minor,selected_protocol_major,selected_protocol_minor,capabilities_snapshot,capabilities_sha256,gateway_workload_identity,gateway_instance_id,artifact_key_id,artifact_public_key,status,authorized_at,expires_at)
		 VALUES($1,$2,$3,'initial_enrollment',$1,decode(repeat('e',64),'hex'),(SELECT token_hash FROM node_enrollment_tokens WHERE id=$2),'test',decode(repeat('a',64),'hex'),decode(repeat('a',64),'hex'),1,0,1,0,1,0,'{}',decode(repeat('a',64),'hex'),'spiffe://cdn-platform/gateway/test','test','x25519:test',decode(repeat('a',64),'hex'),'authorized',$4,$5)`, []any{authorization, token, node, now, now.Add(time.Hour)}},
		{`INSERT INTO node_certificates(id,node_id,issuance_kind,enrollment_authorization_id,serial_number,csr_sha256,certificate_public_key_sha256,uri_san,not_before,not_after,renewal_at,leaf_certificate_pem,issuing_chain_pem,leaf_certificate_sha256,status,issued_at,owner_scope_id,installation_id,ca_epoch_id,leaf_der_sha256,rotation_status,lifecycle_revision,lifecycle_request_id,lifecycle_request_digest,lifecycle_bound_at)
		 VALUES($1,$2,'initial',$3,$12,decode(repeat('a',64),'hex'),decode(repeat('b',64),'hex'),$4,$5,$6,$7,'test',ARRAY['test'::bytea],$13,'active',$5,$8,$11,$9,$14,'current',1,$10,decode(repeat('e',64),'hex'),$5)`, []any{certificate, node, authorization, "spiffe://cdn-platform/node/" + node.String(), now, now.Add(24 * time.Hour), now.Add(12 * time.Hour), scope, epoch, uuid.New(), installation, serial, leafSHA[:], leafDER[:]}},
		// 019: the authorization reaches issued through signing, naming the certificate.
		{`UPDATE node_identity_authorizations SET status='signing',signing_lease_id=gen_random_uuid(),
		 signing_lease_expires_at=$2,signing_attempt=signing_attempt+1 WHERE id=$1`, []any{authorization, now.Add(time.Minute)}},
		{`UPDATE node_identity_authorizations SET status='issued',signing_lease_id=NULL,signing_lease_expires_at=NULL,
		 issued_certificate_id=$2,completed_at=$3 WHERE id=$1`, []any{authorization, certificate, now}},
	}
	for _, statement := range statements {
		if _, err := env.pool.Exec(t.Context(), statement.sql, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
}
