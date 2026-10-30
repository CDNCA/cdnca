package urlauthpolicyhttp

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/apikey"
	"github.com/cdnca/cdnca/services/control-api/internal/apikeycredential"
	"github.com/cdnca/cdnca/services/control-api/internal/database"
	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	"github.com/cdnca/cdnca/services/control-api/internal/iamlock"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/sessioncredential"
	"github.com/cdnca/cdnca/services/control-api/internal/urlauthpolicy"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type runtimeIntegrationFixture struct {
	pool            *pgxpool.Pool
	handler         http.Handler
	identity        *identity.Service
	apiKeys         *apikey.Service
	cipher          *toggleCipher
	tenantID        uuid.UUID
	tenantScopeID   uuid.UUID
	tenantUserID    uuid.UUID
	tenantRoleID    uuid.UUID
	tenantSiteID    uuid.UUID
	otherSiteID     uuid.UUID
	platformScopeID uuid.UUID
	tenantLogin     identity.AuthResult
	platformLogin   identity.AuthResult
}

type toggleCipher struct {
	inner *urlauthpolicy.AESGCMSecretCipher
	fail  atomic.Bool
}

func (cipher *toggleCipher) Encrypt(value []byte) (string, []byte, error) {
	return cipher.EncryptBound(value, nil)
}

func (cipher *toggleCipher) EncryptBound(value, associatedData []byte) (string, []byte, error) {
	if cipher.fail.Load() {
		return "", nil, urlauthpolicy.ErrEncryptionUnavailable
	}
	return cipher.inner.EncryptBound(value, associatedData)
}

func (cipher *toggleCipher) DecryptBound(keyID string, value, associatedData []byte) ([]byte, error) {
	return cipher.inner.DecryptBound(keyID, value, associatedData)
}

func (cipher *toggleCipher) IdempotencyDigest(value []byte) [32]byte {
	return cipher.inner.IdempotencyDigest(value)
}

func (cipher *toggleCipher) SecretDigest(value []byte) [32]byte {
	return cipher.inner.SecretDigest(value)
}

func TestRuntimePostgreSQLCredentialAndKeyLifecycle(t *testing.T) {
	fixture := newRuntimeIntegrationFixture(t)
	createBody := map[string]any{
		"target_scope_id":           fixture.tenantScopeID,
		"owner_id":                  fixture.tenantUserID,
		"site_id":                   fixture.tenantSiteID,
		"name":                      "Protected downloads",
		"enabled":                   true,
		"algorithm":                 urlauthpolicy.AlgorithmHMACSHA256,
		"signature_parameter":       "sig",
		"expiration_parameter":      "exp",
		"key_id_parameter":          "kid",
		"bind_client_ip":            true,
		"max_clock_skew_seconds":    30,
		"max_validity_seconds":      600,
		"max_signature_uses":        1,
		"excluded_query_parameters": []string{"utm_source"},
		"trusted_proxy_cidrs":       []string{"10.0.0.0/8"},
	}

	createdResponse := fixture.request(t, http.MethodPost, "/v1/url-auth-policies", createBody,
		"Bearer "+fixture.platformLogin.AccessToken, "create-policy", "")
	if createdResponse.Code != http.StatusCreated {
		t.Fatalf("create status=%d body=%s", createdResponse.Code, createdResponse.Body.String())
	}
	var created urlauthpolicy.SecretWriteResult
	decodeRuntimeResponse(t, createdResponse, &created)
	if created.Policy.Revision != 1 || created.Policy.Owner == nil || len(created.Secret) != 43 || created.Replayed {
		t.Fatalf("created=%#v", created)
	}
	firstSecret := created.Secret

	fixture.cipher.fail.Store(true)
	replayResponse := fixture.request(t, http.MethodPost, "/v1/url-auth-policies", createBody,
		"Bearer "+fixture.platformLogin.AccessToken, "create-policy", "")
	fixture.cipher.fail.Store(false)
	var replayed urlauthpolicy.SecretWriteResult
	decodeRuntimeResponse(t, replayResponse, &replayed)
	if replayResponse.Code != http.StatusCreated || !replayed.Replayed || replayed.Secret != "" || replayed.Policy.ID != created.Policy.ID {
		t.Fatalf("replay status=%d result=%#v", replayResponse.Code, replayed)
	}

	listResponse := fixture.request(t, http.MethodGet, "/v1/url-auth-policies?page=1&limit=20", nil,
		"Bearer "+fixture.tenantLogin.AccessToken, "list-policy", "")
	var page urlauthpolicy.ListResult
	decodeRuntimeResponse(t, listResponse, &page)
	if listResponse.Code != http.StatusOK || page.Total != 1 || len(page.Items) != 1 || page.Items[0].Owner != nil || strings.Contains(listResponse.Body.String(), firstSecret) {
		t.Fatalf("tenant list status=%d page=%#v body=%s", listResponse.Code, page, listResponse.Body.String())
	}

	issued, err := fixture.apiKeys.CreateSelf(t.Context(), fixture.tenantLogin.Principal, apikey.CreateInput{
		Name: "URL auth automation", Scopes: []string{urlauthpolicy.PermissionRead, urlauthpolicy.PermissionManage},
		IdempotencyKey: "create-url-auth-api-key", RequestID: "create-url-auth-api-key",
	})
	if err != nil {
		t.Fatal(err)
	}
	apiCredential := issued.Key.KeyID + "." + issued.Secret
	disableResponse := fixture.request(t, http.MethodPost, "/v1/url-auth-policies/"+created.Policy.ID.String()+"/disable", map[string]any{},
		"CdncaKey "+apiCredential, "disable-policy", `"1"`)
	var disabled urlauthpolicy.WriteResult
	decodeRuntimeResponse(t, disableResponse, &disabled)
	if disableResponse.Code != http.StatusOK || disabled.Policy.Enabled || disabled.Policy.Revision != 2 || disabled.Policy.Owner != nil {
		t.Fatalf("disable status=%d result=%#v", disableResponse.Code, disabled)
	}

	rotateResponse := fixture.request(t, http.MethodPost, "/v1/url-auth-policies/"+created.Policy.ID.String()+"/rotate", map[string]any{},
		"Bearer "+fixture.platformLogin.AccessToken, "rotate-policy-1", `"2"`)
	var rotated urlauthpolicy.SecretWriteResult
	decodeRuntimeResponse(t, rotateResponse, &rotated)
	if rotateResponse.Code != http.StatusOK || len(rotated.Secret) != 43 || rotated.Policy.PreviousKey == nil || rotated.Policy.Revision != 3 {
		t.Fatalf("rotate status=%d result=%#v", rotateResponse.Code, rotated)
	}
	secondSecret := rotated.Secret

	rotateAgainResponse := fixture.request(t, http.MethodPost, "/v1/url-auth-policies/"+created.Policy.ID.String()+"/rotate", map[string]any{},
		"Bearer "+fixture.platformLogin.AccessToken, "rotate-policy-2", `"3"`)
	var rotatedAgain urlauthpolicy.SecretWriteResult
	decodeRuntimeResponse(t, rotateAgainResponse, &rotatedAgain)
	if rotateAgainResponse.Code != http.StatusOK || rotatedAgain.Policy.PreviousKey == nil ||
		rotatedAgain.Policy.PreviousKey.KeyID != rotated.Policy.CurrentKey.KeyID || rotatedAgain.Policy.Revision != 4 {
		t.Fatalf("second rotate status=%d result=%#v", rotateAgainResponse.Code, rotatedAgain)
	}
	assertStoredSecrets(t, fixture, created.Policy.ID, []string{firstSecret, secondSecret, rotatedAgain.Secret})
	snapshotResponse := fixture.request(t, http.MethodGet, "/v1/url-auth-policies/"+created.Policy.ID.String()+"/edge-snapshot", nil,
		"Bearer "+fixture.platformLogin.AccessToken, "edge-snapshot", "")
	var snapshot urlauthpolicy.SnapshotResult
	decodeRuntimeResponse(t, snapshotResponse, &snapshot)
	if snapshotResponse.Code != http.StatusOK || snapshot.Document.SchemaVersion != urlauthpolicy.SchemaVersion ||
		snapshot.Document.Algorithm != urlauthpolicy.AlgorithmHMACSHA256 || snapshot.Document.PreviousKey == nil ||
		!strings.HasPrefix(snapshot.Document.CurrentKey.KeyFile, "/var/lib/cdnca-edge/urlauth/keys/") ||
		strings.Contains(snapshotResponse.Body.String(), rotatedAgain.Secret) {
		t.Fatalf("snapshot status=%d value=%#v body=%s", snapshotResponse.Code, snapshot, snapshotResponse.Body.String())
	}

	currentRevoke := fixture.request(t, http.MethodPost, "/v1/url-auth-policies/"+created.Policy.ID.String()+"/revoke",
		map[string]any{"key_id": rotatedAgain.Policy.CurrentKey.KeyID}, "Bearer "+fixture.platformLogin.AccessToken,
		"revoke-current", `"4"`)
	if currentRevoke.Code != http.StatusConflict {
		t.Fatalf("current revoke status=%d body=%s", currentRevoke.Code, currentRevoke.Body.String())
	}
	revokeResponse := fixture.request(t, http.MethodPost, "/v1/url-auth-policies/"+created.Policy.ID.String()+"/revoke",
		map[string]any{"key_id": rotatedAgain.Policy.PreviousKey.KeyID}, "Bearer "+fixture.platformLogin.AccessToken,
		"revoke-previous", `"4"`)
	var revoked urlauthpolicy.WriteResult
	decodeRuntimeResponse(t, revokeResponse, &revoked)
	if revokeResponse.Code != http.StatusOK || revoked.Policy.PreviousKey != nil || revoked.Policy.Revision != 5 {
		t.Fatalf("revoke status=%d result=%#v", revokeResponse.Code, revoked)
	}

	assertConcurrentRevisionWinner(t, fixture, revoked.Policy)
	assertLiveRevocation(t, fixture, apiCredential, issued.Key)
	assertCrossTenantSiteDenied(t, fixture)
	assertSessionLogout(t, fixture)
}

func TestRuntimePostgreSQLOwnerIsolation(t *testing.T) {
	fixture := newRuntimeIntegrationFixture(t)
	fields := policyFieldsForRuntime(urlauthpolicy.Policy{Site: urlauthpolicy.SiteReference{ID: fixture.tenantSiteID}})
	fields.Name = "Owner-isolated policy"
	createdResponse := fixture.request(t, http.MethodPost, "/v1/url-auth-policies", fields,
		"Bearer "+fixture.tenantLogin.AccessToken, "owner-create", "")
	var created urlauthpolicy.SecretWriteResult
	decodeRuntimeResponse(t, createdResponse, &created)
	if createdResponse.Code != http.StatusCreated {
		t.Fatalf("owner create status=%d body=%s", createdResponse.Code, createdResponse.Body.String())
	}
	rotatedResponse := fixture.request(t, http.MethodPost, "/v1/url-auth-policies/"+created.Policy.ID.String()+"/rotate", map[string]any{},
		"Bearer "+fixture.tenantLogin.AccessToken, "owner-rotate", `"1"`)
	var rotated urlauthpolicy.SecretWriteResult
	decodeRuntimeResponse(t, rotatedResponse, &rotated)
	if rotatedResponse.Code != http.StatusOK || rotated.Policy.PreviousKey == nil {
		t.Fatalf("owner rotate status=%d body=%s", rotatedResponse.Code, rotatedResponse.Body.String())
	}

	otherLogin, otherCredential := createSameScopeTenantActor(t, fixture)
	type persistentState struct {
		Revision int64
		Enabled  bool
		Keys     int
		Versions int
		Writes   int
		Audits   int
	}
	readState := func() persistentState {
		var state persistentState
		if err := fixture.pool.QueryRow(t.Context(), `SELECT p.revision,p.enabled,
			(SELECT count(*) FROM url_auth_policy_keys WHERE policy_id=p.id),
			(SELECT count(*) FROM url_auth_policy_versions WHERE policy_id=p.id),
			(SELECT count(*) FROM url_auth_policy_write_requests WHERE resource_id=p.id),
			(SELECT count(*) FROM audit_events WHERE resource_type='url_auth_policy' AND resource_id=p.id::text)
			FROM url_auth_policies p WHERE p.id=$1`, created.Policy.ID).Scan(
			&state.Revision, &state.Enabled, &state.Keys, &state.Versions, &state.Writes, &state.Audits); err != nil {
			t.Fatal(err)
		}
		return state
	}
	before := readState()
	updateFields := policyFieldsForRuntime(rotated.Policy)
	updateFields.Name = "Cross-owner update"
	for index, authorization := range []string{"Bearer " + otherLogin.AccessToken, "CdncaKey " + otherCredential} {
		prefix := fmt.Sprintf("other-owner-%d", index)
		listPaths := []string{
			"/v1/url-auth-policies?page=1&limit=20",
			"/v1/url-auth-policies?page=2&limit=20&name=owner&status=enabled&site_id=" + fixture.tenantSiteID.String(),
		}
		for _, path := range listPaths {
			response := fixture.request(t, http.MethodGet, path, nil, authorization, prefix+"-list", "")
			var page urlauthpolicy.ListResult
			decodeRuntimeResponse(t, response, &page)
			if response.Code != http.StatusOK || page.Total != 0 || len(page.Items) != 0 {
				t.Fatalf("%s list status=%d page=%#v", prefix, response.Code, page)
			}
		}
		for _, path := range []string{
			"/v1/url-auth-policies/" + created.Policy.ID.String(),
			"/v1/url-auth-policies/" + created.Policy.ID.String() + "/edge-snapshot",
		} {
			response := fixture.request(t, http.MethodGet, path, nil, authorization, prefix+"-read", "")
			if response.Code != http.StatusNotFound {
				t.Fatalf("%s read %s status=%d body=%s", prefix, path, response.Code, response.Body.String())
			}
		}
		writes := []struct {
			method string
			path   string
			body   any
		}{
			{http.MethodPatch, "/v1/url-auth-policies/" + created.Policy.ID.String(), updateFields},
			{http.MethodPost, "/v1/url-auth-policies/" + created.Policy.ID.String() + "/enable", map[string]any{}},
			{http.MethodPost, "/v1/url-auth-policies/" + created.Policy.ID.String() + "/disable", map[string]any{}},
			{http.MethodPost, "/v1/url-auth-policies/" + created.Policy.ID.String() + "/rotate", map[string]any{}},
			{http.MethodPost, "/v1/url-auth-policies/" + created.Policy.ID.String() + "/revoke", map[string]any{"key_id": rotated.Policy.PreviousKey.KeyID}},
		}
		for writeIndex, write := range writes {
			response := fixture.request(t, write.method, write.path, write.body, authorization,
				fmt.Sprintf("%s-write-%d", prefix, writeIndex), `"2"`)
			if response.Code != http.StatusNotFound {
				t.Fatalf("%s write %s status=%d body=%s", prefix, write.path, response.Code, response.Body.String())
			}
		}
	}
	if after := readState(); after != before {
		t.Fatalf("cross-owner attempts changed state: before=%+v after=%+v", before, after)
	}
	platformGet := fixture.request(t, http.MethodGet, "/v1/url-auth-policies/"+created.Policy.ID.String(), nil,
		"Bearer "+fixture.platformLogin.AccessToken, "platform-owner-get", "")
	if platformGet.Code != http.StatusOK {
		t.Fatalf("platform get status=%d body=%s", platformGet.Code, platformGet.Body.String())
	}
}

func createSameScopeTenantActor(t *testing.T, fixture *runtimeIntegrationFixture) (identity.AuthResult, string) {
	t.Helper()
	const password = "UrlAuth-Stage1-Other-Password!"
	passwordHash, err := identity.HashPassword(password)
	if err != nil {
		t.Fatal(err)
	}
	userID, roleID := uuid.New(), uuid.New()
	now := time.Now().UTC()
	err = pgx.BeginFunc(t.Context(), fixture.pool, func(tx pgx.Tx) error {
		statements := []struct {
			query string
			args  []any
		}{
			{`INSERT INTO users(id,username,display_name,password_hash,created_at,updated_at) VALUES($1,'url-auth-same-scope-other','Same Scope Other',$2,$3,$3)`, []any{userID, passwordHash, now}},
			{`INSERT INTO memberships(scope_id,user_id,created_at) VALUES($1,$2,$3)`, []any{fixture.tenantScopeID, userID, now}},
			{`INSERT INTO roles(id,scope_id,name,description,system_role,created_at) VALUES($1,$2,'same_scope_other','same scope other',true,$3)`, []any{roleID, fixture.tenantScopeID, now}},
			{`INSERT INTO role_permissions(role_id,permission_name) VALUES($1,'url_auth_policies.read'),($1,'url_auth_policies.manage'),($1,'api_keys.self.manage')`, []any{roleID}},
			{`INSERT INTO role_assignments(scope_id,user_id,role_id,assigned_at) VALUES($1,$2,$3,$4)`, []any{fixture.tenantScopeID, userID, roleID, now}},
		}
		for _, statement := range statements {
			if _, err := tx.Exec(t.Context(), statement.query, statement.args...); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	login, err := fixture.identity.Login(t.Context(), identity.LoginInput{
		Username: "url-auth-same-scope-other", Password: password, ScopeID: &fixture.tenantScopeID,
	}, identity.RequestInfo{RequestID: "same-scope-other-login", UserAgent: "integration-test", SourceIP: "127.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	issued, err := fixture.apiKeys.CreateSelf(t.Context(), login.Principal, apikey.CreateInput{
		Name: "same-scope-other", Scopes: []string{urlauthpolicy.PermissionRead, urlauthpolicy.PermissionManage},
		IdempotencyKey: "same-scope-other-key", RequestID: "same-scope-other-key",
	})
	if err != nil {
		t.Fatal(err)
	}
	return login, issued.Key.KeyID + "." + issued.Secret
}

func assertConcurrentRevisionWinner(t *testing.T, fixture *runtimeIntegrationFixture, policy urlauthpolicy.Policy) {
	t.Helper()
	fields := policyFieldsForRuntime(policy)
	bodies := []urlauthpolicy.PolicyFields{fields, fields}
	bodies[0].Name, bodies[1].Name = "Concurrent A", "Concurrent B"
	statuses := make([]int, 2)
	var group sync.WaitGroup
	for index := range bodies {
		group.Add(1)
		go func(index int) {
			defer group.Done()
			response := fixture.request(t, http.MethodPatch, "/v1/url-auth-policies/"+policy.ID.String(), bodies[index],
				"Bearer "+fixture.platformLogin.AccessToken, fmt.Sprintf("concurrent-%d", index), fmt.Sprintf(`"%d"`, policy.Revision))
			statuses[index] = response.Code
		}(index)
	}
	group.Wait()
	sort.Ints(statuses)
	if statuses[0] != http.StatusOK || statuses[1] != http.StatusPreconditionFailed {
		t.Fatalf("concurrent statuses=%v", statuses)
	}
}

func assertLiveRevocation(t *testing.T, fixture *runtimeIntegrationFixture, credential string, key apikey.Key) {
	t.Helper()
	if _, err := fixture.pool.Exec(t.Context(), `DELETE FROM role_assignments WHERE scope_id=$1 AND user_id=$2 AND role_id=$3`, fixture.tenantScopeID, fixture.tenantUserID, fixture.tenantRoleID); err != nil {
		t.Fatal(err)
	}
	denied := fixture.request(t, http.MethodGet, "/v1/url-auth-policies?page=1&limit=20", nil,
		"CdncaKey "+credential, "rbac-revoked", "")
	if denied.Code != http.StatusForbidden && denied.Code != http.StatusUnauthorized {
		t.Fatalf("RBAC revocation status=%d body=%s", denied.Code, denied.Body.String())
	}
	if _, err := fixture.pool.Exec(t.Context(), `INSERT INTO role_assignments(scope_id,user_id,role_id,assigned_at) VALUES($1,$2,$3,$4)`, fixture.tenantScopeID, fixture.tenantUserID, fixture.tenantRoleID, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	statusFacts := []struct {
		name    string
		disable string
		restore string
		args    []any
	}{
		{name: "membership", disable: `UPDATE memberships SET status='suspended' WHERE scope_id=$1 AND user_id=$2`, restore: `UPDATE memberships SET status='active' WHERE scope_id=$1 AND user_id=$2`, args: []any{fixture.tenantScopeID, fixture.tenantUserID}},
		{name: "user", disable: `UPDATE users SET status='disabled',revision=revision+1 WHERE id=$1`, restore: `UPDATE users SET status='active',revision=revision+1 WHERE id=$1`, args: []any{fixture.tenantUserID}},
		{name: "tenant", disable: `UPDATE tenants SET status='suspended',revision=revision+1 WHERE id=$1`, restore: `UPDATE tenants SET status='active',revision=revision+1 WHERE id=$1`, args: []any{fixture.tenantID}},
	}
	for _, fact := range statusFacts {
		if _, err := fixture.pool.Exec(t.Context(), fact.disable, fact.args...); err != nil {
			t.Fatal(err)
		}
		response := fixture.request(t, http.MethodGet, "/v1/url-auth-policies?page=1&limit=20", nil,
			"CdncaKey "+credential, fact.name+"-disabled", "")
		if response.Code != http.StatusUnauthorized {
			t.Fatalf("%s disable status=%d body=%s", fact.name, response.Code, response.Body.String())
		}
		if _, err := fixture.pool.Exec(t.Context(), fact.restore, fact.args...); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := fixture.apiKeys.RevokeSelf(t.Context(), fixture.tenantLogin.Principal, apikey.MutationInput{
		ID: key.ID, ExpectedRevision: key.Revision, IdempotencyKey: "revoke-url-auth-api-key", RequestID: "revoke-url-auth-api-key",
	}); err != nil {
		t.Fatal(err)
	}
	unauthorized := fixture.request(t, http.MethodGet, "/v1/url-auth-policies?page=1&limit=20", nil,
		"CdncaKey "+credential, "api-key-revoked", "")
	if unauthorized.Code != http.StatusUnauthorized {
		t.Fatalf("API key revocation status=%d body=%s", unauthorized.Code, unauthorized.Body.String())
	}
}

func assertCrossTenantSiteDenied(t *testing.T, fixture *runtimeIntegrationFixture) {
	t.Helper()
	body := policyFieldsForRuntime(urlauthpolicy.Policy{Site: urlauthpolicy.SiteReference{ID: fixture.otherSiteID}})
	body.Name = "Cross tenant"
	response := fixture.request(t, http.MethodPost, "/v1/url-auth-policies", body,
		"Bearer "+fixture.tenantLogin.AccessToken, "cross-tenant-site", "")
	if response.Code != http.StatusUnprocessableEntity {
		t.Fatalf("cross-tenant status=%d body=%s", response.Code, response.Body.String())
	}
}

func assertSessionLogout(t *testing.T, fixture *runtimeIntegrationFixture) {
	t.Helper()
	if err := fixture.identity.Logout(t.Context(), fixture.tenantLogin.RefreshToken, "logout-url-auth-session"); err != nil {
		t.Fatal(err)
	}
	response := fixture.request(t, http.MethodGet, "/v1/url-auth-policies?page=1&limit=20", nil,
		"Bearer "+fixture.tenantLogin.AccessToken, "session-revoked", "")
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("session revocation status=%d body=%s", response.Code, response.Body.String())
	}
}

func assertStoredSecrets(t *testing.T, fixture *runtimeIntegrationFixture, policyID uuid.UUID, plaintexts []string) {
	t.Helper()
	rows, err := fixture.pool.Query(t.Context(), `SELECT key_id,role,kek_key_id,ciphertext,secret_digest FROM url_auth_policy_keys WHERE policy_id=$1 ORDER BY created_at`, policyID)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	count := 0
	for rows.Next() {
		var keyID, role, kekID string
		var ciphertext, digest []byte
		if err := rows.Scan(&keyID, &role, &kekID, &ciphertext, &digest); err != nil {
			t.Fatal(err)
		}
		if len(ciphertext) <= 16 || len(digest) != 32 || kekID == "" {
			t.Fatalf("invalid envelope metadata key=%s role=%s cipher=%d digest=%d", keyID, role, len(ciphertext), len(digest))
		}
		for _, plaintext := range plaintexts {
			if bytes.Contains(ciphertext, []byte(plaintext)) || bytes.Equal(digest, []byte(plaintext)) {
				t.Fatalf("plaintext leaked for key=%s", keyID)
			}
		}
		wrongAAD := []byte("cdnca-control-url-auth/key-envelope/v1\x00" + uuid.NewString() + "\x00" + keyID + "\x00current")
		if _, err := fixture.cipher.DecryptBound(kekID, ciphertext, wrongAAD); !errors.Is(err, urlauthpolicy.ErrEncryptionUnavailable) {
			t.Fatalf("cross-policy ciphertext accepted key=%s error=%v", keyID, err)
		}
		count++
	}
	if err := rows.Err(); err != nil || count != 3 {
		t.Fatalf("stored key count=%d error=%v", count, err)
	}
}

func policyFieldsForRuntime(policy urlauthpolicy.Policy) urlauthpolicy.PolicyFields {
	return urlauthpolicy.PolicyFields{
		SiteID: policy.Site.ID, Name: policy.Name, Enabled: policy.Enabled, Algorithm: urlauthpolicy.AlgorithmHMACSHA256,
		SignatureParameter: "sig", ExpirationParameter: "exp", KeyIDParameter: "kid", BindClientIP: true,
		MaxClockSkewSeconds: 30, MaxValiditySeconds: 600, MaxSignatureUses: 1,
		ExcludedQueryParameters: []string{"utm_source"}, TrustedProxyCIDRs: []string{"10.0.0.0/8"},
	}
}

func (fixture *runtimeIntegrationFixture) request(t *testing.T, method, path string, body any, authorization, idempotencyKey, ifMatch string) *httptest.ResponseRecorder {
	t.Helper()
	var encoded []byte
	if body != nil {
		var err error
		encoded, err = json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
	}
	request := httptest.NewRequest(method, path, bytes.NewReader(encoded))
	request.Header.Set("Authorization", authorization)
	request.Header.Set("X-Request-ID", idempotencyKey+"-request")
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if idempotencyKey != "" {
		request.Header.Set("Idempotency-Key", idempotencyKey)
	}
	if ifMatch != "" {
		request.Header.Set("If-Match", ifMatch)
	}
	response := httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	return response
}

func decodeRuntimeResponse(t *testing.T, response *httptest.ResponseRecorder, target any) {
	t.Helper()
	if err := json.Unmarshal(response.Body.Bytes(), target); err != nil {
		t.Fatalf("decode status=%d body=%s: %v", response.Code, response.Body.String(), err)
	}
}

func newRuntimeIntegrationFixture(t *testing.T) *runtimeIntegrationFixture {
	t.Helper()
	pool := isolatedRuntimePool(t)
	fixture := &runtimeIntegrationFixture{pool: pool}
	password := "UrlAuth-Stage1-Test-Password!"
	passwordHash, err := identity.HashPassword(password)
	if err != nil {
		t.Fatal(err)
	}
	fixture.seed(t, passwordHash)
	tokens, err := identity.NewTokenManager(strings.Repeat("url-auth-runtime-secret-", 2), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	fixture.identity, err = identity.NewService(identity.NewStore(pool), tokens, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	fixture.tenantLogin, err = fixture.identity.Login(t.Context(), identity.LoginInput{
		Username: "url-auth-tenant", Password: password, ScopeID: &fixture.tenantScopeID,
	}, identity.RequestInfo{RequestID: "tenant-formal-login", UserAgent: "integration-test", SourceIP: "127.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	fixture.platformLogin, err = fixture.identity.Login(t.Context(), identity.LoginInput{
		Username: "url-auth-platform", Password: password, ScopeID: &fixture.platformScopeID,
	}, identity.RequestInfo{RequestID: "platform-formal-login", UserAgent: "integration-test", SourceIP: "127.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	pepper := bytes.Repeat([]byte{0x91}, 32)
	fixture.apiKeys = apikey.NewService(pool, pepper, time.Now)
	sessions, err := sessioncredential.NewVerifier(tokens, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	apiKeyVerifier, err := apikeycredential.NewVerifier(pepper, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	iam, err := iamlock.NewAuthorizer(sessions, apiKeyVerifier)
	if err != nil {
		t.Fatal(err)
	}
	innerCipher, err := urlauthpolicy.NewAESGCMSecretCipher("url-auth-kek-v1", bytes.Repeat([]byte{0x42}, 32))
	if err != nil {
		t.Fatal(err)
	}
	fixture.cipher = &toggleCipher{inner: innerCipher}
	fixture.handler, err = NewRuntimeHandler(RuntimeConfig{Enabled: true}, RuntimeDependencies{
		Pool: pool, Identity: fixture.identity, APIKeys: fixture.apiKeys, IAM: iam, Cipher: fixture.cipher, Now: time.Now,
	})
	if err != nil {
		t.Fatal(err)
	}
	return fixture
}

func (fixture *runtimeIntegrationFixture) seed(t *testing.T, passwordHash string) {
	t.Helper()
	fixture.tenantID, fixture.tenantScopeID, fixture.tenantUserID = uuid.New(), uuid.New(), uuid.New()
	fixture.tenantRoleID, fixture.tenantSiteID = uuid.New(), uuid.New()
	fixture.platformScopeID = uuid.New()
	platformUserID, platformRoleID := uuid.New(), uuid.New()
	otherTenantID, otherScopeID, otherUserID, otherRoleID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	fixture.otherSiteID = uuid.New()
	now := time.Now().UTC()
	err := pgx.BeginFunc(t.Context(), fixture.pool, func(tx pgx.Tx) error {
		statements := []struct {
			query string
			args  []any
		}{
			{`INSERT INTO tenants(id,display_name,created_at,updated_at) VALUES($1,'URL Auth Tenant',$3,$3),($2,'Other Tenant',$3,$3)`, []any{fixture.tenantID, otherTenantID, now}},
			{`INSERT INTO access_scopes(id,kind,tenant_id,created_at) VALUES($1,'tenant',$2,$5),($3,'tenant',$4,$5),($6,'platform',NULL,$5)`, []any{fixture.tenantScopeID, fixture.tenantID, otherScopeID, otherTenantID, now, fixture.platformScopeID}},
			{`INSERT INTO users(id,username,display_name,password_hash,created_at,updated_at) VALUES
				($1,'url-auth-tenant','Tenant Owner',$4,$5,$5),($2,'url-auth-other','Other Owner',$4,$5,$5),($3,'url-auth-platform','Platform Owner',$4,$5,$5)`, []any{fixture.tenantUserID, otherUserID, platformUserID, passwordHash, now}},
			{`INSERT INTO memberships(scope_id,user_id,created_at) VALUES($1,$2,$7),($3,$4,$7),($5,$6,$7)`, []any{fixture.tenantScopeID, fixture.tenantUserID, otherScopeID, otherUserID, fixture.platformScopeID, platformUserID, now}},
			{`INSERT INTO roles(id,scope_id,name,description,system_role,created_at) VALUES
				($1,$2,'tenant_owner','owner',true,$7),($3,$4,'tenant_owner','owner',true,$7),($5,$6,'platform_owner','owner',true,$7)`, []any{fixture.tenantRoleID, fixture.tenantScopeID, otherRoleID, otherScopeID, platformRoleID, fixture.platformScopeID, now}},
			{`INSERT INTO role_permissions(role_id,permission_name) VALUES
				($1,'url_auth_policies.read'),($1,'url_auth_policies.manage'),($1,'api_keys.self.manage'),($2,'url_auth_policies.read'),($2,'url_auth_policies.manage'),($3,'platform.admin')
				ON CONFLICT DO NOTHING`, []any{fixture.tenantRoleID, otherRoleID, platformRoleID}},
			{`INSERT INTO role_assignments(scope_id,user_id,role_id,assigned_at) VALUES($1,$2,$3,$7),($4,$5,$6,$7),($8,$9,$10,$7)`, []any{fixture.tenantScopeID, fixture.tenantUserID, fixture.tenantRoleID, otherScopeID, otherUserID, otherRoleID, now, fixture.platformScopeID, platformUserID, platformRoleID}},
			{`INSERT INTO sites(id,scope_id,display_id,owner_user_id,domain,http_ports,https_ports,origins,origin_hosts,cname,https_enabled,enabled,status,is_default,revision,created_by_user_id,updated_by_user_id,created_at,updated_at)
				VALUES($1,$2,1,$3,'auth.example.test',ARRAY['80'],ARRAY[]::text[],ARRAY['192.0.2.1:80'],ARRAY['192.0.2.1'],'',false,true,'active',false,1,$3,$3,$7,$7),
				($4,$5,1,$6,'other.example.test',ARRAY['80'],ARRAY[]::text[],ARRAY['192.0.2.2:80'],ARRAY['192.0.2.2'],'',false,true,'active',false,1,$6,$6,$7,$7)`, []any{fixture.tenantSiteID, fixture.tenantScopeID, fixture.tenantUserID, fixture.otherSiteID, otherScopeID, otherUserID, now}},
			{`INSERT INTO site_origin_pools(site_id,updated_at) VALUES($1,$3),($2,$3)`, []any{fixture.tenantSiteID, fixture.otherSiteID, now}},
			{`INSERT INTO site_origins(site_id,position,host,port,weight,enabled) VALUES($1,1,'192.0.2.1',80,1,true),($2,1,'192.0.2.2',80,1,true)`, []any{fixture.tenantSiteID, fixture.otherSiteID}},
		}
		for _, statement := range statements {
			if _, err := tx.Exec(t.Context(), statement.query, statement.args...); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func isolatedRuntimePool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	databaseURL := strings.TrimSpace(os.Getenv("TEST_DATABASE_URL"))
	if databaseURL == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}
	admin, err := pgxpool.New(t.Context(), databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	schema := "url_auth_http_test_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if !regexp.MustCompile(`^url_auth_http_test_[a-f0-9]{32}$`).MatchString(schema) {
		t.Fatalf("unsafe schema %q", schema)
	}
	identifier := pgx.Identifier{schema}.Sanitize()
	if _, err := admin.Exec(t.Context(), "CREATE SCHEMA "+identifier); err != nil {
		t.Fatal(err)
	}
	config, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	config.MaxConns = 10
	config.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(t.Context(), config)
	if err != nil {
		t.Fatal(err)
	}
	if err := database.Migrate(t.Context(), pool, "up"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		pool.Close()
		ctx, cancel := databasetest.CleanupContext()
		defer cancel()
		if _, err := admin.Exec(ctx, "DROP SCHEMA "+identifier+" CASCADE"); err != nil {
			t.Errorf("drop schema: %v", err)
		}
		admin.Close()
	})
	return pool
}

var _ urlauthpolicy.BoundSecretCipher = (*toggleCipher)(nil)
