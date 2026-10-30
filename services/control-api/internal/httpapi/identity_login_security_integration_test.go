package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/accountloginchallenge"
	"github.com/cdnca/cdnca/services/control-api/internal/accountloginchallengehttp"
	"github.com/cdnca/cdnca/services/control-api/internal/accountrecoverycontext"
	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/impersonationhttp"
	"github.com/cdnca/cdnca/services/control-api/internal/systemusersettings"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func TestManagedUserLoginSecurityHTTP(t *testing.T) {
	f := newUserMetadataHTTPFixture(t)
	user, _ := f.create(t, "security", nil, false)
	path := metadataUserPath(user) + "/login-security?tenant_scope_id=" + user["scope_id"].(string)
	base := map[string]any{"expected_revision": 0, "login_verification": "none", "login_allowlist": []string{}}
	initial := f.request(t, "GET", path, "security-default", nil, 200)
	if len(initial) != 5 || initial["revision"] != float64(0) || initial["login_verification"] != "none" || len(initial["login_allowlist"].([]any)) != 0 {
		t.Fatalf("default=%v", initial)
	}
	t.Run("real session permissions scope and strict replacement", func(t *testing.T) {
		unauth := f
		unauth.admin = ""
		unauth.request(t, "GET", path, "security-anon", nil, 401)
		tenantAuth, _ := loginWithPassword(t, f.server.Client(), f.server.URL, user["username"].(string), tenantPassword)
		tenant := f
		tenant.admin = tenantAuth.AccessToken
		tenant.request(t, "GET", path, "security-tenant", nil, 403)
		response := identityRequest(t, f.server.Client(), "GET", f.server.URL+path, nil, "ApiKey not-a-session", "", "security-apikey")
		defer response.Body.Close()
		if response.StatusCode != 401 {
			t.Fatalf("API key session status=%d", response.StatusCode)
		}
		request := httptest.NewRequest("GET", path, nil)
		request.Header.Set("Authorization", "Bearer "+f.admin)
		request.AddCookie(&http.Cookie{Name: impersonationhttp.CookieName, Value: "opaque"})
		writer := httptest.NewRecorder()
		f.server.Config.Handler.ServeHTTP(writer, request)
		if writer.Code != 403 {
			t.Fatalf("impersonation context=%d", writer.Code)
		}
		f.request(t, "GET", metadataUserPath(user)+"/login-security?tenant_scope_id="+uuid.NewString(), "security-wrong-scope", nil, 404)
		f.request(t, "GET", path+"&tenant_scope_id="+user["scope_id"].(string), "security-duplicate-scope", nil, 400)
		for i, body := range []map[string]any{
			{"expected_revision": 0, "login_verification": "none"},
			{"expected_revision": 0, "login_verification": "none", "login_allowlist": nil},
			{"expected_revision": 0, "login_verification": "none", "login_allowlist": []string{"192.0.2.1/33"}},
			{"expected_revision": 0, "login_verification": "none", "login_allowlist": []string{"fe80::1%en0"}},
			{"expected_revision": 0, "login_verification": "totp", "login_allowlist": []string{}},
		} {
			f.request(t, "PUT", path, fmt.Sprintf("security-invalid-%d", i), body, 400)
		}
		f.request(t, "PUT", path, "security-no-email", map[string]any{"expected_revision": 0, "login_verification": "email", "login_allowlist": []string{}}, 422)
		f.request(t, "PUT", path, "", base, 400)
		r := httptest.NewRequest("PUT", path, strings.NewReader(`{"expected_revision":0,"login_verification":"none","login_verification":"email","login_allowlist":[]}`))
		r.Header.Set("Authorization", "Bearer "+f.admin)
		r.Header.Set("Idempotency-Key", "security-duplicate-body")
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		f.server.Config.Handler.ServeHTTP(w, r)
		if w.Code != 400 {
			t.Fatalf("duplicate body=%d", w.Code)
		}
	})
	t.Run("canonical save receipt CAS clear and legacy shape", func(t *testing.T) {
		body := cloneBody(base)
		body["login_allowlist"] = []string{"::ffff:192.0.2.2", "2001:0db8::1", "192.0.2.2"}
		saved := f.request(t, "PUT", path, "security-save", body, 200)
		if saved["revision"] != float64(1) || !reflect.DeepEqual(saved["login_allowlist"], []any{"192.0.2.2", "2001:db8::1"}) {
			t.Fatal(saved)
		}
		if got := f.request(t, "PUT", path, "security-save", body, 200); !reflect.DeepEqual(saved, got) {
			t.Fatalf("replay differs=%v", got)
		}
		f.request(t, "PUT", path, "security-save", base, 409)
		f.request(t, "PUT", path, "security-stale", base, 409)
		old := f.request(t, "GET", metadataUserPath(user), "security-legacy", nil, 200)
		assertLegacyMetadataUser(t, old)
		if old["revision"] != user["revision"] {
			t.Fatal("security policy altered user revision")
		}
		clear := cloneBody(base)
		clear["expected_revision"] = 1
		cleared := f.request(t, "PUT", path, "security-clear", clear, 200)
		if cleared["revision"] != float64(2) || len(cleared["login_allowlist"].([]any)) != 0 {
			t.Fatal(cleared)
		}
		var audits, receipts int
		var payload string
		if err := f.pool.QueryRow(t.Context(), `SELECT (SELECT count(*) FROM audit_events WHERE request_id='metadata-security-save'),(SELECT count(*) FROM identity_write_requests WHERE idempotency_key='security-save'),(SELECT payload::text FROM audit_events WHERE request_id='metadata-security-save')`).Scan(&audits, &receipts, &payload); err != nil || audits != 1 || receipts != 1 {
			t.Fatalf("atomic receipt/audit=%d/%d err=%v", audits, receipts, err)
		}
		if strings.Contains(payload, "192.0.2.2") || !strings.Contains(payload, "allowlist_sha256") {
			t.Fatalf("allowlist audit not redacted=%s", payload)
		}
	})
	t.Run("failed audit rolls back policy and receipt", func(t *testing.T) {
		if _, err := f.pool.Exec(t.Context(), `CREATE FUNCTION login_policy_fail() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='identity.user.login_security.update' THEN RAISE EXCEPTION 'injected audit failure'; END IF; RETURN NEW; END $$; CREATE TRIGGER login_policy_fail BEFORE INSERT ON audit_events FOR EACH ROW EXECUTE FUNCTION login_policy_fail()`, pgx.QueryExecModeSimpleProtocol); err != nil {
			t.Fatal(err)
		}
		body := cloneBody(base)
		body["expected_revision"] = 2
		result := f.request(t, "PUT", path, "security-rollback", body, 503)
		if result["error"].(map[string]any)["code"] != "login_security_unavailable" {
			t.Fatal(result)
		}
		current := f.request(t, "GET", path, "security-after-fault", nil, 200)
		var receipts int
		err := f.pool.QueryRow(t.Context(), `SELECT count(*) FROM identity_write_requests WHERE idempotency_key='security-rollback'`).Scan(&receipts)
		if err != nil || receipts != 0 || current["revision"] != float64(2) {
			t.Fatalf("failed audit left policy/receipt: %v %d %v", current, receipts, err)
		}
		if _, err := f.pool.Exec(t.Context(), `DROP TRIGGER login_policy_fail ON audit_events; DROP FUNCTION login_policy_fail()`, pgx.QueryExecModeSimpleProtocol); err != nil {
			t.Fatal(err)
		}
		f.request(t, "PUT", path, "security-rollback", body, 200)
	})
}

// The 251->252 upgrade/down round trip was removed with the 1.0.35 baseline
// (no compatibility with earlier schemas); a single down step from the release
// head no longer reaches 251. The runtime-grant contract is checked at head.
func TestLoginSecurityRuntimeGrants(t *testing.T) {
	f := newUserMetadataHTTPFixture(t)
	user, _ := f.create(t, "before-login-security", map[string]any{"remark": "preserved", "qq": "00text"}, true)
	path := metadataUserPath(user) + "/login-security?tenant_scope_id=" + user["scope_id"].(string)
	initial := f.request(t, "GET", path, "upgrade-default", nil, 200)
	if initial["revision"] != float64(0) || initial["login_verification"] != "none" {
		t.Fatal(initial)
	}
	// Use the real predefined non-super runtime role for the new table. Existing
	// role privileges are inspected independently rather than granted by the test.
	tx, err := f.pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(t.Context())
	if _, err := tx.Exec(t.Context(), `SET LOCAL ROLE cdnca_control_app`); err != nil {
		t.Fatal(err)
	}
	var role string
	var superuser bool
	if err := tx.QueryRow(t.Context(), `SELECT current_user,rolsuper FROM pg_roles WHERE rolname=current_user`).Scan(&role, &superuser); err != nil || superuser || role != "cdnca_control_app" {
		t.Fatalf("role=%s super=%t err=%v", role, superuser, err)
	}
	var selected int
	if err := tx.QueryRow(t.Context(), `SELECT count(*) FROM identity_user_login_security`).Scan(&selected); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(t.Context(), `INSERT INTO identity_user_login_security(scope_id,user_id,revision,login_verification,login_allowlist,updated_by_user_id,updated_at) VALUES($1,$2,1,'none',ARRAY[]::text[],$2,now())`, user["scope_id"], user["id"]); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(t.Context(), `UPDATE identity_user_login_security SET revision=2 WHERE user_id=$1`, user["id"]); err != nil {
		t.Fatal(err)
	}
	if err := tx.Rollback(t.Context()); err != nil {
		t.Fatal(err)
	}
	var privilegesJSON []byte
	if err := f.pool.QueryRow(t.Context(), `SELECT json_object_agg(name,json_build_object('select',has_table_privilege('cdnca_control_app',name,'SELECT'),'insert',has_table_privilege('cdnca_control_app',name,'INSERT'),'update',has_table_privilege('cdnca_control_app',name,'UPDATE'))) FROM unnest(ARRAY['users','memberships','auth_sessions','identity_write_requests','account_login_challenges_197','account_login_challenge_verify_receipts_197','notification_events']) AS name`).Scan(&privilegesJSON); err != nil {
		t.Fatal(err)
	}
	var privileges map[string]any
	if err := json.Unmarshal(privilegesJSON, &privileges); err != nil {
		t.Fatal(err)
	}
	t.Logf("unchanged baseline runtime grants: %s", privilegesJSON)
	f.request(t, "PUT", path, "upgrade-policy", map[string]any{"expected_revision": 0, "login_verification": "none", "login_allowlist": []string{}}, 200)
}

type loginSecurityContactCapture struct {
	otp   string
	calls int
}

func (capture *loginSecurityContactCapture) Enqueue(_ context.Context, _ pgx.Tx, request accountloginchallenge.ContactRequest) error {
	capture.otp = request.OTP
	capture.calls++
	return nil
}

func TestPasswordLoginChallengeHTTPAtomicContract(t *testing.T) {
	f := newUserMetadataHTTPFixture(t)
	user, _ := f.create(t, "password-otp-http", map[string]any{"email": "http-security@example.com"}, false)
	capture := new(loginSecurityContactCapture)
	settings, err := systemusersettings.NewService(f.pool, audit.New(f.pool), time.Now)
	if err != nil {
		t.Fatal(err)
	}
	challenge, err := accountloginchallenge.NewService(f.pool, accountloginchallenge.Config{DigestKey: bytes.Repeat([]byte{3}, 32), Policy: settings, Issuer: f.service, Contacts: capture})
	if err != nil {
		t.Fatal(err)
	}
	f.service.SetLoginChallengeConsumer(challenge)
	source, err := accountrecoverycontext.NewSourceIPResolver(nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	adminSession, err := f.service.AuthenticateSession(t.Context(), f.admin)
	if err != nil {
		t.Fatal(err)
	}
	// The legacy resolver deliberately selects the platform Host. The credential
	// challenge must select the user's tenant membership instead.
	handler, err := accountloginchallengehttp.NewHandler(challenge, accountloginchallengehttp.TrustedContextResolverFunc(func(*http.Request) (accountloginchallengehttp.TrustedContext, error) {
		return accountloginchallengehttp.TrustedContext{ScopeID: adminSession.Principal.ScopeID, SourceIP: "127.0.0.1"}, nil
	}), accountloginchallengehttp.Config{SourceIPResolver: source})
	if err != nil {
		t.Fatal(err)
	}
	api := New(f.pool, f.service, Config{CookieSecure: false, APIKeyPepper: bytes.Repeat([]byte{8}, 32), AccountLoginHandlerFactory: func() (http.Handler, error) { return handler, nil }})
	if err := api.InitializationError(); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(api.Handler())
	t.Cleanup(server.Close)
	path := metadataUserPath(user) + "/login-security?tenant_scope_id=" + user["scope_id"].(string)
	f.request(t, "PUT", path, "http-email-policy", map[string]any{"expected_revision": 0, "login_verification": "email", "login_allowlist": []string{}}, 200)
	login := map[string]any{"username": user["username"], "password": tenantPassword}
	request := func(path, key string, body any, status int) map[string]any {
		t.Helper()
		response := identityRequest(t, server.Client(), "POST", server.URL+path, body, "", key, "http-security-"+key)
		defer response.Body.Close()
		var decoded map[string]any
		decodeResponse(t, response, status, &decoded)
		if status != 200 && len(response.Cookies()) != 0 {
			t.Fatal("failed challenge flow emitted session cookie")
		}
		return decoded
	}
	required := request("/v1/auth/login", "missing-proof", login, 401)
	params := required["error"].(map[string]any)["params"].(map[string]any)
	if params["channel"] != "email" || params["scope_id"] != user["scope_id"] || capture.calls != 0 {
		t.Fatal("missing proof response sent notification or selected wrong scope")
	}
	created := request("/v1/auth/login-challenges", "http-issue", login, 202)["data"].(map[string]any)
	if capture.calls != 1 {
		t.Fatal("real sender was not captured")
	}
	login["login_challenge"] = map[string]any{"challenge_id": created["challenge_id"], "otp": capture.otp}
	request("/v1/auth/login", "", login, 400)
	wrong := cloneBody(login)
	wrong["login_challenge"] = map[string]any{"challenge_id": created["challenge_id"], "otp": "invalid"}
	request("/v1/auth/login", "http-malformed-proof", wrong, 400)
	success := request("/v1/auth/login", "http-proof", login, 200)
	if success["access_token"] == "" || success["principal"].(map[string]any)["scope_id"] != user["scope_id"] {
		t.Fatal("combined login did not create selected tenant session")
	}
	request("/v1/auth/login", "http-replay", login, 401)
	var sessions, receipts int
	if err := f.pool.QueryRow(t.Context(), `SELECT (SELECT count(*) FROM auth_sessions WHERE user_id=$1),(SELECT count(*) FROM account_login_challenge_verify_receipts_197 WHERE challenge_id=$2 AND outcome='consumed')`, user["id"], created["challenge_id"]).Scan(&sessions, &receipts); err != nil || sessions != 1 || receipts != 1 {
		t.Fatalf("session/consumption=%d/%d err=%v", sessions, receipts, err)
	}
}
