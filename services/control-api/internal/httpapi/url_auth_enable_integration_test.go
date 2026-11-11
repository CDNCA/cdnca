package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/dnsacme"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/urlauthpolicy"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// recordingURLAuthPublisher stands in for the edge publication runtime
// (urlauthpolicy.ArtifactPublisher): it records the enabled policy versions
// a write delivered in its transaction.
type recordingURLAuthPublisher struct {
	mu        sync.Mutex
	published []urlauthpolicy.Policy
}

func (publisher *recordingURLAuthPublisher) PublishURLAuthPolicyTx(_ context.Context, _ pgx.Tx, _ uuid.UUID,
	item urlauthpolicy.Policy, _ string) error {
	publisher.mu.Lock()
	defer publisher.mu.Unlock()
	publisher.published = append(publisher.published, item)
	return nil
}

func (publisher *recordingURLAuthPublisher) count() int {
	publisher.mu.Lock()
	defer publisher.mu.Unlock()
	return len(publisher.published)
}

// enabling a policy needs the edge publication runtime (the
// policy reaches nodes declaring URL_AUTH); without it creating or enabling
// an enabled policy answers url_auth_unavailable and disabled writes keep
// working. With it every enabled write delivers the version, disabled ones
// do not, and the console's enable/disable actions are mounted.
func TestURLAuthPolicyEnableNeedsEdgePublication(t *testing.T) {
	pool := isolatedTestPool(t)
	passwordHash, err := identity.HashPassword(testPassword)
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	identityStore := identity.NewStore(pool)
	if _, err := identityStore.BootstrapPlatformUser(context.Background(), "urlauthready", "URL Auth Ready", passwordHash, "url-auth-ready-bootstrap"); err != nil {
		t.Fatalf("BootstrapPlatformUser: %v", err)
	}
	tenant := insertURLAuthTenant(t, pool, "URL Auth Ready Tenant", "urlauth-ready", passwordHash)
	site := insertURLAuthSite(t, pool, tenant, "auth-ready.example")
	tokens, err := identity.NewTokenManager("url-auth-ready-integration-secret-32b", 5*time.Minute)
	if err != nil {
		t.Fatalf("NewTokenManager: %v", err)
	}
	identityService, err := identity.NewService(identityStore, tokens, 24*time.Hour)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	cipher, err := dnsacme.NewAESGCMCredentialCipher("url-auth-kek-v1", bytes.Repeat([]byte{17}, 32))
	if err != nil {
		t.Fatalf("NewAESGCMCredentialCipher: %v", err)
	}
	publisher := &recordingURLAuthPublisher{}
	base := Config{APIKeyPepper: bytes.Repeat([]byte{0x52}, 32), DNSCredentialCipher: cipher}
	off := httptest.NewServer(New(pool, identityService, base).Handler())
	t.Cleanup(off.Close)
	ready := base
	ready.URLAuthPublisher = publisher
	server := httptest.NewServer(New(pool, identityService, ready).Handler())
	t.Cleanup(server.Close)
	client := server.Client()
	auth, _ := loginOK(t, client, server.URL, "urlauthready")
	tenantAuth := loginForScope(t, client, server.URL, tenant.username, tenant.scopeID)

	assertUnavailable := func(t *testing.T, response *http.Response) {
		t.Helper()
		defer response.Body.Close()
		var envelope testErrorEnvelope
		raw, _ := io.ReadAll(response.Body)
		if response.StatusCode != http.StatusUnprocessableEntity || json.Unmarshal(raw, &envelope) != nil || envelope.Error.Code != "url_auth_unavailable" || envelope.Error.RequestID == "" {
			t.Fatalf("response %d %s, want 422 url_auth_unavailable", response.StatusCode, raw)
		}
		if !strings.Contains(string(raw), "URL 鉴权尚未在节点生效，暂不可用") {
			t.Fatalf("message missing from %s", raw)
		}
	}
	readEnabled := func(t *testing.T, id uuid.UUID) bool {
		t.Helper()
		var enabled bool
		if err := pool.QueryRow(context.Background(), `SELECT enabled FROM url_auth_policies WHERE id=$1`, id).Scan(&enabled); err != nil {
			t.Fatalf("read enabled: %v", err)
		}
		return enabled
	}
	action := func(t *testing.T, base, id, name, key string, revision int64) *http.Response {
		t.Helper()
		return siteRequest(t, client, http.MethodPost, base+"/v1/url-auth-policies/"+id+"/"+name, nil, tenantAuth.AccessToken, key, quoteVersion(revision))
	}

	enabledFields := createURLAuthPolicyRequest{TargetScopeID: tenant.scopeID.String(), OwnerID: tenant.userID.String(), PolicyFields: validURLAuthFields(site, "Ready")}
	t.Run("without edge publication an enabled policy is refused", func(t *testing.T) {
		assertUnavailable(t, siteRequest(t, client, http.MethodPost, off.URL+"/v1/url-auth-policies", enabledFields, auth.AccessToken, "url-auth-ready-off", ""))
	})

	disabledFields := enabledFields
	disabledFields.PolicyFields.Enabled = false
	seeded := createURLAuthPolicy(t, client, off.URL, auth.AccessToken, "url-auth-ready-disabled", disabledFields).Policy
	id := seeded.ID.String()

	t.Run("without edge publication enable is refused and leaves the row disabled", func(t *testing.T) {
		assertUnavailable(t, action(t, off.URL, id, "enable", "url-auth-ready-enable-off", seeded.Revision))
		if readEnabled(t, seeded.ID) {
			t.Fatal("policy enabled without edge publication")
		}
	})

	t.Run("with edge publication enable and disable work", func(t *testing.T) {
		response := action(t, server.URL, id, "enable", "url-auth-ready-enable", seeded.Revision)
		var enabled urlauthpolicy.WriteResult
		decodeResponse(t, response, http.StatusOK, &enabled)
		response.Body.Close()
		if !enabled.Policy.Enabled || !readEnabled(t, seeded.ID) || publisher.count() != 1 {
			t.Fatalf("enabled=%#v published=%d", enabled.Policy, publisher.count())
		}
		response = action(t, server.URL, id, "disable", "url-auth-ready-disable", enabled.Policy.Revision)
		var disabled urlauthpolicy.WriteResult
		decodeResponse(t, response, http.StatusOK, &disabled)
		response.Body.Close()
		if disabled.Policy.Enabled || readEnabled(t, seeded.ID) || publisher.count() != 1 {
			t.Fatalf("disabled=%#v published=%d", disabled.Policy, publisher.count())
		}
	})
}
