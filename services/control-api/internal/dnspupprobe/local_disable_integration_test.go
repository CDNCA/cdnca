package dnspupprobe

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/entitlement"
	"github.com/cdnca/cdnca/services/control-api/internal/entitlementguard"
	"github.com/cdnca/cdnca/services/control-api/internal/entitlementguard/guardtest"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type probeLeaseSigner struct{ private ed25519.PrivateKey }

func (probeLeaseSigner) KeyID() string { return "dnspup-local-disable-key" }

func (signer probeLeaseSigner) Sign(_ context.Context, payload []byte) ([]byte, error) {
	return ed25519.Sign(signer.private, payload), nil
}

// with the real lease guard, stopping dnspup 拨测 on this
// controller (its licence and lease unchanged) makes the probe API answer
// entitlement_feature_denied and the plugin probe API not installed; enabling
// it again restores both.
func TestLocalDisableStopsDNSPupProbing(t *testing.T) {
	f := newServiceFixture(t)
	ctx := t.Context()
	// The revocation LKG is checked against the database clock: run on it (the
	// fixture's sessions, seeded at its fixed clock, stay valid for 30 days).
	if err := f.pool.QueryRow(ctx, `SELECT date_trunc('second',clock_timestamp())`).Scan(&f.now); err != nil {
		t.Fatal(err)
	}
	f.now = f.now.UTC()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	until := f.now.Add(24 * time.Hour)
	trust, err := entitlementguard.NewTrustStore([]entitlementguard.VerificationKey{{KeyID: "dnspup-local-disable-key",
		PublicKey: public, NotBefore: f.now.Add(-24 * time.Hour), SignUntil: &until, VerifyUntil: &until}})
	if err != nil {
		t.Fatal(err)
	}
	lease := entitlement.Lease{Schema: entitlement.SchemaV1, Audience: entitlement.ControlAudience,
		CustomerID: "bbbbbbbb-1111-4111-8111-111111111111", InstallationID: "bbbbbbbb-2222-4222-8222-222222222222",
		LicenseID: "bbbbbbbb-3333-4333-8333-333333333333", Serial: 1, NotBefore: f.now.Add(-time.Hour).Unix(),
		ExpiresAt: f.now.Add(time.Hour).Unix(), GraceUntil: f.now.Add(2 * time.Hour).Unix(),
		Version:  entitlement.VersionRange{Channel: "stable", Min: "0.1.0", Max: "1.0.0"},
		Features: []entitlement.Feature{{Code: Feature}, {Code: entitlementguard.FeatureSitesManage}},
		Quotas:   []entitlement.Quota{{Code: entitlementguard.QuotaDomainsCount, Limit: 10}},
	}
	guardtest.AcceptRevocation(t, f.pool, trust, probeLeaseSigner{private}, lease, f.now)
	signed, err := entitlement.Sign(ctx, lease, probeLeaseSigner{private})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := entitlementguard.NewService(f.pool, trust).Install(ctx, entitlementguard.InstallBundle{
		InstallationID: lease.InstallationID, SignedLease: signed}, f.now); err != nil {
		t.Fatal(err)
	}
	f.service.config.Features = entitlementguard.NewGuard(f.pool, func() time.Time { return f.now }, trust)
	handler, err := NewHandler(f.service, func(context.Context, string) (identity.AuthenticatedSession, error) {
		return identity.AuthenticatedSession{SessionID: f.admin.SessionID, Principal: identity.Principal{
			UserID: f.admin.UserID, ScopeID: f.admin.ScopeID, ScopeKind: "platform", Permissions: []string{PermissionManage}}}, nil
	}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.service.UpdateSettings(ctx, f.admin, "s1", f.input(true, ptr(f.fake.Secret))); err != nil {
		t.Fatalf("enable while licensed: %v", err)
	}
	probeTest := func(key string) (int, string) {
		t.Helper()
		body, _ := json.Marshal(f.input(false, nil))
		request := httptest.NewRequest(http.MethodPost, "/v1/admin/probe-dnspup/tests", strings.NewReader(string(body)))
		request.Header.Set("Authorization", "Bearer session")
		request.Header.Set("Idempotency-Key", key)
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		return response.Code, response.Body.String()
	}
	pluginReason := func() string {
		t.Helper()
		var reason string
		if err := pgx.BeginFunc(ctx, f.pool, func(tx pgx.Tx) error {
			_, _, why, _, err := f.service.availability(ctx, tx)
			reason = why
			return err
		}); err != nil {
			t.Fatal(err)
		}
		return reason
	}
	if code, body := probeTest("t1"); code != http.StatusOK || !strings.Contains(body, `"ok":true`) {
		t.Fatalf("probe test while enabled: %d %s", code, body)
	}
	if reason := pluginReason(); reason != "" {
		t.Fatalf("plugin probe availability while enabled: %q", reason)
	}

	stops := entitlementguard.NewLocalDisableStore(f.pool, func() time.Time { return f.now }, nil)
	actor := entitlementguard.LocalDisableActor{UserID: f.admin.UserID, ScopeID: f.admin.ScopeID}
	if _, err := stops.Disable(ctx, actor, "stop-"+uuid.NewString(), entitlementguard.LocalDisableInput{
		PluginID: "io.cdnca.probe-dnspup", FeatureCode: Feature}); err != nil {
		t.Fatal(err)
	}
	if code, body := probeTest("t2"); code != http.StatusForbidden || !strings.Contains(body, "entitlement_feature_denied") {
		t.Fatalf("probe test after the local stop: %d %s", code, body)
	}
	if reason := pluginReason(); reason != ReasonNotInstalled {
		t.Fatalf("plugin probe availability after the local stop: %q", reason)
	}
	if status, err := f.service.Status(ctx, f.admin); err != nil || status.Licensed || status.Active {
		t.Fatalf("status after the local stop: %+v %v", status, err)
	}
	if runtime := f.service.Runtime(ctx); runtime.Probe != nil {
		t.Fatal("stopped dnspup still offered to the probe runtime")
	}

	if _, err := stops.Enable(ctx, actor, "enable-"+uuid.NewString(), "io.cdnca.probe-dnspup"); err != nil {
		t.Fatal(err)
	}
	if code, body := probeTest("t3"); code != http.StatusOK {
		t.Fatalf("probe test after enabling again: %d %s", code, body)
	}
	if status, err := f.service.Status(ctx, f.admin); err != nil || !status.Licensed || !status.Active {
		t.Fatalf("status after enabling again: %+v %v", status, err)
	}
}
