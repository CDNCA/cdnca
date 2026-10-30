//go:build integration

package httpapi

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/entitlement"
	"github.com/cdnca/cdnca/services/control-api/internal/controlupgrade"
	"github.com/cdnca/cdnca/services/control-api/internal/entitlementguard"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/google/uuid"
)

func TestMaintenanceUpgradeStatusHTTPReadOnlyScopeAndConfirmedInventory(t *testing.T) {
	pool := isolatedTestPool(t)
	now := time.Now().UTC().Truncate(time.Second)
	public, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	signer := controlUpgradeTestSigner{id: "maintenance-read-key", private: private}
	verifyUntil := now.Add(24 * time.Hour)
	trust, err := entitlementguard.NewTrustStore([]entitlementguard.VerificationKey{{KeyID: signer.id, PublicKey: public,
		NotBefore: now.Add(-24 * time.Hour), SignUntil: &verifyUntil, VerifyUntil: &verifyUntil}})
	if err != nil {
		t.Fatal(err)
	}
	hash, err := identity.HashPassword(testPassword)
	if err != nil {
		t.Fatal(err)
	}
	store := identity.NewStore(pool)
	owner, err := store.BootstrapPlatformUser(t.Context(), "maintenance-owner", "Maintenance Owner", hash, "maintenance-bootstrap")
	if err != nil {
		t.Fatal(err)
	}
	insertTestUser(t, pool, owner.ScopeID, "maintenance-viewer", "Maintenance Viewer", hash, "active")
	insertControlUpgradeTenantUser(t, pool, "maintenance-tenant", hash)
	tokens, err := identity.NewTokenManager("maintenance-status-test-secret-32-bytes", 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	identityService, err := identity.NewService(store, tokens, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	api := New(pool, identityService, Config{EntitlementTrust: trust, Now: func() time.Time { return now },
		APIKeyPepper:              bytes.Repeat([]byte{0x63}, 32),
		MaintenanceUpgradeRuntime: controlupgrade.MaintenanceRuntime{CurrentVersion: "2.4.1", ConfiguredVersion: "2.9.0", ProtocolVersion: 1},
	})
	if api.initializationErr != nil {
		t.Fatal(api.initializationErr)
	}
	server := httptest.NewServer(api.Handler())
	t.Cleanup(server.Close)
	client := server.Client()
	admin, _ := loginOK(t, client, server.URL, "maintenance-owner")
	viewer, _ := loginOK(t, client, server.URL, "maintenance-viewer")
	tenant, _ := loginOK(t, client, server.URL, "maintenance-tenant")
	get := func(token, query string, want int) controlupgrade.MaintenanceStatus {
		t.Helper()
		request, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, server.URL+"/v1/admin/maintenance-upgrade-status"+query, nil)
		if token != "" {
			request.Header.Set("Authorization", "Bearer "+token)
		}
		response, err := client.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		if response.StatusCode != want {
			t.Fatalf("status=%d want=%d", response.StatusCode, want)
		}
		var body struct {
			Data controlupgrade.MaintenanceStatus `json:"data"`
		}
		if want == http.StatusOK {
			if response.Header.Get("Cache-Control") != "no-store" {
				t.Fatal("status may be cached")
			}
			if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
		}
		return body.Data
	}
	get("", "", http.StatusUnauthorized)
	get(viewer.AccessToken, "", http.StatusForbidden)
	get(tenant.AccessToken, "", http.StatusForbidden)
	get(admin.AccessToken, "?state=completed", http.StatusBadRequest)
	missingLease := get(admin.AccessToken, "", http.StatusOK)
	if missingLease.Control.CurrentVersion == nil || *missingLease.Control.CurrentVersion != "2.4.1" ||
		missingLease.Control.ConfiguredVersionMatches == nil || *missingLease.Control.ConfiguredVersionMatches ||
		missingLease.Control.Authorization.State != "unavailable" || missingLease.Control.Candidate.Version != nil {
		t.Fatalf("process and authorization facts = %+v", missingLease.Control)
	}
	leaseBody := controlUpgradeLease(now, 1, now.Add(time.Hour), now.Add(2*time.Hour))
	leaseBody.CustomerID, leaseBody.InstallationID, leaseBody.LicenseID = uuid.NewString(), uuid.NewString(), uuid.NewString()
	leaseBody.Version.Max = "3.0.0"
	keyset, err := json.Marshal(map[string]any{"schema": "cdnca.signing-keyset/v2", "active_key_id": signer.id,
		"keys": []map[string]any{{"key_id": signer.id, "algorithm": "Ed25519", "public_key": base64.RawURLEncoding.EncodeToString(public),
			"status": "active", "not_before": now.Add(-24 * time.Hour), "sign_until": verifyUntil, "verify_until": verifyUntil}}, "rotations": []any{}})
	if err != nil {
		t.Fatal(err)
	}
	keysetDigest := sha256.Sum256(keyset)
	if _, err := pool.Exec(t.Context(), `INSERT INTO entitlement_signing_keyset_lkg(singleton,schema_version,etag,active_key_id,chain_depth,payload,payload_sha256,accepted_at,updated_at)
		VALUES(true,'cdnca.signing-keyset/v2',$1,$2,1,$3,$4,$5,$5)`, `"`+base64.RawURLEncoding.EncodeToString(keysetDigest[:])+`"`, signer.id, keyset, keysetDigest[:], now); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO entitlement_signing_keyset_current_keys(key_id,public_key,status,not_before,sign_until,verify_until,keyset_payload_sha256,accepted_at)
		VALUES($1,$2,'active',$3,$4,$4,$5,$6)`, signer.id, public, now.Add(-24*time.Hour), verifyUntil, keysetDigest[:], now); err != nil {
		t.Fatal(err)
	}
	revocations, err := entitlement.SignRevocationSet(t.Context(), entitlement.RevocationSet{
		Schema: entitlement.RevocationSetSchemaV2, Audience: entitlement.RevocationSetAudience,
		CustomerID: leaseBody.CustomerID, InstallationID: leaseBody.InstallationID, LicenseID: leaseBody.LicenseID,
		Revision: 1, IssuedAt: now.Unix(), ExpiresAt: now.Add(entitlement.RevocationSetWindow).Unix(), RevokedSerials: []uint64{},
	}, signer, entitlement.RevocationKeyWindow{NotBefore: now.Add(-24 * time.Hour), SignUntil: &verifyUntil, VerifyUntil: &verifyUntil})
	if err != nil {
		t.Fatal(err)
	}
	revocationArtifact, err := revocations.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := entitlementguard.NewRevocationService(pool, trust).Accept(t.Context(), revocationArtifact, now); err != nil {
		t.Fatal(err)
	}
	lease, err := entitlement.Sign(t.Context(), leaseBody, signer)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := entitlementguard.NewService(pool, trust).Install(t.Context(), entitlementguard.InstallBundle{InstallationID: lease.Lease.InstallationID, SignedLease: lease}, now); err != nil {
		t.Fatal(err)
	}
	var before int
	if err := pool.QueryRow(t.Context(), "SELECT count(*) FROM audit_events").Scan(&before); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		status := get(admin.AccessToken, "", http.StatusOK)
		if status.Control.Authorization.State != "valid" || status.Control.Candidate.Reason != "candidate_service_unconfigured" || status.Control.Runtime.Ready {
			t.Fatalf("status = %+v", status)
		}
	}
	var after, plans, checks int
	if err := pool.QueryRow(t.Context(), "SELECT count(*) FROM audit_events").Scan(&after); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(t.Context(), "SELECT count(*) FROM control_upgrade_rollout_plans").Scan(&plans); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(t.Context(), "SELECT count(*) FROM control_upgrade_check_requests").Scan(&checks); err != nil {
		t.Fatal(err)
	}
	if before != after || plans != 0 || checks != 0 {
		t.Fatalf("GET wrote audit/plans/checks %d %d %d %d", before, after, plans, checks)
	}
	query := url.Values{}
	var last string
	for index := range 101 {
		id := uuid.NewString()
		insertPresenceNode(t, pool, owner.ScopeID, owner.UserID, uuid.MustParse(id), int64(index+1), id, now)
		if index < 100 {
			query.Add("node_id", id)
		} else {
			last = id
		}
	}
	status := get(admin.AccessToken, "?"+query.Encode(), http.StatusOK)
	if len(status.Nodes) != 100 {
		t.Fatalf("node count=%d", len(status.Nodes))
	}
	for _, node := range status.Nodes {
		if node.CurrentVersion != nil || node.Eligible || node.Reason != "version_unavailable" {
			t.Fatalf("unconfirmed node = %+v", node)
		}
	}
	status = get(admin.AccessToken, "?node_id="+last, http.StatusOK)
	if len(status.Nodes) != 1 || status.Nodes[0].NodeID != last {
		t.Fatal("101st node missing")
	}
	get(admin.AccessToken, "?node_id="+uuid.NewString(), http.StatusNotFound)
	query.Add("node_id", last)
	get(admin.AccessToken, "?"+query.Encode(), http.StatusBadRequest)
	version, candidateCalls := "2.4.1", 0
	insertConfirmedPresence(t, pool, uuid.MustParse(last), now, &version)
	api.maintenanceUpgradeRuntime.Candidates = maintenanceHTTPReader(func(ctx context.Context, component, current string, protocol int) (controlupgrade.MaintenanceCandidate, error) {
		candidateCalls++
		if component != "control-api" || current != "2.4.1" || protocol != 1 {
			t.Error("unconfirmed node capabilities contacted upstream")
		}
		target, expiry := "2.5.0", now.Add(time.Minute)
		return controlupgrade.MaintenanceCandidate{State: "available", Reason: "upgrade_available", Version: &target, ExpiresAt: &expiry, Channel: "stable"}, nil
	})
	for _, reason := range []string{"node_capability_unavailable", "node_offline", "node_disabled"} {
		if reason == "node_offline" {
			if _, err := pool.Exec(t.Context(), `UPDATE node_presence SET last_seen_at=$2 WHERE node_id=$1`, last, now.Add(-time.Minute)); err != nil {
				t.Fatal(err)
			}
		}
		if reason == "node_disabled" {
			if _, err := pool.Exec(t.Context(), `UPDATE nodes SET admin_state='disabled' WHERE id=$1`, last); err != nil {
				t.Fatal(err)
			}
		}
		status = get(admin.AccessToken, "?node_id="+last, http.StatusOK)
		if status.Control.Candidate.State != "available" || status.Control.Candidate.Version == nil || *status.Control.Candidate.Version != "2.5.0" || status.Control.Runtime.Ready ||
			status.Nodes[0].Reason != reason || status.Nodes[0].Eligible || status.Nodes[0].Candidate.Version != nil {
			t.Fatalf("candidate/node facts: %+v", status)
		}
	}
	if candidateCalls != 3 {
		t.Fatalf("candidate query count=%d", candidateCalls)
	}
	if _, err := pool.Exec(t.Context(), `UPDATE memberships SET status='suspended' WHERE scope_id=$1 AND user_id=$2`, owner.ScopeID, owner.UserID); err != nil {
		t.Fatal(err)
	}
	get(admin.AccessToken, "", http.StatusUnauthorized)
}

type maintenanceHTTPReader func(context.Context, string, string, int) (controlupgrade.MaintenanceCandidate, error)

func (read maintenanceHTTPReader) ReadCandidate(ctx context.Context, component, version string, protocol int) (controlupgrade.MaintenanceCandidate, error) {
	return read(ctx, component, version, protocol)
}
