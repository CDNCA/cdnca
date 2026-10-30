package nodeidentity

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"
)

// siteRuntimeV2Fixture is the shared site runtime v2 contract fixture with
// streams (api/schemas/edge/v2/testdata), decoded for mutation.
func siteRuntimeV2Fixture(t *testing.T) map[string]any {
	t.Helper()
	raw, err := os.ReadFile("../../../../api/schemas/edge/v2/testdata/site-runtime-capability-v4-streams.json")
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := json.Unmarshal(raw, &document); err != nil {
		t.Fatal(err)
	}
	return document
}

func encodeSnapshot(t *testing.T, value any) ([]byte, []byte) {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(raw)
	return raw, digest[:]
}

func TestTelemetrySiteRuntimeV2Binds(t *testing.T) {
	document := siteRuntimeV2Fixture(t)
	scopeID := uuid.MustParse(document["configuration_scope_id"].(string))
	configID := uuid.MustParse(document["config_version_id"].(string))
	tenantID := uuid.MustParse(document["streams"].(map[string]any)["tenant_id"].(string))
	site := document["sites"].([]any)[0].(map[string]any)
	siteID := uuid.MustParse(site["id"].(string))
	subscriptionID := uuid.MustParse("99999999-9999-4999-8999-999999999999")

	raw, digest := encodeSnapshot(t, document)
	v2, listeners, unverified, err := parseTelemetrySnapshot(raw, digest, scopeID, tenantID, configID,
		telemetrySiteSubscriptions{sites: map[uuid.UUID]uuid.UUID{siteID: subscriptionID}, recorded: true})
	if err != nil || len(unverified) != 0 {
		t.Fatalf("site runtime v2 snapshot: %v", err)
	}
	if len(v2) != 3 || v2[0] != (TelemetrySiteScope{SiteID: siteID, TenantID: tenantID, ConfigurationScopeID: scopeID,
		ConfigVersionID: configID, PackageSubscriptionID: subscriptionID}) {
		t.Fatalf("bindings = %#v", v2)
	}
	if len(listeners) != 2 || listeners[0].ListenPort != 18090 || listeners[1].ListenPort != 18443 ||
		listeners[0].Domain != "route.example.test" {
		t.Fatalf("listeners = %#v", listeners)
	}

	// Realtime settlement reads the v2 roster too.
	published, err := PublishedTelemetryListeners(raw, digest, scopeID, tenantID, configID)
	if err != nil || len(published) != 2 {
		t.Fatalf("PublishedTelemetryListeners = %#v, %v", published, err)
	}
}

func TestTelemetrySiteRuntimeV2PackageLimitCarriesTheSubscription(t *testing.T) {
	document := siteRuntimeV2Fixture(t)
	scopeID := uuid.MustParse(document["configuration_scope_id"].(string))
	configID := uuid.MustParse(document["config_version_id"].(string))
	tenantID := uuid.MustParse(document["streams"].(map[string]any)["tenant_id"].(string))
	site := document["sites"].([]any)[0].(map[string]any)
	limited := "88888888-8888-4888-8888-888888888888"
	site["package_limits"] = map[string]any{"subscription_id": limited, "connections": 10}
	raw, digest := encodeSnapshot(t, document)
	siteID := uuid.MustParse(site["id"].(string))
	bindings, _, unverified, err := parseTelemetrySnapshot(raw, digest, scopeID, tenantID, configID, telemetrySiteSubscriptions{})
	if err != nil || len(unverified) != 0 || len(bindings) != 3 || bindings[0].PackageSubscriptionID.String() != limited {
		t.Fatalf("bindings %#v unverified %v err %v", bindings, unverified, err)
	}
	// A recorded subscription that disagrees with the document is refused.
	if _, _, _, err := parseTelemetrySnapshot(raw, digest, scopeID, tenantID, configID,
		telemetrySiteSubscriptions{sites: map[uuid.UUID]uuid.UUID{siteID: uuid.New()}, recorded: true}); !errors.Is(err, ErrPersistence) {
		t.Fatalf("inconsistent subscription err = %v", err)
	}
	// Before migration 295 the package monitor bindings may disagree or be
	// missing; the document's limit wins and nothing fails.
	bindings, _, _, err = parseTelemetrySnapshot(raw, digest, scopeID, tenantID, configID,
		telemetrySiteSubscriptions{sites: map[uuid.UUID]uuid.UUID{siteID: uuid.New()}})
	if err != nil || bindings[0].PackageSubscriptionID.String() != limited {
		t.Fatalf("legacy bindings %#v err %v", bindings, err)
	}
}

// TestTelemetrySiteRuntimeV2LegacyVersionsDegrade: a v2 version published
// before migration 295 whose sites the package monitor bindings do not cover
// still binds, without a subscription, and names the sites; a version
// published since must record every site.
func TestTelemetrySiteRuntimeV2LegacyVersionsDegrade(t *testing.T) {
	document := siteRuntimeV2Fixture(t)
	scopeID := uuid.MustParse(document["configuration_scope_id"].(string))
	configID := uuid.MustParse(document["config_version_id"].(string))
	tenantID := uuid.MustParse(document["streams"].(map[string]any)["tenant_id"].(string))
	siteID := uuid.MustParse(document["sites"].([]any)[0].(map[string]any)["id"].(string))
	raw, digest := encodeSnapshot(t, document)
	bindings, _, unverified, err := parseTelemetrySnapshot(raw, digest, scopeID, tenantID, configID, telemetrySiteSubscriptions{})
	if err != nil || len(bindings) != 3 || bindings[0].PackageSubscriptionID != uuid.Nil ||
		len(unverified) != 1 || unverified[0] != siteID {
		t.Fatalf("legacy version bindings %#v unverified %v err %v", bindings, unverified, err)
	}
	legacy := uuid.New()
	bindings, _, unverified, err = parseTelemetrySnapshot(raw, digest, scopeID, tenantID, configID,
		telemetrySiteSubscriptions{sites: map[uuid.UUID]uuid.UUID{siteID: legacy}})
	if err != nil || len(unverified) != 0 || bindings[0].PackageSubscriptionID != legacy {
		t.Fatalf("legacy monitor binding %#v unverified %v err %v", bindings, unverified, err)
	}
	if _, _, _, err := parseTelemetrySnapshot(raw, digest, scopeID, tenantID, configID,
		telemetrySiteSubscriptions{sites: map[uuid.UUID]uuid.UUID{}, recorded: true}); !errors.Is(err, ErrPersistence) {
		t.Fatalf("recorded version missing a site err = %v", err)
	}
}

func TestTelemetrySnapshotRefusalsNameTheirReason(t *testing.T) {
	base := siteRuntimeV2Fixture(t)
	scopeID := uuid.MustParse(base["configuration_scope_id"].(string))
	configID := uuid.MustParse(base["config_version_id"].(string))
	tenantID := uuid.MustParse(base["streams"].(map[string]any)["tenant_id"].(string))
	for name, c := range map[string]struct {
		mutate func(map[string]any)
		reason string
	}{
		"unknown schema":       {func(d map[string]any) { d["schema"] = "cdnca.edge.site-runtime/v3" }, `unknown canonical snapshot schema "cdnca.edge.site-runtime/v3"`},
		"other scope":          {func(d map[string]any) { d["configuration_scope_id"] = uuid.NewString() }, "identity does not match"},
		"other config version": {func(d map[string]any) { d["config_version_id"] = uuid.NewString() }, "identity does not match"},
		"duplicated site": {func(d map[string]any) {
			sites := d["sites"].([]any)
			d["sites"] = append(sites, sites[0])
		}, "site is duplicated"},
		"invalid port": {func(d map[string]any) {
			d["sites"].([]any)[0].(map[string]any)["listeners"].([]any)[0].(map[string]any)["port"] = 0
		}, "listener port is invalid"},
		// 多域名站点合法（G8-a 缺陷 3），没有域名才是无效站点。
		"no domains": {func(d map[string]any) {
			d["sites"].([]any)[0].(map[string]any)["domains"] = []any{}
		}, "site is invalid"},
		"streams of another tenant": {func(d map[string]any) {
			d["streams"].(map[string]any)["tenant_id"] = uuid.NewString()
		}, "streams name another tenant"},
	} {
		document := siteRuntimeV2Fixture(t)
		c.mutate(document)
		raw, digest := encodeSnapshot(t, document)
		_, _, _, err := parseTelemetrySnapshot(raw, digest, scopeID, tenantID, configID, telemetrySiteSubscriptions{})
		var snapshotErr *TelemetrySnapshotError
		if !errors.Is(err, ErrPersistence) || !errors.As(err, &snapshotErr) || !strings.Contains(snapshotErr.Reason, c.reason) ||
			snapshotErr.ConfigVersionID != configID {
			t.Errorf("%s: err = %v, want reason %q", name, err, c.reason)
		}
	}
	raw, digest := encodeSnapshot(t, base)
	digest[0] ^= 1
	if _, _, _, err := parseTelemetrySnapshot(raw, digest, scopeID, tenantID, configID, telemetrySiteSubscriptions{}); telemetrySnapshotReason(err) != "canonical snapshot digest does not match" {
		t.Fatalf("digest mismatch err = %v", err)
	}
}

// telemetryV2SnapshotForTest is a minimal published site runtime v2 document
// with one plain HTTP listener per site (the fields telemetry reads).
func telemetryV2SnapshotForTest(t *testing.T, scopeID, configVersionID uuid.UUID, siteIDs []uuid.UUID) []byte {
	t.Helper()
	sites := make([]map[string]any, len(siteIDs))
	for index, siteID := range siteIDs {
		sites[index] = map[string]any{
			"id": siteID.String(), "revision": 1, "domains": []string{"telemetry-" + siteID.String()[:8] + ".example.test"},
			"listeners": []map[string]any{{"id": "http", "position": 0, "address_family": "ipv4", "port": 80,
				"protocols": []string{"http1"}}},
		}
	}
	raw, err := json.Marshal(map[string]any{
		"schema": telemetrySnapshotSchemaV2, "configuration_scope_id": scopeID.String(), "source_revision": 1,
		"config_version_id": configVersionID.String(), "sites": sites,
	})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
