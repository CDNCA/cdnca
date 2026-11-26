package edgepublish

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/libs/edgeconfig/siteobject"
	"github.com/cdnca/cdnca/services/control-api/internal/packageaddon"
	"github.com/google/uuid"
)

// only a refusal the scope's own facts decide
// redelivers the node settings; an outcome nobody decided (a lost
// connection, a conflict, a persistence error) is retried as before, and a
// node lacking a capability or a denied lease or permission publishes nothing.
func TestNodeSettingsContentRefusal(t *testing.T) {
	for err, want := range map[error]string{
		&SiteConfigInvalidError{SiteID: uuid.New(), Reason: "x"}:            AutomaticFailureSiteConfigInvalid,
		fmt.Errorf("wrapped: %w", packageaddon.ErrSubscriptionInactive):     AutomaticFailurePackageSubscriptionInactive,
		packageaddon.ErrQuotaExceeded:                                       AutomaticFailurePackageQuotaExceeded,
		packageaddon.ErrFeatureDenied:                                       AutomaticFailurePackageFeatureDenied,
		&ModuleNotEntitledError{Modules: []string{"module.ipintel.dnspup"}}: AutomaticFailureModuleNotEntitled,
		ErrSiteL2Unavailable:                                                AutomaticFailureSiteL2Unavailable,
		&CRSOutOfProfileError{}:                                             AutomaticFailureRulePackOutOfProfile,
	} {
		got, refused := NodeSettingsContentRefusal(err)
		if !refused || got != want || !NodeSettingsRefusalCode(got) {
			t.Errorf("NodeSettingsContentRefusal(%v) = %q %v, want %q", err, got, refused, want)
		}
	}
	for _, err := range []error{nil, ErrPersistence, ErrRevisionConflict, ErrIdempotencyConflict, ErrAlreadyPublished,
		context.Canceled, context.DeadlineExceeded, errors.New("connection reset"), ErrPermissionDenied, ErrEntitlementDenied,
		ErrTargetIneligible, &TargetCapabilityError{NodeID: uuid.New()}, &ChallengePolicyUnavailableError{NodeID: uuid.New()},
		&RulePackUnavailableError{NodeID: uuid.New()}, &CrossScopeConflictError{NodeID: uuid.New()}} {
		if code, refused := NodeSettingsContentRefusal(err); refused {
			t.Errorf("NodeSettingsContentRefusal(%v) = %q, want no redelivery", err, code)
		}
	}
	if NodeSettingsRefusalCode("no_target_nodes") || NodeSettingsRefusalCode("") {
		t.Error("a node refusal code passes as a content refusal")
	}
}

func TestNodeSettingsOnlyTriggers(t *testing.T) {
	for triggers, want := range map[string][2]bool{ // only, carried
		"node_storage": {true, true},
		"":             {false, false}, "node_storage,node_networks": {false, true}, "node_networks": {false, false},
		"node_storage,line_group": {false, true}, "traffic_enforcement": {false, false},
	} {
		var list []string
		if triggers != "" {
			list = strings.Split(triggers, ",")
		}
		if got := nodeSettingsOnlyTriggers(list); got != want[0] {
			t.Errorf("nodeSettingsOnlyTriggers(%q) = %v, want %v", triggers, got, want[0])
		}
		if got := nodeSettingsTriggered(list); got != want[1] {
			t.Errorf("nodeSettingsTriggered(%q) = %v, want %v", triggers, got, want[1])
		}
	}
	for id, want := range map[string]bool{
		NodeSettingsRequestPrefixStorage + uuid.NewString(): true,
		"node-networks." + uuid.NewString():                 false, "node-locations.x": false, "site.update": false,
	} {
		if got := NodeSettingsOnlyRequest(id); got != want {
			t.Errorf("NodeSettingsOnlyRequest(%q) = %v, want %v", id, got, want)
		}
	}
	if key := nodeSettingsIdempotencyKey(strings.Repeat("k", 128)); !publishKeyPattern.MatchString(key) ||
		key == nodeSettingsIdempotencyKey("other") || key != nodeSettingsIdempotencyKey(strings.Repeat("k", 128)) {
		t.Fatalf("node settings idempotency key %q", key)
	}
}

// The redelivered document is the base's byte for byte apart from its
// identity; anything else (a non-canonical or foreign base) is refused.
func TestNodeSettingsDocumentChangesOnlyIdentity(t *testing.T) {
	site, err := compileForceHTTPSFact(siteFact{
		id: uuid.MustParse("018f47a2-5b9c-7d31-8a60-104c9c0b7103"), revision: 9, domain: "secure.example.test",
		httpPorts: []string{"80"}, httpsPorts: []string{"443"}, httpsEnabled: true, balance: "round_robin", failoverTries: 1,
		connectTimeoutMS: 3000, readTimeoutMS: 30000, forceHTTPS: true,
		origins: []snapshotOrigin{{Host: "192.0.2.10", Port: 80, Weight: 100}},
	})
	if err != nil {
		t.Fatal(err)
	}
	baseID, nextID := uuid.MustParse("018f47a2-5b9c-7d31-8a60-104c9c0b7102"), uuid.MustParse("018f47a2-5b9c-7d31-8a60-104c9c0b7199")
	raw, _ := json.Marshal(siteRuntimeV2Document{
		Schema: siteRuntimeV2Schema, ConfigurationScopeID: "018f47a2-5b9c-7d31-8a60-104c9c0b7101", SourceRevision: 3,
		ConfigVersionID: baseID.String(), Sites: []siteRuntimeV2Site{site},
		RequiredCapabilities: []siteRuntimeV2Capability{{"http1", 1}, {"http2", 1}, {"http3", 1}, {"ipv4", 1}, {"ipv6", 1},
			{"site_runtime", edgeconfig.MinSiteRuntimeVersion}, {"websocket", 1}},
	})
	base, _, baseCapabilities, _, err := compileSiteRuntimeV2Document(raw)
	if err != nil {
		t.Fatal(err)
	}
	next, digest, capabilities, _, err := nodeSettingsDocument(base, baseID, 3, nextID, 11)
	if err != nil {
		t.Fatal(err)
	}
	if digest != sha256Sum(next) || len(capabilities) != len(baseCapabilities) {
		t.Fatalf("digest or capabilities differ: %d vs %d", len(capabilities), len(baseCapabilities))
	}
	var before, after map[string]any
	if json.Unmarshal(base, &before) != nil || json.Unmarshal(next, &after) != nil {
		t.Fatal("documents do not decode")
	}
	if after["config_version_id"] != nextID.String() || after["source_revision"] != float64(11) {
		t.Fatalf("identity = %v / %v", after["config_version_id"], after["source_revision"])
	}
	for _, field := range []string{"config_version_id", "source_revision"} {
		delete(before, field)
		delete(after, field)
	}
	if left, _ := json.Marshal(before); !bytes.Equal(left, mustMarshal(t, after)) {
		t.Fatal("the redelivered document changed beyond its identity")
	}
	if _, _, _, _, err := nodeSettingsDocument(base, nextID, 3, nextID, 11); err == nil {
		t.Fatal("a base of another config version accepted")
	}
	if _, _, _, _, err := nodeSettingsDocument(base, baseID, 4, nextID, 11); err == nil {
		t.Fatal("a base of another source revision accepted")
	}
	if _, _, _, _, err := nodeSettingsDocument(append([]byte(" "), base...), baseID, 3, nextID, 11); err == nil {
		t.Fatal("a non-canonical base accepted")
	}

	// The root keeps everything but its identity and document digest.
	documentDigest := strings.Repeat("a", 64)
	_, root, err := siteobject.BuildV2(siteobject.BuildV2Input{
		ConfigurationScopeID: "018f47a2-5b9c-7d31-8a60-104c9c0b7101", ConfigVersionID: baseID.String(), SourceRevision: 3,
		KeyEpoch: siteObjectKeyEpoch, DocumentSHA256: documentDigest,
		RequiredCapabilities: []siteobject.Capability{{Name: "http1", APIVersion: 1}, {Name: "site_runtime", APIVersion: siteobject.DynamicRoutingSiteRuntimeVersion}},
	})
	if err != nil {
		t.Fatal(err)
	}
	rootBytes, err := siteobject.Encode(root)
	if err != nil {
		t.Fatal(err)
	}
	nextRoot, err := nodeSettingsRoot(rootBytes, baseID, 3, nextID, 11, strings.Repeat("b", 64))
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := siteobject.ParseRootV2(nextRoot)
	if err != nil || parsed.ConfigVersionID != nextID.String() || parsed.SourceRevision != 11 ||
		parsed.DocumentSHA256 != strings.Repeat("b", 64) {
		t.Fatalf("redelivered root = %+v %v", parsed, err)
	}
	parsed.ConfigVersionID, parsed.SourceRevision, parsed.DocumentSHA256 = root.ConfigVersionID, root.SourceRevision, root.DocumentSHA256
	if again, _ := siteobject.Encode(parsed); !bytes.Equal(again, rootBytes) {
		t.Fatal("the redelivered root changed beyond its identity")
	}
	if _, err := nodeSettingsRoot(rootBytes, nextID, 3, nextID, 11, documentDigest); err == nil {
		t.Fatal("a root of another config version accepted")
	}
}

func sha256Sum(value []byte) [32]byte {
	_, digest, _, _, _ := compileSiteRuntimeV2Document(value)
	return digest
}

func mustMarshal(t *testing.T, value any) []byte {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
