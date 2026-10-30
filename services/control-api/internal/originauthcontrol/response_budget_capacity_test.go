package originauthcontrol

import (
	"bytes"
	"strings"
	"testing"
)

func TestMaximumJSONBudgetCoversWorstPublicationBounds(t *testing.T) {
	pathPrefix := "/" + strings.Repeat("\"", 2046) + "/"
	config := responseBudgetRuleConfig(t, pathPrefix)
	if len(pathPrefix) != 2048 || len(strings.TrimPrefix(config.Endpoint, "https://")) != 253 ||
		len(config.Region) != 64 || len(config.EgressPolicyReference) != 128 || config.PreviousCredential == nil {
		t.Fatalf("fixture does not exercise service maxima: %+v", config)
	}

	rule, err := encodeJSON(responseBudgetPublicationRule(0, config))
	if err != nil {
		t.Fatal(err)
	}
	lastRule, err := encodeJSON(responseBudgetPublicationRule(maximumPublicationRules-1, config))
	if err != nil {
		t.Fatal(err)
	}
	if len(rule) != len(lastRule) {
		t.Fatalf("rule bytes vary by index: %d != %d", len(rule), len(lastRule))
	}
	tenantScopeID := responseBudgetUUID("tenant", 0)
	publication := Publication{
		ID:            responseBudgetUUID("publication", 0),
		TenantScopeID: tenantScopeID,
		Revision:      maxSafeRevision,
		SnapshotHash:  strings.Repeat("a", 64),
		PreviousHash:  strings.Repeat("b", 64),
		Snapshot: PublicationSnapshot{
			SchemaVersion:       publicationSchema,
			TenantScopeID:       tenantScopeID,
			PublicationRevision: maxSafeRevision,
			Rules:               []PublicationRule{},
		},
		CreatedAt: responseBudgetLatestTime(),
	}
	fixed, err := encodeJSON(publication)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(fixed, []byte(`"rules":[]`)) {
		t.Fatalf("empty publication encoding changed: %s", fixed)
	}
	serviceMaximum := len(fixed) + maximumPublicationRules*len(rule) + maximumPublicationRules - 1
	if serviceMaximum > maximumJSONBytes {
		t.Fatalf("service-valid publication upper bound = %d, maximum = %d", serviceMaximum, maximumJSONBytes)
	}

	// PublicationRule's OpenAPI maxima can be independently combined. These
	// fields contain no JSON-escaped characters, so their byte deltas are exact.
	schemaRuleMaximum := len(rule) +
		(512 - len(config.Endpoint)) +
		(63 - len(config.Bucket)) +
		(64 - len(config.Service)) +
		(len(ProviderOSS) - len(config.Provider))
	schemaMaximum := len(fixed) + maximumPublicationRules*schemaRuleMaximum + maximumPublicationRules - 1
	if schemaMaximum > maximumJSONBytes {
		t.Fatalf("schema publication upper bound = %d, maximum = %d", schemaMaximum, maximumJSONBytes)
	}
}
