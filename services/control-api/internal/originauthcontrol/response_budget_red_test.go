package originauthcontrol

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestHandlerDefaultResponseBudgetAllowsSchemaLegalRulePage(t *testing.T) {
	pathPrefix := "/" + strings.Repeat("<", 2046) + "/"
	if len(pathPrefix) != 2048 {
		t.Fatalf("path prefix bytes = %d, want 2048", len(pathPrefix))
	}
	config := responseBudgetRuleConfig(t, pathPrefix)
	items := make([]Rule, 100)
	for index := range items {
		items[index] = responseBudgetRule(index, config)
	}

	handler := &Handler{maxResponseBytes: defaultMaxResponseBytes}
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	response := httptest.NewRecorder()
	handler.writeJSON(response, request, http.StatusOK, RuleList{Items: items})

	if response.Code != http.StatusOK {
		t.Fatalf("writeJSON() status = %d, want 200 (body bytes = %d)", response.Code, response.Body.Len())
	}
	var decoded RuleList
	if err := json.NewDecoder(response.Body).Decode(&decoded); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(decoded.Items) != len(items) {
		t.Fatalf("decoded items = %d, want %d", len(decoded.Items), len(items))
	}
}

func TestMaximumResponseBudgetAllowsSchemaMaximumPublication(t *testing.T) {
	pathPrefix := "/" + strings.Repeat("a", 2046) + "/"
	if len(pathPrefix) != 2048 {
		t.Fatalf("path prefix bytes = %d, want 2048", len(pathPrefix))
	}
	config := responseBudgetRuleConfig(t, pathPrefix)
	rules := make([]PublicationRule, 10_000)
	for index := range rules {
		rules[index] = responseBudgetPublicationRule(index, config)
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
			Rules:               rules,
		},
		CreatedAt: responseBudgetLatestTime(),
	}

	encoded, err := json.Marshal(publication)
	if err != nil {
		t.Fatalf("marshal publication: %v", err)
	}
	if len(encoded) > maximumMaxResponseBytes {
		t.Fatalf("publication bytes = %d, runtime maximum = %d", len(encoded), maximumMaxResponseBytes)
	}

	handler := &Handler{maxResponseBytes: maximumMaxResponseBytes}
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	response := httptest.NewRecorder()
	handler.writeJSON(response, request, http.StatusOK, publication)
	if response.Code != http.StatusOK {
		t.Fatalf("writeJSON() status = %d, want 200", response.Code)
	}
}

func responseBudgetRuleConfig(t *testing.T, pathPrefix string) RuleConfig {
	t.Helper()
	host := strings.Join([]string{
		strings.Repeat("a", 63),
		strings.Repeat("b", 63),
		strings.Repeat("c", 63),
		strings.Repeat("d", 61),
	}, ".")
	egressReference := strings.Repeat("e", 128)
	activation := responseBudgetLatestTime()
	config := RuleConfig{
		Provider:              ProviderS3,
		Algorithm:             AlgorithmS3,
		Endpoint:              "https://" + host,
		PathPrefix:            pathPrefix,
		Region:                strings.Repeat("r", 64),
		Service:               "s3",
		SignatureTTLSeconds:   3600,
		EgressPolicyReference: egressReference,
		CurrentCredential: CredentialReference{
			CredentialID: responseBudgetUUID("current-credential", 0),
			Revision:     maxSafeRevision,
		},
		PreviousCredential: &CredentialReference{
			CredentialID: responseBudgetUUID("previous-credential", 0),
			Revision:     maxSafeRevision,
		},
		ActivateCurrentAt: &activation,
	}
	policies := map[string]map[string]struct{}{
		egressReference: {host: {}},
	}
	if err := validateRuleConfig(&config, policies); err != nil {
		t.Fatalf("response-budget fixture is not service-valid: %v", err)
	}
	return config
}

func responseBudgetRule(index int, config RuleConfig) Rule {
	return Rule{
		ID:             responseBudgetUUID("rule", index),
		TenantScopeID:  responseBudgetUUID("tenant", 0),
		SiteID:         responseBudgetUUID("site", index),
		SourcePosition: 32,
		RuleConfig:     config,
		Enabled:        true,
		Revision:       maxSafeRevision,
		CreatedAt:      responseBudgetLatestTime(),
		UpdatedAt:      responseBudgetLatestTime(),
	}
}

func responseBudgetPublicationRule(index int, config RuleConfig) PublicationRule {
	previousRevisionRef := responseBudgetUUID("previous-revision", index)
	return PublicationRule{
		RuleID:                        responseBudgetUUID("rule", index),
		SiteID:                        responseBudgetUUID("site", index),
		SourcePosition:                32,
		Provider:                      config.Provider,
		Algorithm:                     config.Algorithm,
		Endpoint:                      config.Endpoint,
		Bucket:                        config.Bucket,
		PathPrefix:                    config.PathPrefix,
		Region:                        config.Region,
		Service:                       config.Service,
		SignatureTTLSeconds:           config.SignatureTTLSeconds,
		CurrentCredentialRevisionRef:  responseBudgetUUID("current-revision", index),
		PreviousCredentialRevisionRef: &previousRevisionRef,
		ActivateCurrentAtUnix:         responseBudgetLatestTime().Unix(),
	}
}

func responseBudgetUUID(kind string, index int) uuid.UUID {
	return uuid.NewSHA1(uuid.NameSpaceOID, []byte(kind+":"+strconv.Itoa(index)))
}

func responseBudgetLatestTime() time.Time {
	return time.Date(9999, time.December, 31, 23, 59, 59, 999999999, time.UTC)
}
