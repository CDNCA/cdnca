package edgepublishhttp

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"regexp"
	"slices"
	"sort"
	"strings"
	"testing"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/cdnca/cdnca/services/control-api/internal/edgedeployment"
	"github.com/cdnca/cdnca/services/control-api/internal/edgepublish"
	"github.com/cdnca/cdnca/services/control-api/internal/packageaddon"
	"github.com/cdnca/cdnca/services/control-api/internal/securityactivation"
	"github.com/cdnca/cdnca/services/control-api/internal/securitypolicy"
	"github.com/google/uuid"
	"gopkg.in/yaml.v3"
)

const sitePublicationsOpenAPIPath = "../../../../api/control-site-publications.openapi.yaml"

// One error per stable code classifyError emits; the contract test fails when
// handler.go gains a code without a sample here.
func errorEnvelopeSamples() map[string]error {
	node, other, site := uuid.New(), uuid.New(), uuid.New()
	return map[string]error{
		"node_scope_conflict": fmt.Errorf("%w: node %s rule cc", edgepublish.ErrCrossScopeConflict, node),
		"challenge_policy_unavailable": fmt.Errorf("publish: %w", &edgepublish.ChallengePolicyUnavailableError{
			NodeID: node, SiteID: site.String(), Domain: "shop.example.com", PolicyID: "policy", PolicyVersion: 4,
			OtherNodeIDs: []uuid.UUID{other}}),
		"node_capability_unavailable": fmt.Errorf("publish: %w", &edgepublish.TargetCapabilityError{
			NodeID: node, AgentVersion: "1.0.35", Feature: "an L4 session log",
			Capability: agentv1.CapabilityName_CAPABILITY_NAME_TCP_PROXY, Required: 7, Advertised: 6,
			OtherNodeIDs: []uuid.UUID{other}}),
		"rule_pack_unavailable": fmt.Errorf("publish: %w", &edgepublish.RulePackUnavailableError{
			NodeID: node, SHA256: []string{strings.Repeat("a", 64)}, OtherNodeIDs: []uuid.UUID{other}}),
		"rule_pack_out_of_profile": fmt.Errorf("publish: %w", &edgepublish.CRSOutOfProfileError{
			SiteID: site.String(), PackID: "system/sqli-narrow", Reason: "paranoia 2 is above the profile's 1"}),
		"quick_block_site_override_conflict": fmt.Errorf("rollback: %w", &securitypolicy.QuickBlockSiteOverrideError{
			SiteIDs: []uuid.UUID{site}}),
		"entitlement_feature_denied": fmt.Errorf("publish: %w",
			&edgepublish.ModuleNotEntitledError{Modules: []string{"module.aggregated_edge"}}),
		"package_resource_quota_exceeded":   packageaddon.ErrQuotaExceeded,
		"package_feature_denied":            packageaddon.ErrFeatureDenied,
		"package_subscription_inactive":     packageaddon.ErrSubscriptionInactive,
		"package_addon_in_use":              packageaddon.ErrInUse,
		"authentication_required":           ErrUnauthenticated,
		"permission_denied":                 ErrPermissionDenied,
		"validation_error":                  ErrInvalidRequest,
		"publication_resource_not_found":    edgepublish.ErrNotFound,
		"revision_conflict":                 edgepublish.ErrRevisionConflict,
		"source_revision_already_published": edgepublish.ErrAlreadyPublished,
		"idempotency_conflict":              edgepublish.ErrIdempotencyConflict,
		"site_locked":                       securityactivation.ErrSiteLocked,
		"security_policy_deleted":           securityactivation.ErrPolicyDeleted,
		"activation_expiry_too_late":        securityactivation.ErrExpiryTooLate,
		"no_target_nodes":                   securityactivation.ErrNoTargetNodes,
		"target_snapshot_conflict":          edgepublish.ErrTargetSnapshotConflict,
		"publication_deadline_expired":      edgedeployment.ErrDeadlineExpired,
		"publication_state_conflict":        edgedeployment.ErrInvalidTransition,
		"publication_not_allowed":           edgepublish.ErrEntitlementDenied,
		"publication_not_ready":             edgepublish.ErrTargetIneligible,
		"publication_service_unavailable":   edgepublish.ErrPersistence,
	}
}

// The error bodies both handlers of this fragment actually write must satisfy
// ErrorEnvelope (additionalProperties: false), and the code enum must list
// every code classifyError emits.
func TestErrorEnvelopeOpenAPIMatchesHandlerBodies(t *testing.T) {
	source, err := os.ReadFile("handler.go")
	if err != nil {
		t.Fatal(err)
	}
	emitted := map[string]bool{}
	for _, match := range regexp.MustCompile(`return http\.Status[A-Za-z]+, "([a-z_]+)"`).FindAllSubmatch(source, -1) {
		emitted[string(match[1])] = true
	}
	samples := errorEnvelopeSamples()
	if got, want := sortedKeys(samples), sortedKeys(emitted); !slices.Equal(got, want) {
		t.Fatalf("samples cover %v, classifyError emits %v", got, want)
	}

	document := loadOpenAPIJSON(t, sitePublicationsOpenAPIPath)
	enum := errorEnvelopeCodeEnum(t, document)
	if got, want := enum, sortedKeys(emitted); !slices.Equal(got, want) {
		t.Fatalf("ErrorEnvelope code enum = %v, classifyError emits %v", got, want)
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	publications := &Handler{logger: logger}
	activations := &SecurityActivationHandler{logger: logger}
	writers := map[string]func(http.ResponseWriter, *http.Request, error){
		"site-publications":    publications.writeError,
		"security-activations": activations.writeError,
	}
	type validationCase struct {
		Name string          `json:"name"`
		Body json.RawMessage `json:"body"`
		Want bool            `json:"want"`
	}
	var cases []validationCase
	for _, code := range sortedKeys(samples) {
		for _, writerName := range sortedKeys(writers) {
			response := httptest.NewRecorder()
			response.Header().Set("X-Request-ID", uuid.NewString())
			writers[writerName](response, httptest.NewRequest(http.MethodPost, "/v1/site-publications", nil), samples[code])
			assertAPIError(t, response, response.Code, code)
			body := json.RawMessage(strings.TrimSpace(response.Body.String()))
			cases = append(cases, validationCase{Name: writerName + " " + code, Body: body, Want: true})
		}
	}
	// The schema is strict: unknown fields, a detail object on the wrong code
	// and a refusal without its details are rejected.
	requestID := uuid.NewString()
	nodeID := uuid.NewString()
	capability := fmt.Sprintf(`{"node_id":%q,"capability":"CAPABILITY_NAME_CC","required_version":4,"other_node_ids":[]}`, nodeID)
	for name, body := range map[string]string{
		"unknown field":                     fmt.Sprintf(`{"error":{"code":"validation_error","message":"m","request_id":%q,"detail":"x"}}`, requestID),
		"unknown code":                      fmt.Sprintf(`{"error":{"code":"made_up","message":"m","request_id":%q}}`, requestID),
		"capability on other code":          fmt.Sprintf(`{"error":{"code":"publication_not_ready","message":"m","request_id":%q,"capability":%s}}`, requestID, capability),
		"capability refusal without nodes":  fmt.Sprintf(`{"error":{"code":"node_capability_unavailable","message":"m","request_id":%q}}`, requestID),
		"challenge refusal without details": fmt.Sprintf(`{"error":{"code":"challenge_policy_unavailable","message":"m","request_id":%q}}`, requestID),
		"rule pack refusal without details": fmt.Sprintf(`{"error":{"code":"rule_pack_unavailable","message":"m","request_id":%q}}`, requestID),
		"module refusal without modules":    fmt.Sprintf(`{"error":{"code":"entitlement_feature_denied","message":"m","request_id":%q}}`, requestID),
		"modules on other code":             fmt.Sprintf(`{"error":{"code":"publication_not_ready","message":"m","request_id":%q,"modules":["module.x"]}}`, requestID),
		"capability version zero":           fmt.Sprintf(`{"error":{"code":"node_capability_unavailable","message":"m","request_id":%q,"capability":{"node_id":%q,"capability":"CAPABILITY_NAME_CC","required_version":0,"other_node_ids":[]}}}`, requestID, nodeID),
	} {
		cases = append(cases, validationCase{Name: "negative " + name, Body: json.RawMessage(body), Want: false})
	}
	payload, err := json.Marshal(map[string]any{"document": document, "cases": cases})
	if err != nil {
		t.Fatal(err)
	}
	script := `const Ajv2020 = require("ajv/dist/2020").default;
const addFormats = require("ajv-formats").default;
const input = JSON.parse(require("node:fs").readFileSync(0, "utf8"));
const ajv = new Ajv2020({allErrors: true, strict: false});
addFormats(ajv);
const validate = ajv.compile({$ref: "#/components/schemas/ErrorEnvelope", components: input.document.components});
for (const testCase of input.cases) {
  const got = validate(testCase.body);
  if (got !== testCase.want) {
    console.error(testCase.name + ": got " + got + ", want " + testCase.want + " " + JSON.stringify(validate.errors) + " " + JSON.stringify(testCase.body));
    process.exitCode = 1;
  }
}`
	command := exec.Command("node", "-e", script)
	command.Stdin = strings.NewReader(string(payload))
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("ErrorEnvelope schema assertions failed: %v\n%s", err, output)
	}
}

func loadOpenAPIJSON(t *testing.T, path string) map[string]any {
	t.Helper()
	encoded, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := yaml.Unmarshal(encoded, &document); err != nil {
		t.Fatal(err)
	}
	return document
}

func errorEnvelopeCodeEnum(t *testing.T, document map[string]any) []string {
	t.Helper()
	var codes []string
	defer func() {
		if recovered := recover(); recovered != nil {
			t.Fatalf("ErrorEnvelope error.code enum is missing: %v", recovered)
		}
	}()
	code := document["components"].(map[string]any)["schemas"].(map[string]any)["ErrorEnvelope"].(map[string]any)["properties"].(map[string]any)["error"].(map[string]any)["properties"].(map[string]any)["code"].(map[string]any)
	for _, value := range code["enum"].([]any) {
		codes = append(codes, value.(string))
	}
	sort.Strings(codes)
	return codes
}

func sortedKeys[V any](values map[string]V) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

// sa-rulepack-wait: a recorded security activation says so in
// error.rule_packs.auto_resume; a plain publish refusal omits it.
func TestRulePackRefusalAutoResumeField(t *testing.T) {
	node := uuid.New()
	for _, autoResume := range []bool{false, true} {
		refusal := &edgepublish.RulePackUnavailableError{NodeID: node, SHA256: []string{strings.Repeat("a", 64)},
			AutoResume: autoResume}
		body, err := json.Marshal(newErrorEnvelope("rule_pack_unavailable", refusal.Error(), "req", fmt.Errorf("start: %w", refusal)))
		if err != nil {
			t.Fatal(err)
		}
		if got := strings.Contains(string(body), `"auto_resume":true`); got != autoResume {
			t.Fatalf("auto_resume=%v body %s", autoResume, body)
		}
	}
}
