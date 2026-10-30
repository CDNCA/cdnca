package httpapi

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/dnsacme"
	"github.com/cdnca/cdnca/services/control-api/internal/fielderr"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/packagecatalog"
	"github.com/cdnca/cdnca/services/control-api/internal/securitypolicy"
	"github.com/google/uuid"
	"gopkg.in/yaml.v3"
)

type fieldErrorBody struct {
	Error struct {
		Code      string `json:"code"`
		Message   string `json:"message"`
		RequestID string `json:"request_id"`
		Details   *struct {
			Field  string `json:"field"`
			Reason string `json:"reason"`
		} `json:"details"`
	} `json:"error"`
}

func decodeFieldError(t *testing.T, recorder *httptest.ResponseRecorder) fieldErrorBody {
	t.Helper()
	var body fieldErrorBody
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	return body
}

// assertFieldError checks a 400 validation_error naming field/reason in details.
func assertFieldError(t *testing.T, recorder *httptest.ResponseRecorder, field, reason string) {
	t.Helper()
	body := decodeFieldError(t, recorder)
	if recorder.Code != http.StatusBadRequest || body.Error.Code != "validation_error" || body.Error.Details == nil ||
		body.Error.Details.Field != field || body.Error.Details.Reason != reason || body.Error.Message == "" {
		t.Fatalf("want 400 validation_error %s/%s, got %d %s", field, reason, recorder.Code, recorder.Body.String())
	}
}

// fix-fielderr-be: a located domain refusal keeps 400 validation_error and adds
// details.field/reason; an unlocated one is unchanged (no details).
func TestWriteErrorAddsLocatedField(t *testing.T) {
	server := &Server{}
	recorder := httptest.NewRecorder()
	err := fmt.Errorf("create: %w", fielderr.New(packagecatalog.ErrInvalidInput, "limits.domains", fielderr.OutOfRange))
	server.writeError(recorder, httptest.NewRequest(http.MethodPost, "/v1/admin/packages", nil), err)
	assertFieldError(t, recorder, "limits.domains", fielderr.OutOfRange)

	recorder = httptest.NewRecorder()
	server.writeError(recorder, httptest.NewRequest(http.MethodPost, "/v1/admin/packages", nil), packagecatalog.ErrInvalidInput)
	if recorder.Code != http.StatusBadRequest || decodeFieldError(t, recorder).Error.Details != nil {
		t.Fatalf("unlocated: %d %s", recorder.Code, recorder.Body.String())
	}

	recorder = httptest.NewRecorder()
	server.writeFieldError(recorder, httptest.NewRequest(http.MethodPost, "/", nil), "expected_revision", fielderr.Required)
	assertFieldError(t, recorder, "expected_revision", fielderr.Required)
}

// fieldErrorSamples are domain refusals that must reach the page as a located
// field. The service rejects them before touching its store, so a nil store
// is enough (no database).
func fieldErrorSamples(t *testing.T) map[string]struct {
	err           error
	field, reason string
} {
	t.Helper()
	dnsActor := dnsacme.Actor{UserID: uuid.New(), ScopeID: uuid.New(), ScopeKind: "tenant"}
	_, orderErr := dnsacme.NewService(nil, nil).CreateOrder(t.Context(), dnsActor, dnsacme.CreateOrderRequest{
		ChallengeType: "http-01", Domains: []string{"a.example.test", "bad_domain"}, IdempotencyKey: "k", RequestID: "r"})
	_, userErr := (&identity.Service{}).CreateUser(t.Context(), identity.Actor{UserID: uuid.New(), ScopeID: uuid.New(), ScopeKind: "platform"},
		identity.CreateUserInput{Username: "ab", Role: identity.UserRoleOwner, IdempotencyKey: "key-1", RequestID: "r"})
	// fix-fielderr-be3: a CC rule's window, named as sent in the policy body.
	_, policyErr := securitypolicy.NewService(nil).Create(t.Context(), securitypolicy.Actor{UserID: uuid.New(), ScopeID: uuid.New(), ScopeKind: "tenant"},
		securitypolicy.CreateRequest{Fields: securitypolicy.PolicyFields{Kind: securitypolicy.KindCC, Name: "p", DefaultAction: securitypolicy.ActionAllow,
			Rules: []securitypolicy.Rule{{Name: "r", Priority: 1, Action: securitypolicy.ActionRateLimit, Flow: securitypolicy.FlowContinue,
				Conditions:   []securitypolicy.Condition{{Field: "path", Operator: "prefix", Values: []string{"/"}}},
				ActionConfig: securitypolicy.ActionConfig{RateLimit: &securitypolicy.RateLimitConfig{WindowSeconds: 7200, MaxRequests: 1}}}}},
			IdempotencyKey: "k", RequestID: "r"})
	return map[string]struct {
		err           error
		field, reason string
	}{
		"security policy": {policyErr, "rules[0].action_config.rate_limit.window_seconds", fielderr.OutOfRange},
		"certificate":     {orderErr, "domains[1]", fielderr.InvalidFormat},
		"user":            {userErr, "username", fielderr.TooShort},
	}
}

func TestDomainFieldRefusalsReachTheResponse(t *testing.T) {
	server := &Server{}
	for name, sample := range fieldErrorSamples(t) {
		t.Run(name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			server.writeError(recorder, httptest.NewRequest(http.MethodPost, "/", nil), sample.err)
			assertFieldError(t, recorder, sample.field, sample.reason)
		})
	}
}

// The ErrorEnvelope of control.yaml and the Error of dns-acme.yaml accept the
// located field bodies and still reject malformed ones (node + ajv from the
// root node_modules).
func TestFieldErrorMatchesOpenAPI(t *testing.T) {
	if _, err := exec.LookPath("node"); err != nil {
		t.Skip("node is not installed")
	}
	var bodies []json.RawMessage
	server := &Server{}
	for _, sample := range fieldErrorSamples(t) {
		recorder := httptest.NewRecorder()
		server.writeError(recorder, httptest.NewRequest(http.MethodPost, "/", nil), sample.err)
		bodies = append(bodies, json.RawMessage(strings.TrimSpace(recorder.Body.String())))
	}
	recorder := httptest.NewRecorder()
	server.writeFieldError(recorder, httptest.NewRequest(http.MethodPost, "/", nil), "zone_id", fielderr.Required)
	bodies = append(bodies, json.RawMessage(strings.TrimSpace(recorder.Body.String())))
	negative := []json.RawMessage{
		json.RawMessage(`{"error":{"code":"validation_error","message":"m","request_id":"r","details":{"field":"name"}}}`),
		json.RawMessage(`{"error":{"code":"validation_error","message":"m","request_id":"r","details":{"field":"Name","reason":"required"}}}`),
		json.RawMessage(`{"error":{"code":"validation_error","message":"m","request_id":"r","details":{"field":"name","reason":"required","x":1}}}`),
	}
	assertOpenAPIErrorBodies(t, "../../../../api/openapi/v1/control.yaml", "ErrorEnvelope", bodies, negative)
	assertOpenAPIErrorBodies(t, "../../../../api/openapi/v1/dns-acme.yaml", "Error", bodies, negative)
	assertOpenAPIErrorBodies(t, "../../../../api/control-security-policies.openapi.yaml", "ErrorEnvelope", bodies, negative)
}

func assertOpenAPIErrorBodies(t *testing.T, path, schema string, valid, invalid []json.RawMessage) {
	t.Helper()
	encoded, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := yaml.Unmarshal(encoded, &document); err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(map[string]any{"document": document, "schema": schema, "valid": valid, "invalid": invalid})
	if err != nil {
		t.Fatal(err)
	}
	script := `const Ajv2020 = require("ajv/dist/2020").default;
const input = JSON.parse(require("node:fs").readFileSync(0, "utf8"));
const ajv = new Ajv2020({allErrors: true, strict: false});
const validate = ajv.compile({$ref: "#/components/schemas/" + input.schema, components: input.document.components});
for (const [want, bodies] of [[true, input.valid], [false, input.invalid]]) {
  for (const body of bodies) {
    if (validate(body) !== want) {
      console.error("want " + want + ": " + JSON.stringify(body) + " " + JSON.stringify(validate.errors));
      process.exitCode = 1;
    }
  }
}`
	command := exec.Command("node", "-e", script)
	command.Stdin = strings.NewReader(string(payload))
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("%s %s assertions failed: %v\n%s", path, schema, err, output)
	}
}
