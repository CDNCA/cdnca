package edgepublishhttp

import (
	"context"
	"encoding/json"
	"net/http"
	"os/exec"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/edgepublish"
	"github.com/google/uuid"
)

// TestPublishResponseListsNodesStillOnTheOldConfiguration: a
// manual publication that left nodes out for their key envelope, or sent every
// website to nodes without SITE_SELECTION, says so in the 201 body
// (key_envelope_oversized_node_ids / site_selection_unsupported_node_ids);
// without them the keys are absent. The tenant view carries no node IDs.
func TestPublishResponseListsNodesStillOnTheOldConfiguration(t *testing.T) {
	domain := &fakeDomain{}
	handler := newTestHandler(t, domain)
	scopeID := testTenantScopeID()
	oversized := []uuid.UUID{uuid.MustParse("10000000-0000-4000-8000-000000000001"), uuid.MustParse("10000000-0000-4000-8000-000000000002")}
	unsupported := []uuid.UUID{uuid.MustParse("20000000-0000-4000-8000-000000000003")}
	leftOut := true
	domain.publishFn = func(_ context.Context, request edgepublish.PublishRequest) (edgepublish.PublishResult, error) {
		result := testPublication(request.ConfigurationScopeID)
		if leftOut {
			result.KeyEnvelopeOversizedNodeIDs = oversized
			result.SiteSelectionUnsupportedNodeIDs = unsupported
		}
		return result, nil
	}
	decode := func(t *testing.T, path, token string, body any) map[string]any {
		t.Helper()
		response := performRequest(handler, http.MethodPost, path, token, body, true)
		if response.Code != http.StatusCreated {
			t.Fatalf("%s status=%d body=%s", path, response.Code, response.Body.String())
		}
		var decoded map[string]any
		if err := json.Unmarshal(response.Body.Bytes(), &decoded); err != nil {
			t.Fatal(err)
		}
		return decoded
	}
	ids := func(values []uuid.UUID) []any {
		out := make([]any, len(values))
		for index, value := range values {
			out[index] = value.String()
		}
		return out
	}
	body := validPublishBody(scopeID, []uuid.UUID{uuid.New()})

	admin := decode(t, "/v1/admin/site-publications", "platform-manage", body)
	if got, _ := json.Marshal(admin["key_envelope_oversized_node_ids"]); string(got) != mustJSON(t, ids(oversized)) {
		t.Fatalf("key_envelope_oversized_node_ids = %s", got)
	}
	if got, _ := json.Marshal(admin["site_selection_unsupported_node_ids"]); string(got) != mustJSON(t, ids(unsupported)) {
		t.Fatalf("site_selection_unsupported_node_ids = %s", got)
	}
	adminSchemaAccepts(t, admin, true)

	tenant := decode(t, "/v1/site-publications", "tenant-manage", body)
	for _, key := range []string{"key_envelope_oversized_node_ids", "site_selection_unsupported_node_ids"} {
		if _, ok := tenant[key]; ok {
			t.Fatalf("tenant publication carries %s: %v", key, tenant)
		}
	}

	// Reads (migration 649 keeps the lists): the admin list and detail carry
	// them, the tenant reads do not.
	stored := testPublication(scopeID)
	stored.KeyEnvelopeOversizedNodeIDs, stored.SiteSelectionUnsupportedNodeIDs = oversized, unsupported
	domain.getPublicationFn = func(context.Context, edgepublish.Actor, uuid.UUID, uuid.UUID) (edgepublish.PublishResult, error) {
		return stored, nil
	}
	domain.listPublicationFn = func(context.Context, edgepublish.Actor, uuid.UUID, edgepublish.PublicationPageRequest) (edgepublish.PublicationPage, error) {
		return edgepublish.PublicationPage{Items: []edgepublish.PublishResult{stored}, CurrentSourceRevision: 7}, nil
	}
	read := func(t *testing.T, path, token string) map[string]any {
		t.Helper()
		response := performRequest(handler, http.MethodGet, path, token, nil, false)
		if response.Code != http.StatusOK {
			t.Fatalf("%s status=%d body=%s", path, response.Code, response.Body.String())
		}
		var decoded map[string]any
		if err := json.Unmarshal(response.Body.Bytes(), &decoded); err != nil {
			t.Fatal(err)
		}
		return decoded
	}
	adminDetail := read(t, "/v1/admin/site-publications/"+stored.PublicationID.String()+"?scope_id="+scopeID.String(), "platform-read")
	adminList := read(t, "/v1/admin/site-publications?scope_id="+scopeID.String(), "platform-read")["items"].([]any)[0].(map[string]any)
	for name, item := range map[string]map[string]any{"detail": adminDetail, "list": adminList} {
		if got, _ := json.Marshal(item["key_envelope_oversized_node_ids"]); string(got) != mustJSON(t, ids(oversized)) {
			t.Fatalf("admin %s key_envelope_oversized_node_ids = %s", name, got)
		}
		if got, _ := json.Marshal(item["site_selection_unsupported_node_ids"]); string(got) != mustJSON(t, ids(unsupported)) {
			t.Fatalf("admin %s site_selection_unsupported_node_ids = %s", name, got)
		}
		adminSchemaAccepts(t, item, true)
	}
	tenantDetail := read(t, "/v1/site-publications/"+stored.PublicationID.String(), "tenant-read")
	tenantList := read(t, "/v1/site-publications", "tenant-read")["items"].([]any)[0].(map[string]any)
	for name, item := range map[string]map[string]any{"detail": tenantDetail, "list": tenantList} {
		for _, key := range []string{"key_envelope_oversized_node_ids", "site_selection_unsupported_node_ids"} {
			if _, ok := item[key]; ok {
				t.Fatalf("tenant %s carries %s", name, key)
			}
		}
	}

	leftOut = false
	clean := decode(t, "/v1/admin/site-publications", "platform-manage", body)
	for _, key := range []string{"key_envelope_oversized_node_ids", "site_selection_unsupported_node_ids"} {
		if _, ok := clean[key]; ok {
			t.Fatalf("publication without left-out nodes carries %s: %v", key, clean)
		}
	}
	adminSchemaAccepts(t, clean, true)

	// The schema refuses an empty list, a duplicate and a non-UUID.
	for name, value := range map[string]any{
		"empty":     []any{},
		"duplicate": []any{oversized[0].String(), oversized[0].String()},
		"not uuid":  []any{"node-1"},
	} {
		broken := map[string]any{}
		for key, field := range admin {
			broken[key] = field
		}
		broken["key_envelope_oversized_node_ids"] = value
		t.Run(name, func(t *testing.T) { adminSchemaAccepts(t, broken, false) })
	}
}

func mustJSON(t *testing.T, value any) string {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(encoded)
}

func adminSchemaAccepts(t *testing.T, body map[string]any, want bool) {
	t.Helper()
	payload, err := json.Marshal(map[string]any{
		"document": loadOpenAPIJSON(t, sitePublicationsOpenAPIPath), "body": body, "want": want,
	})
	if err != nil {
		t.Fatal(err)
	}
	script := `const Ajv2020 = require("ajv/dist/2020").default;
const addFormats = require("ajv-formats").default;
const input = JSON.parse(require("node:fs").readFileSync(0, "utf8"));
const ajv = new Ajv2020({allErrors: true, strict: false});
addFormats(ajv);
const validate = ajv.compile({$ref: "#/components/schemas/AdminPublication", components: input.document.components});
if (validate(input.body) !== input.want) {
  console.error("got " + !input.want + " " + JSON.stringify(validate.errors));
  process.exitCode = 1;
}`
	command := exec.Command("node", "-e", script)
	command.Stdin = strings.NewReader(string(payload))
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("AdminPublication schema (want %v): %v\n%s", want, err, output)
	}
}
