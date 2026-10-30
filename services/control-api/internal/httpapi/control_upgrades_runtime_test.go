package httpapi

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/controlupgrade"
)

func TestDecodeControlUpgradeCreateIsStrict(t *testing.T) {
	want := controlupgrade.CreateRolloutBody{Schema: "cdnca.control-upgrade-rollout.create/v1",
		NodeIDs:       []string{"00000000-0000-4000-8000-000000000001", "00000000-0000-4000-8000-000000000002"},
		CanaryNodeIDs: []string{"00000000-0000-4000-8000-000000000001"}, BatchSize: 1, AutomaticRollback: true}
	encoded, _ := json.Marshal(want)
	request := httptest.NewRequest("POST", "/v1/admin/control-upgrade-rollouts", bytes.NewReader(encoded))
	request.Header.Set("Content-Type", "application/json")
	got, err := decodeControlUpgradeCreate(request)
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("decodeControlUpgradeCreate() = (%#v,%v), want %#v", got, err, want)
	}
	for name, body := range map[string]string{
		"unknown":   string(encoded[:len(encoded)-1]) + `,"component":"edge-agent"}`,
		"duplicate": `{"schema":"cdnca.control-upgrade-rollout.create/v1","schema":"cdnca.control-upgrade-rollout.create/v1","node_ids":[],"canary_node_ids":[],"batch_size":1,"automatic_rollback":true}`,
		"trailing":  string(encoded) + `{}`,
		"null":      `{"schema":null,"node_ids":null,"canary_node_ids":null,"batch_size":null,"automatic_rollback":null}`,
	} {
		t.Run(name, func(t *testing.T) {
			candidate := httptest.NewRequest("POST", "/v1/admin/control-upgrade-rollouts", bytes.NewBufferString(body))
			candidate.Header.Set("Content-Type", "application/json")
			if _, err := decodeControlUpgradeCreate(candidate); err == nil {
				t.Fatalf("strict decoder accepted %s body", name)
			}
		})
	}
}

func TestDecodeControlUpgradeBodyRejectsMediaTypeAndSizeViolations(t *testing.T) {
	valid := `{"expected_revision":"1","reason":"operator_requested"}`
	for name, configure := range map[string]func(*http.Request){
		"missing": func(*http.Request) {},
		"duplicate": func(request *http.Request) {
			request.Header["Content-Type"] = []string{"application/json", "application/json"}
		},
		"parameter": func(request *http.Request) {
			request.Header.Set("Content-Type", "application/json; charset=utf-8")
		},
		"noncanonical case": func(request *http.Request) {
			request.Header.Set("Content-Type", "Application/JSON")
		},
		"unsupported": func(request *http.Request) {
			request.Header.Set("Content-Type", "text/plain")
		},
	} {
		t.Run(name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, "/v1/admin/control-upgrade-rollouts/id/start",
				strings.NewReader(valid))
			configure(request)
			if _, err := decodeControlUpgradeAction(request); !errors.Is(err, errControlUpgradeUnsupportedMediaType) {
				t.Fatalf("decodeControlUpgradeAction() error = %v, want unsupported media type", err)
			}
		})
	}
	oversized := httptest.NewRequest(http.MethodPost, "/v1/admin/control-upgrade-rollouts",
		strings.NewReader(strings.Repeat("x", controlUpgradeBodyLimit+1)))
	oversized.Header.Set("Content-Type", "application/json")
	if _, err := decodeControlUpgradeCreate(oversized); !errors.Is(err, errControlUpgradeBodyTooLarge) {
		t.Fatalf("decodeControlUpgradeCreate() error = %v, want body too large", err)
	}
}

func TestControlUpgradeActionRevisionAndPlanIDBoundaries(t *testing.T) {
	for _, raw := range []string{"1", "9007199254740993", "9223372036854775807"} {
		if revision, err := parseControlUpgradeRevision(raw, false); err != nil ||
			strconv.FormatUint(revision, 10) != raw {
			t.Fatalf("valid action revision %q = (%d,%v)", raw, revision, err)
		}
	}
	for _, raw := range []string{"", "0", "01", "+1", " 1", "1 ", "1.0", "1e0", "9223372036854775808"} {
		if revision, err := parseControlUpgradeRevision(raw, false); err == nil {
			t.Fatalf("invalid action revision %q accepted as %d", raw, revision)
		}
	}
	if revision, err := parseControlUpgradeRevision("0", true); err != nil || revision != 0 {
		t.Fatalf("dispatch zero revision = (%d,%v)", revision, err)
	}
	for _, encoded := range []string{
		`{"expected_revision":"9223372036854775807","reason":"operator_requested"}`,
		`{"expected_revision":"9007199254740993","reason":"operator_requested"}`,
	} {
		request := httptest.NewRequest(http.MethodPost, "/v1/admin/control-upgrade-rollouts/id/start",
			strings.NewReader(encoded))
		request.Header.Set("Content-Type", "application/json")
		if body, err := decodeControlUpgradeAction(request); err != nil ||
			strconv.FormatUint(body.ExpectedRevision, 10) != strings.Split(encoded, `"`)[3] {
			t.Fatalf("decode action %s = (%+v,%v)", encoded, body, err)
		}
	}
	for _, encoded := range []string{
		`{"expected_revision":1,"reason":"operator_requested"}`,
		`{"expected_revision":"01","reason":"operator_requested"}`,
		`{"expected_revision":"9223372036854775808","reason":"operator_requested"}`,
	} {
		request := httptest.NewRequest(http.MethodPost, "/v1/admin/control-upgrade-rollouts/id/start",
			strings.NewReader(encoded))
		request.Header.Set("Content-Type", "application/json")
		if _, err := decodeControlUpgradeAction(request); err == nil {
			t.Fatalf("invalid action body accepted: %s", encoded)
		}
	}
	validID := "00000000-0000-4000-8000-000000000001"
	if got, err := parseControlUpgradePlanID(validID); err != nil || got != validID {
		t.Fatalf("parseControlUpgradePlanID() = (%q,%v), want %q", got, err, validID)
	}
	for _, raw := range []string{"", "00000000-0000-0000-0000-000000000000",
		"00000000-0000-4000-8000-000000000001 ", "{00000000-0000-4000-8000-000000000001}",
		"00000000-0000-4000-8000-000000000001"[:35] + "A"} {
		if _, err := parseControlUpgradePlanID(raw); err == nil {
			t.Fatalf("noncanonical plan ID accepted: %q", raw)
		}
	}
}

func TestControlUpgradeIdempotencyKeyIsSingleAndCanonical(t *testing.T) {
	server := &Server{}
	for name, values := range map[string][]string{
		"missing":    nil,
		"duplicate":  {"upgrade.1", "upgrade.1"},
		"whitespace": {" upgrade.1"},
		"separator":  {"upgrade,1"},
	} {
		t.Run(name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, "/v1/admin/control-upgrade-rollouts", nil)
			request.Header["Idempotency-Key"] = values
			response := httptest.NewRecorder()
			if _, ok := server.controlUpgradeIdempotencyKey(response, request); ok {
				t.Fatal("invalid Idempotency-Key accepted")
			}
			if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), `"code":"invalid_idempotency_key"`) {
				t.Fatalf("response = %d %s", response.Code, response.Body.String())
			}
		})
	}
	request := httptest.NewRequest(http.MethodPost, "/v1/admin/control-upgrade-rollouts", nil)
	request.Header.Set("Idempotency-Key", "upgrade.1")
	if key, ok := server.controlUpgradeIdempotencyKey(httptest.NewRecorder(), request); !ok || key != "upgrade.1" {
		t.Fatalf("canonical Idempotency-Key = (%q,%v)", key, ok)
	}
}

func TestParseControlUpgradeListQueryRejectsUnknownAndDuplicates(t *testing.T) {
	request := httptest.NewRequest("GET", "/v1/admin/control-upgrade-rollouts?page=2&page_size=50&state=paused&node_id=00000000-0000-4000-8000-000000000001", nil)
	got, err := parseControlUpgradeListQuery(request.URL.Query())
	want := controlupgrade.ListRolloutsRequest{Page: 2, PageSize: 50, State: controlupgrade.PlanPaused,
		NodeID: "00000000-0000-4000-8000-000000000001"}
	if err != nil || got != want {
		t.Fatalf("parseControlUpgradeListQuery() = (%#v,%v), want %#v", got, err, want)
	}
	for _, raw := range []string{
		"?page=1&page=2", "?page_size=101", "?state=unknown", "?node_id={00000000-0000-4000-8000-000000000001}", "?sort=id",
	} {
		candidate := httptest.NewRequest("GET", "/v1/admin/control-upgrade-rollouts"+raw, nil)
		if _, err := parseControlUpgradeListQuery(candidate.URL.Query()); err == nil {
			t.Errorf("invalid list query accepted: %s", raw)
		}
	}
	if _, err := parseControlUpgradeListRawQuery("page=1;sort=id"); err == nil {
		t.Fatal("malformed query was accepted")
	}
}

func TestControlUpgradeResponseJSONOrderAndRedaction(t *testing.T) {
	detail := controlupgrade.RolloutDetail{RolloutSummary: controlupgrade.RolloutSummary{
		ID: "00000000-0000-4000-8000-000000000010", SchemaVersion: 2,
		InstallationID: "00000000-0000-4000-8000-000000000011", Component: "edge-agent",
		CurrentVersion: "1.0.0", TargetVersion: "2.0.0", State: controlupgrade.PlanQueued,
		Revision: uint64(1<<63 - 1), AutomaticRollback: true,
	}, Nodes: []controlupgrade.RolloutNode{{
		NodeID: "00000000-0000-4000-8000-000000000012", DispatchRevision: 0,
	}}, Events: []controlupgrade.RolloutEvent{{
		ID: "00000000-0000-4000-8000-000000000013", Revision: uint64(1<<53 + 1),
	}}}
	encoded, err := json.Marshal(controlUpgradeWriteResponse{Data: controlUpgradeRolloutDetail(detail), Replayed: false})
	if err != nil {
		t.Fatal(err)
	}
	wantPrefix := `{"data":{"id":"` + detail.ID + `","schema_version":2,"installation_id":`
	if !bytes.HasPrefix(encoded, []byte(wantPrefix)) {
		t.Fatalf("write response field order = %s", encoded)
	}
	for _, required := range []string{
		`"revision":"9223372036854775807"`, `"dispatch_revision":"0"`,
		`"revision":"9007199254740993"`,
	} {
		if !bytes.Contains(encoded, []byte(required)) {
			t.Fatalf("response missing exact decimal string %s: %s", required, encoded)
		}
	}
	for _, forbidden := range []string{`"revision":9223372036854775807`, `"dispatch_revision":0`,
		`"revision":9007199254740993`} {
		if bytes.Contains(encoded, []byte(forbidden)) {
			t.Fatalf("response exposed an imprecise JSON number %s: %s", forbidden, encoded)
		}
	}
	for _, forbidden := range []string{"parent_grant_bytes", "signature", "download_url", "control_signer"} {
		if bytes.Contains(encoded, []byte(forbidden)) {
			t.Fatalf("response leaked %q: %s", forbidden, encoded)
		}
	}
	if bytes.Contains(encoded, []byte(`"occurred_at"`)) {
		t.Fatalf("event without a committed time must omit occurred_at: %s", encoded)
	}
}

func TestControlUpgradeRolloutEventsExposeCommitTime(t *testing.T) {
	at := time.Date(2026, 10, 14, 8, 30, 15, 0, time.UTC)
	detail := controlupgrade.RolloutDetail{Events: []controlupgrade.RolloutEvent{
		{ID: "00000000-0000-4000-8000-000000000021", Revision: 1, Action: "start"},
		{ID: "00000000-0000-4000-8000-000000000022", Revision: 2, Action: "advance"},
	}, EventTimes: map[uint64]time.Time{1: at}}
	response := controlUpgradeRolloutDetail(detail)
	if len(response.Events) != 2 {
		t.Fatalf("events = %d", len(response.Events))
	}
	if got := response.Events[0].OccurredAt; got == nil || !got.Equal(at) {
		t.Fatalf("event 1 occurred_at = %v, want %v", got, at)
	}
	if response.Events[1].OccurredAt != nil {
		t.Fatalf("event 2 without a recorded time must have nil occurred_at")
	}
	encoded, err := json.Marshal(response)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(encoded, []byte(`"occurred_at":"2026-10-14T08:30:15Z"`)) {
		t.Fatalf("occurred_at not encoded as RFC3339: %s", encoded)
	}
}

func TestControlUpgradeRoutesAreRegistered(t *testing.T) {
	handler := (&Server{}).Handler()
	paths := []struct {
		method string
		path   string
	}{
		{http.MethodPost, "/v1/admin/control-upgrade-rollouts"},
		{http.MethodGet, "/v1/admin/control-upgrade-rollouts"},
		{http.MethodGet, "/v1/admin/control-upgrade-rollouts/00000000-0000-4000-8000-000000000001"},
		{http.MethodPost, "/v1/admin/control-upgrade-rollouts/00000000-0000-4000-8000-000000000001/start"},
		{http.MethodPost, "/v1/admin/control-upgrade-rollouts/00000000-0000-4000-8000-000000000001/pause"},
		{http.MethodPost, "/v1/admin/control-upgrade-rollouts/00000000-0000-4000-8000-000000000001/resume"},
		{http.MethodPost, "/v1/admin/control-upgrade-rollouts/00000000-0000-4000-8000-000000000001/rollback"},
	}
	for _, route := range paths {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(route.method, route.path, nil))
		if response.Code != http.StatusUnauthorized {
			t.Errorf("%s %s = %d, want authenticated route", route.method, route.path, response.Code)
		}
	}
}

func TestControlUpgradeConfiguredServiceInjection(t *testing.T) {
	configured := &controlupgrade.Service{}
	pepper := bytes.Repeat([]byte{0x52}, 32)
	server := New(nil, nil, Config{APIKeyPepper: pepper, ControlUpgradeService: configured})
	if server.controlUpgrades != configured {
		t.Fatal("New() did not preserve the configured control upgrade service")
	}
	defaulted := New(nil, nil, Config{APIKeyPepper: pepper})
	if defaulted.controlUpgrades == nil {
		t.Fatal("New() did not construct the backward-compatible control upgrade service")
	}
}

func TestControlUpgradeStableErrorMapping(t *testing.T) {
	tests := []struct {
		err    error
		status int
		code   string
	}{
		{controlupgrade.ErrInvalidInput, http.StatusBadRequest, "invalid_request"},
		{controlupgrade.ErrPermissionDenied, http.StatusForbidden, "permission_denied"},
		{controlupgrade.ErrRolloutNotFound, http.StatusNotFound, "control_upgrade_rollout_not_found"},
		{controlupgrade.ErrNodeNotFound, http.StatusNotFound, "node_not_found"},
		{controlupgrade.ErrIdempotencyConflict, http.StatusConflict, "idempotency_conflict"},
		{controlupgrade.ErrPlanIdempotencyConflict, http.StatusConflict, "idempotency_conflict"},
		{controlupgrade.ErrStalePlanRevision, http.StatusConflict, "revision_conflict"},
		{controlupgrade.ErrInvalidPlanTransition, http.StatusConflict, "control_upgrade_rollout_invalid_transition"},
		{controlupgrade.ErrPlanBlocked, http.StatusConflict, "control_upgrade_rollout_blocked"},
		{controlupgrade.ErrCohortIncompatible, http.StatusConflict, "control_upgrade_cohort_incompatible"},
		{controlupgrade.ErrGrantInvalid, http.StatusBadGateway, "control_upgrade_grant_invalid"},
		{controlupgrade.ErrExecutionInvalid, http.StatusBadGateway, "control_upgrade_execution_invalid"},
		{controlupgrade.ErrLicenseOutcomeUnknown, http.StatusServiceUnavailable, "control_upgrade_license_outcome_unknown"},
		{controlupgrade.ErrLicenseUnavailable, http.StatusServiceUnavailable, "control_upgrade_license_unavailable"},
		{controlupgrade.ErrRuntimeUnavailable, http.StatusServiceUnavailable, "control_upgrade_runtime_unavailable"},
		{controlupgrade.ErrResourceUnavailable, http.StatusServiceUnavailable, "control_upgrade_resource_unavailable"},
	}
	server := &Server{}
	for _, test := range tests {
		response := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodGet, "/v1/admin/control-upgrade-rollouts", nil)
		server.writeControlUpgradeError(response, request, test.err)
		if response.Code != test.status || !strings.Contains(response.Body.String(), `"code":"`+test.code+`"`) {
			t.Errorf("%v response = %d %s", test.err, response.Code, response.Body.String())
		}
	}
}
