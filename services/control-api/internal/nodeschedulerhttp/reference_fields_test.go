package nodeschedulerhttp

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/nodescheduler"
	"github.com/google/uuid"
)

func TestLineGroupReferenceFieldsDTORoundTrip(t *testing.T) {
	groupID, scopeID, userID, l2ConfigID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	body := lineGroupWriteBody{
		Name: "华东线路", Region: "华东", IPv4ResolvedValue: "v4-east", L2ConfigID: &l2ConfigID,
		FailoverMode: nodescheduler.FailoverOnlineLessThanBackupCount, Endpoints: []endpointDTO{},
	}
	request := body.request(groupID, 4, "reference-update", "reference-request")
	if request.IPv4ResolvedValue != body.IPv4ResolvedValue || request.L2ConfigID == nil ||
		*request.L2ConfigID != l2ConfigID || request.FailoverMode != body.FailoverMode {
		t.Fatalf("write request = %#v", request)
	}

	now := time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC)
	view := lineGroupView(nodescheduler.LineGroupRevision{
		GroupID: groupID, DisplayID: "8", TenantScopeID: scopeID, Revision: 4, Name: body.Name,
		Region: body.Region, IPv4ResolvedValue: body.IPv4ResolvedValue, L2ConfigID: &l2ConfigID,
		FailoverMode: body.FailoverMode, Policy: nodescheduler.DefaultHealthPolicy(), Endpoints: []nodescheduler.Endpoint{},
		ConfigurationDigest: make([]byte, 32), CreatedByUserID: userID, CreatedAt: now, SealedAt: now,
	})
	if view.IPv4ResolvedValue != body.IPv4ResolvedValue || view.L2ConfigID == nil ||
		*view.L2ConfigID != l2ConfigID || view.FailoverMode != body.FailoverMode {
		t.Fatalf("line group view = %#v", view)
	}
}

func TestHandlerLineGroupReferenceFieldsCreateAndRead(t *testing.T) {
	scopeID, userID, groupID, l2ConfigID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	now := time.Date(2026, 9, 15, 12, 30, 0, 0, time.UTC)
	service := &fakeService{group: nodescheduler.LineGroupRevision{
		GroupID: groupID, DisplayID: "9", TenantScopeID: scopeID, Revision: 1, Name: "华东线路",
		Region: "华东", ResolvedValue: "edge-east", IPv4ResolvedValue: "v4-east", L2ConfigID: &l2ConfigID,
		FailoverMode: nodescheduler.FailoverOnlineLessThanBackupCount, Policy: nodescheduler.DefaultHealthPolicy(),
		Endpoints: []nodescheduler.Endpoint{}, ConfigurationDigest: make([]byte, 32),
		CreatedByUserID: userID, CreatedAt: now, SealedAt: now,
	}}
	handler, err := NewHandler(service, &staticAuthenticator{actor: nodescheduler.Actor{
		UserID: userID, ScopeID: scopeID, ScopeKind: "tenant",
	}})
	if err != nil {
		t.Fatal(err)
	}
	body := `{"name":"华东线路","region":"华东","ipv4_resolved_value":"v4-east","l2_config_id":"` + l2ConfigID.String() + `","failover_mode":"online_less_than_backup_count","health_policy":{"probe_interval_ms":10000,"probe_timeout_ms":3000,"failure_threshold":3,"recovery_threshold":3,"failure_debounce_ms":0,"recovery_debounce_ms":0},"endpoints":[]}`
	request := httptest.NewRequest(http.MethodPost, "/v1/node-line-groups", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("If-Match", `"0"`)
	request.Header.Set("Idempotency-Key", "reference-create")
	request.Header.Set("X-Request-ID", "reference-create-request")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusCreated || service.putRequest.L2ConfigID == nil ||
		*service.putRequest.L2ConfigID != l2ConfigID || service.putRequest.FailoverMode != nodescheduler.FailoverOnlineLessThanBackupCount {
		t.Fatalf("status=%d request=%#v body=%s", response.Code, service.putRequest, response.Body.String())
	}
	var payload struct {
		Group lineGroupDTO `json:"group"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Group.IPv4ResolvedValue != "v4-east" || payload.Group.L2ConfigID == nil ||
		*payload.Group.L2ConfigID != l2ConfigID || payload.Group.FailoverMode != nodescheduler.FailoverOnlineLessThanBackupCount {
		t.Fatalf("response group = %#v", payload.Group)
	}
}

func TestReferenceConflictErrorMapping(t *testing.T) {
	status, code, _ := errorMapping(nodescheduler.ErrReferenceConflict)
	if status != http.StatusConflict || code != "node_scheduling_reference_conflict" {
		t.Fatalf("mapping = %d %q", status, code)
	}
}
