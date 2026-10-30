package nodeschedulerhttp

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/fielderr"
	"github.com/cdnca/cdnca/services/control-api/internal/nodescheduler"
	"github.com/google/uuid"
)

// fix-fielderr-be: a located line group refusal keeps 400
// node_scheduling_invalid_request and adds details.field/reason.
func TestWriteErrorNamesLineGroupField(t *testing.T) {
	handler := &Handler{}
	policy := &healthPolicyDTO{}
	for name, check := range map[string]struct {
		err           error
		field, reason string
	}{
		"domain":       {fmt.Errorf("put: %w", fielderr.New(nodescheduler.ErrInvalidInput, "endpoints[2].port", fielderr.OutOfRange)), "endpoints[2].port", fielderr.OutOfRange},
		"handler name": {lineGroupBodyError(lineGroupWriteBody{HealthPolicy: policy}), "name", fielderr.Required},
		"handler node": {lineGroupBodyError(lineGroupWriteBody{Name: "a", HealthPolicy: policy, Endpoints: []endpointDTO{{ID: uuid.New()}}}),
			"endpoints[0].node_id", fielderr.Required},
	} {
		recorder := httptest.NewRecorder()
		handler.writeError(recorder, httptest.NewRequest(http.MethodPost, "/v1/node-line-groups", nil), check.err)
		var body struct {
			Error struct {
				Code    string            `json:"code"`
				Details map[string]string `json:"details"`
			} `json:"error"`
		}
		if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		if recorder.Code != http.StatusBadRequest || body.Error.Code != "node_scheduling_invalid_request" ||
			body.Error.Details["field"] != check.field || body.Error.Details["reason"] != check.reason {
			t.Fatalf("%s: %d %s", name, recorder.Code, recorder.Body.String())
		}
	}
	recorder := httptest.NewRecorder()
	handler.writeError(recorder, httptest.NewRequest(http.MethodPost, "/", nil), nodescheduler.ErrInvalidInput)
	if recorder.Code != http.StatusBadRequest || json.Valid(recorder.Body.Bytes()) && containsDetails(recorder.Body.Bytes()) {
		t.Fatalf("unlocated: %s", recorder.Body.String())
	}
	if lineGroupBodyError(lineGroupWriteBody{Name: "a", HealthPolicy: policy}) != nil {
		t.Fatal("valid body refused")
	}
}

func containsDetails(raw []byte) bool {
	var body struct {
		Error map[string]json.RawMessage `json:"error"`
	}
	_ = json.Unmarshal(raw, &body)
	_, ok := body.Error["details"]
	return ok
}
