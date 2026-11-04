package nodeschedulerhttp

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/nodescheduler"
)

// A refused line group delete keeps 409
// node_scheduling_reference_conflict and names what still routes to it.
func TestWriteErrorNamesLineGroupReferences(t *testing.T) {
	handler := &Handler{}
	inUse := &nodescheduler.LineGroupInUseError{Products: []string{"香港 2G", "香港 5G"}, Subscriptions: 2, Sites: 1, Streams: 3,
		Other: []string{nodescheduler.LineGroupUseFallbackLastResort}}
	recorder := httptest.NewRecorder()
	handler.writeError(recorder, httptest.NewRequest(http.MethodDelete, "/v1/node-line-groups/x", nil),
		fmt.Errorf("delete node line group: %w", inUse))
	var body struct {
		Error struct {
			Code    string `json:"code"`
			Details struct {
				Products      []string `json:"products"`
				Subscriptions int      `json:"subscriptions"`
				Sites         int      `json:"sites"`
				Streams       int      `json:"streams"`
				Other         []string `json:"other"`
			} `json:"details"`
		} `json:"error"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	details := body.Error.Details
	if recorder.Code != http.StatusConflict || body.Error.Code != "node_scheduling_reference_conflict" ||
		fmt.Sprint(details.Products) != "[香港 2G 香港 5G]" || details.Subscriptions != 2 || details.Sites != 1 ||
		details.Streams != 3 || fmt.Sprint(details.Other) != "[fallback_last_resort]" {
		t.Fatalf("%d %s", recorder.Code, recorder.Body.String())
	}
	// Any other reference conflict stays without details.
	recorder = httptest.NewRecorder()
	handler.writeError(recorder, httptest.NewRequest(http.MethodDelete, "/", nil), nodescheduler.ErrMarketSupplyInUse)
	if recorder.Code != http.StatusConflict || containsDetails(recorder.Body.Bytes()) {
		t.Fatalf("plain conflict: %d %s", recorder.Code, recorder.Body.String())
	}
}
