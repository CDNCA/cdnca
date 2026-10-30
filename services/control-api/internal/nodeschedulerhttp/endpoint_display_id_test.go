package nodeschedulerhttp

import (
	"encoding/json"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/nodescheduler"
	"github.com/google/uuid"
)

func TestEndpointDisplayIDReadOnlyAndLegacyReceipt(t *testing.T) {
	id := uuid.New()
	view := endpointView(nodescheduler.Endpoint{ID: id, DisplayID: "42"})
	if view.DisplayID != "42" {
		t.Fatal("server display ID omitted from response")
	}
	body := lineGroupWriteBody{Endpoints: []endpointDTO{{ID: id, DisplayID: "999"}}}
	request := body.request(uuid.New(), 1, "display-id-test", "display-id-test")
	if request.Endpoints[0].DisplayID != "" {
		t.Fatal("client display ID trusted")
	}
	raw, err := json.Marshal(endpointView(nodescheduler.Endpoint{ID: id}))
	if err != nil {
		t.Fatal(err)
	}
	var legacy map[string]any
	if err := json.Unmarshal(raw, &legacy); err != nil {
		t.Fatal(err)
	}
	if _, exists := legacy["display_id"]; exists {
		t.Fatal("legacy receipt given a fabricated display ID")
	}
}
