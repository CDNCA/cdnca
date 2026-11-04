package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/node"
)

// 删除被拒（node_in_use）带 error.details.reasons，说明被哪个线路组/供货组/L2/任务占用；
// 不带原因的旧形态（外键兜底）仍是没有 details 的 node_in_use。两者都符合 control.yaml 的 ErrorEnvelope。
func TestNodeInUseRefusalNamesReasons(t *testing.T) {
	two, one, three := 2, 1, 3
	refused := &node.InUseError{Reasons: []node.InUseReason{
		{Kind: node.InUseMarketSupply, ID: "018f0000-0000-7000-8000-0000000000aa", Name: "香港 BGP", GroupNodes: &one, NormalSubscriptions: &two},
		{Kind: node.InUseLineGroup, ID: "018f0000-0000-7000-8000-0000000000bb", Name: "华东 A 组"},
		{Kind: node.InUseCacheOperation, Count: &three},
	}}
	server := &Server{}
	write := func(err error) json.RawMessage {
		recorder := httptest.NewRecorder()
		server.writeNodeLifecycleError(recorder, httptest.NewRequest(http.MethodPatch, "/", nil), err)
		if recorder.Code != http.StatusConflict {
			t.Fatalf("status = %d", recorder.Code)
		}
		return json.RawMessage(strings.TrimSpace(recorder.Body.String()))
	}
	detailed, plain := write(refused), write(node.ErrInUse)
	var body struct {
		Error struct {
			Code    string `json:"code"`
			Details *struct {
				Reasons []node.InUseReason `json:"reasons"`
			} `json:"details"`
		} `json:"error"`
	}
	if err := json.Unmarshal(detailed, &body); err != nil {
		t.Fatal(err)
	}
	if body.Error.Code != "node_in_use" || body.Error.Details == nil || len(body.Error.Details.Reasons) != 3 ||
		body.Error.Details.Reasons[0].Name != "香港 BGP" || *body.Error.Details.Reasons[0].NormalSubscriptions != 2 {
		t.Fatalf("node_in_use body = %s", detailed)
	}
	if strings.Contains(string(plain), `"details"`) {
		t.Fatalf("plain node_in_use body has details: %s", plain)
	}
	if _, err := exec.LookPath("node"); err != nil {
		t.Skip("node is not installed")
	}
	assertOpenAPIErrorBodies(t, "../../../../api/openapi/v1/control.yaml", "ErrorEnvelope",
		[]json.RawMessage{detailed, plain},
		[]json.RawMessage{
			json.RawMessage(`{"error":{"code":"node_in_use","message":"m","request_id":"r","details":{"reasons":[]}}}`),
			json.RawMessage(`{"error":{"code":"node_in_use","message":"m","request_id":"r","details":{"reasons":[{"kind":"site"}]}}}`),
		})
}
