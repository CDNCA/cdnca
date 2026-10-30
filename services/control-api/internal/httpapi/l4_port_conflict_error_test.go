package httpapi

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/l4forward"
)

// 端口冲突说明位置: a located stream port conflict keeps the 409
// stream_port_conflict code and adds where (protocol, ports, with, name).
func TestStreamPortConflictNamesTheLocation(t *testing.T) {
	server := &Server{}
	for name, check := range map[string]struct {
		err  error
		want string
	}{
		"range over a site": {fmt.Errorf("save: %w", &l4forward.PortConflictError{Protocol: "tcp", Port: 8080, With: l4forward.PortConflictSite, Name: "a.example.com"}),
			`{"protocol":"tcp","port":8080,"with":"site","name":"a.example.com"}`},
		"range over a stream": {&l4forward.PortConflictError{Protocol: "udp", Port: 20000, PortEnd: 20010, With: l4forward.PortConflictStream},
			`{"protocol":"udp","port":20000,"port_end":20010,"with":"stream"}`},
		"reserved": {&l4forward.PortConflictError{Protocol: "tcp", Port: 443, With: l4forward.PortConflictReserved},
			`{"protocol":"tcp","port":443,"with":"reserved"}`},
	} {
		recorder := httptest.NewRecorder()
		server.writeError(recorder, httptest.NewRequest(http.MethodPost, "/v1/streams", nil), check.err)
		var body struct {
			Error struct {
				Code    string          `json:"code"`
				Message string          `json:"message"`
				Details json.RawMessage `json:"details"`
			} `json:"error"`
		}
		if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		if recorder.Code != http.StatusConflict || body.Error.Code != "stream_port_conflict" ||
			string(body.Error.Details) != check.want || body.Error.Message == "" {
			t.Fatalf("%s: %d %s", name, recorder.Code, recorder.Body.String())
		}
	}
	recorder := httptest.NewRecorder()
	server.writeError(recorder, httptest.NewRequest(http.MethodPost, "/v1/streams", nil), l4forward.ErrPortConflict)
	if recorder.Code != http.StatusConflict || jsonHasKey(t, recorder.Body.Bytes(), "details") {
		t.Fatalf("unlocated conflict: %d %s", recorder.Code, recorder.Body.String())
	}
}

func jsonHasKey(t *testing.T, raw []byte, key string) bool {
	t.Helper()
	var body struct {
		Error map[string]json.RawMessage `json:"error"`
	}
	if err := json.Unmarshal(raw, &body); err != nil {
		t.Fatal(err)
	}
	_, ok := body.Error[key]
	return ok
}
