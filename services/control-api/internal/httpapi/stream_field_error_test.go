package httpapi

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/l4forward"
)

// fp-role L4-006：四层转发参数错误带出 details.field/reason，前端据此定位字段；无法定位的仍是原来的通用 400。
func TestWriteErrorNamesTheRefusedStreamField(t *testing.T) {
	for _, test := range []struct {
		err   error
		field string
	}{
		{err: fmt.Errorf("create stream: %w", &l4forward.FieldError{Field: "upstream_host", Reason: "invalid"}), field: "upstream_host"},
		{err: l4forward.ErrInvalidInput},
	} {
		recorder := httptest.NewRecorder()
		(&Server{}).writeError(recorder, httptest.NewRequest(http.MethodPost, "/v1/streams", nil), test.err)
		if recorder.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", recorder.Code)
		}
		var body struct {
			Error struct {
				Code    string `json:"code"`
				Details *struct {
					Field  string `json:"field"`
					Reason string `json:"reason"`
				} `json:"details"`
			} `json:"error"`
		}
		if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		if body.Error.Code != "validation_error" {
			t.Fatalf("code = %q", body.Error.Code)
		}
		if test.field == "" {
			if body.Error.Details != nil {
				t.Fatalf("unlocated error has details %+v", body.Error.Details)
			}
			continue
		}
		if body.Error.Details == nil || body.Error.Details.Field != test.field || body.Error.Details.Reason != "invalid" {
			t.Fatalf("details = %+v, want %s/invalid", body.Error.Details, test.field)
		}
	}
}
