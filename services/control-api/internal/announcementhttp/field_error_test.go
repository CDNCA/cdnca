package announcementhttp

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/announcement"
	"github.com/cdnca/cdnca/services/control-api/internal/fielderr"
)

// fix-fielderr-be4: a located announcement refusal keeps 400 validation_error
// and adds error.details {field, reason}; an unlocated one has no details.
func TestCoreErrorCarriesLocatedField(t *testing.T) {
	for name, check := range map[string]struct {
		err           error
		field, reason string
	}{
		"content":   {fmt.Errorf("create: %w", fielderr.New(announcement.ErrInvalidContent, "title", fielderr.TooLong)), "title", fielderr.TooLong},
		"audience":  {fielderr.New(announcement.ErrInvalidAudience, "user_ids", fielderr.Required), "user_ids", fielderr.Required},
		"unlocated": {announcement.ErrInvalidInput, "", ""},
	} {
		t.Run(name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			writeCoreError(recorder, httptest.NewRequest(http.MethodPost, "/v1/announcements", nil), check.err)
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
			if recorder.Code != http.StatusBadRequest || body.Error.Code != "validation_error" {
				t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
			}
			if check.field == "" {
				if body.Error.Details != nil {
					t.Fatalf("unlocated has details: %s", recorder.Body.String())
				}
				return
			}
			if body.Error.Details == nil || body.Error.Details.Field != check.field || body.Error.Details.Reason != check.reason {
				t.Fatalf("details: %s", recorder.Body.String())
			}
		})
	}
}
