package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/identity"
)

// A password that breaks libs/passwordpolicy is 400 password_policy_unmet
// with the unmet items; any other invalid user input stays validation_error.
func TestPasswordPolicyErrorCarriesUnmetItems(t *testing.T) {
	server := &Server{}
	recorder := httptest.NewRecorder()
	server.writeError(recorder, httptest.NewRequest(http.MethodPost, "/v1/users", nil), identity.CheckNewPassword("1234567"))
	var body struct {
		Error struct {
			Code    string `json:"code"`
			Details struct {
				Unmet []string `json:"unmet"`
			} `json:"details"`
		} `json:"error"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if recorder.Code != http.StatusBadRequest || body.Error.Code != "password_policy_unmet" ||
		!reflect.DeepEqual(body.Error.Details.Unmet, []string{"length", "character_classes"}) {
		t.Fatalf("response %d %s", recorder.Code, recorder.Body.String())
	}
	recorder = httptest.NewRecorder()
	server.writeError(recorder, httptest.NewRequest(http.MethodPost, "/v1/users", nil), identity.ErrInvalidUserInput)
	if recorder.Code != http.StatusBadRequest || json.Unmarshal(recorder.Body.Bytes(), &body) != nil ||
		body.Error.Code != "validation_error" {
		t.Fatalf("plain invalid input %d %s", recorder.Code, recorder.Body.String())
	}
}
