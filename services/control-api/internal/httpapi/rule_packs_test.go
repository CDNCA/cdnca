package httpapi

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/cdnca/cdnca/libs/rulepack"
	"github.com/cdnca/cdnca/services/control-api/internal/rulepackcontrol"
)

func TestRulePackErrorMapping(t *testing.T) {
	server := &Server{}
	conflict := &rulepackcontrol.ConflictError{Resolution: rulepack.Resolution{Conflicts: []rulepack.Conflict{{
		Code: rulepack.ConflictOppositeAction, Sides: []rulepack.ConflictSide{{PackID: "system/a"}, {PackID: "system/b"}},
		Remedies: []rulepack.Remedy{{Action: "disable_pack", At: rulepack.LevelRef{Level: rulepack.LevelPlatform}, PackID: "system/a"}},
	}}}}
	cases := []struct {
		err    error
		status int
		code   string
	}{
		{conflict, http.StatusUnprocessableEntity, "rule_pack_conflict"},
		{fmt.Errorf("wrapped: %w", rulepackcontrol.ErrInvalidInput), http.StatusBadRequest, "validation_error"},
		{rulepackcontrol.ErrNotFound, http.StatusNotFound, "not_found"},
		{rulepackcontrol.ErrPermissionDenied, http.StatusForbidden, "forbidden"},
		{rulepackcontrol.ErrLocked, http.StatusConflict, "rule_pack_locked"},
		{rulepackcontrol.ErrInUse, http.StatusConflict, "rule_pack_in_use"},
		{rulepackcontrol.ErrExists, http.StatusConflict, "rule_pack_version_exists"},
	}
	for _, item := range cases {
		recorder := httptest.NewRecorder()
		server.writeRulePackError(recorder, httptest.NewRequest(http.MethodGet, "/v1/rule-packs", nil), item.err)
		var body struct {
			Error struct {
				Code       string              `json:"code"`
				Resolution rulepack.Resolution `json:"resolution"`
			} `json:"error"`
		}
		if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		if recorder.Code != item.status || body.Error.Code != item.code {
			t.Errorf("%v -> %d %s", item.err, recorder.Code, body.Error.Code)
		}
		if item.err == error(conflict) && (len(body.Error.Resolution.Conflicts) != 1 ||
			len(body.Error.Resolution.Conflicts[0].Sides) != 2 || body.Error.Resolution.Conflicts[0].Remedies[0].Action != "disable_pack") {
			t.Errorf("conflict body = %s", recorder.Body.String())
		}
	}
}
