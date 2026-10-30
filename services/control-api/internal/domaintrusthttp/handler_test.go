package domaintrusthttp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/domainblocklist"
	"github.com/cdnca/cdnca/services/control-api/internal/domainownership"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/google/uuid"
)

func TestParseLines(t *testing.T) {
	items, err := parseLines([]byte("# header\nexample.com\nwww.x.com,exact,\"bad, actor\"\n\n"))
	if err != nil || len(items) != 2 || items[0].Pattern != "example.com" || items[0].MatchType != "" ||
		items[1].MatchType != "exact" || items[1].Reason != "bad, actor" {
		t.Fatalf("parseLines = %+v, %v", items, err)
	}
	if _, err := parseLines([]byte("a.com,root,x,extra\n")); err == nil {
		t.Fatal("four columns accepted")
	}
}

func TestSessionKindAndErrorMapping(t *testing.T) {
	tenant := identity.AuthenticatedSession{SessionID: uuid.New(),
		Principal: identity.Principal{UserID: uuid.New(), ScopeID: uuid.New(), ScopeKind: "tenant"}}
	handler := &Handler{authenticate: func(_ context.Context, token string) (identity.AuthenticatedSession, error) {
		if token != "good" {
			return identity.AuthenticatedSession{}, errors.New("bad")
		}
		return tenant, nil
	}}
	for _, item := range []struct {
		auth, kind string
		status     int
	}{{"", "tenant", 401}, {"Bearer bad", "tenant", 401}, {"Bearer good", "platform", 403}, {"Bearer good", "tenant", 0}} {
		request := httptest.NewRequest(http.MethodGet, "/", nil)
		if item.auth != "" {
			request.Header.Set("Authorization", item.auth)
		}
		recorder := httptest.NewRecorder()
		_, ok := handler.session(recorder, request, item.kind)
		if ok != (item.status == 0) || (item.status != 0 && recorder.Code != item.status) {
			t.Fatalf("%q/%s: ok=%v code=%d", item.auth, item.kind, ok, recorder.Code)
		}
	}
	for _, item := range []struct {
		err    error
		status int
		code   string
	}{
		{domainownership.ErrVerifiedByOther, 409, "domain_verified_by_other"},
		{domainownership.ErrBlocked, 422, "domain_blocked"},
		{domainownership.ErrClaimRequiresTXT, 409, "domain_claim_requires_dns_txt"},
		{domainblocklist.ErrConflict, 409, "domain_blocklist_conflict"},
		{errors.New("boom"), 503, "domain_trust_unavailable"},
	} {
		recorder := httptest.NewRecorder()
		writeServiceError(recorder, httptest.NewRequest(http.MethodGet, "/", nil), item.err)
		var body struct {
			Error struct{ Code string } `json:"error"`
		}
		_ = json.NewDecoder(bytes.NewReader(recorder.Body.Bytes())).Decode(&body)
		if recorder.Code != item.status || body.Error.Code != item.code {
			t.Fatalf("%v -> %d %s", item.err, recorder.Code, body.Error.Code)
		}
	}
}
