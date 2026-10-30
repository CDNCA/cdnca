package observabilitylog

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

type fakeRepository09 struct {
	rows           []Fact
	query          StoreQuery
	queries        []StoreQuery
	frontends      []FrontendFact
	listCalls      int
	auditHeads     []int64
	auditHeadCalls int
	auditHeadErr   error
	list           func(StoreQuery) []Fact
}

func (repository *fakeRepository09) ListFacts(_ context.Context, query StoreQuery) ([]Fact, error) {
	repository.listCalls++
	repository.query = query
	repository.queries = append(repository.queries, query)
	if repository.list != nil {
		return repository.list(query), nil
	}
	return append([]Fact(nil), repository.rows...), nil
}

func (repository *fakeRepository09) AppendFrontend(_ context.Context, fact FrontendFact) error {
	repository.frontends = append(repository.frontends, fact)
	return nil
}

func (repository *fakeRepository09) AuditHead(_ context.Context, _ uuid.UUID) (int64, error) {
	repository.auditHeadCalls++
	if repository.auditHeadErr != nil {
		return 0, repository.auditHeadErr
	}
	if len(repository.auditHeads) == 0 {
		return 0, nil
	}
	value := repository.auditHeads[0]
	repository.auditHeads = repository.auditHeads[1:]
	return value, nil
}

func TestOBS09OpaqueAuditBoundaryBindsAuthorityAndFreezesUpperHead(t *testing.T) {
	now := time.Date(2026, 8, 9, 9, 0, 0, 0, time.UTC)
	targetScopeID, authorityID, browserActorID := uuid.New(), uuid.New(), uuid.New()
	repository := &fakeRepository09{auditHeads: []int64{7, 11, 99}}
	repository.list = func(query StoreQuery) []Fact {
		return []Fact{
			{ID: "event-2", ScopeID: targetScopeID, Kind: KindOperation, ActorUserID: &browserActorID,
				Action: "site.update", ReasonCode: "site.update", ResultCode: "denied", SourceIP: "unknown", GeoCode: "unknown", OccurredAt: now.Add(-time.Second)},
			{ID: "event-1", ScopeID: targetScopeID, Kind: KindOperation, ActorUserID: &browserActorID,
				Action: "site.create", ReasonCode: "site.create", ResultCode: "success", SourceIP: "unknown", GeoCode: "unknown", OccurredAt: now.Add(-2 * time.Second)},
		}
	}
	service, err := NewService(repository, []byte("0123456789abcdef0123456789abcdef"), func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	authority := Actor{UserID: authorityID, ScopeID: uuid.New(), ScopeKind: ScopePlatform, SessionID: uuid.New(), Permissions: []string{"platform.admin"}}
	boundary, err := service.CaptureAuditBoundary(t.Context(), authority, targetScopeID)
	if err != nil || boundary.Token == "" || strings.Contains(boundary.Token, "\"audit_head\"") || strings.Contains(boundary.Token, "stream_position") {
		t.Fatalf("boundary=%#v err=%v", boundary, err)
	}
	first, err := service.List(t.Context(), authority, Query{TargetScopeID: &targetScopeID, Kinds: []Kind{KindOperation},
		AuditActorUserID: &browserActorID, AfterAuditBoundary: boundary.Token, Limit: 1})
	if err != nil || len(first.Items) != 1 || first.NextCursor == "" {
		t.Fatalf("first=%#v err=%v", first, err)
	}
	if repository.query.AuditAfterPosition != 7 || repository.query.AuditThroughPosition != 11 ||
		repository.query.ExactActorUserID == nil || *repository.query.ExactActorUserID != browserActorID {
		t.Fatalf("first store query=%#v", repository.query)
	}
	repository.list = func(query StoreQuery) []Fact {
		return []Fact{{ID: "event-1", ScopeID: targetScopeID, Kind: KindOperation, ActorUserID: &browserActorID,
			Action: "site.create", ReasonCode: "site.create", ResultCode: "success", SourceIP: "unknown", GeoCode: "unknown", OccurredAt: now.Add(-2 * time.Second)}}
	}
	second, err := service.List(t.Context(), authority, Query{TargetScopeID: &targetScopeID, Kinds: []Kind{KindOperation},
		AuditActorUserID: &browserActorID, AfterAuditBoundary: boundary.Token, Limit: 1, Cursor: first.NextCursor})
	if err != nil || len(second.Items) != 1 || second.NextCursor != "" || repository.query.AuditThroughPosition != 11 || repository.auditHeadCalls != 2 {
		t.Fatalf("second=%#v query=%#v head_calls=%d err=%v", second, repository.query, repository.auditHeadCalls, err)
	}

	for name, mutate := range map[string]func(Actor, *uuid.UUID, string) (Actor, *uuid.UUID, string){
		"wrong user": func(actor Actor, target *uuid.UUID, token string) (Actor, *uuid.UUID, string) {
			actor.UserID = uuid.New()
			return actor, target, token
		},
		"wrong session": func(actor Actor, target *uuid.UUID, token string) (Actor, *uuid.UUID, string) {
			actor.SessionID = uuid.New()
			return actor, target, token
		},
		"wrong scope": func(actor Actor, _ *uuid.UUID, token string) (Actor, *uuid.UUID, string) {
			other := uuid.New()
			return actor, &other, token
		},
		"tampered": func(actor Actor, target *uuid.UUID, token string) (Actor, *uuid.UUID, string) {
			return actor, target, token + "x"
		},
	} {
		t.Run(name, func(t *testing.T) {
			actor, target, token := mutate(authority, &targetScopeID, boundary.Token)
			_, err := service.List(t.Context(), actor, Query{TargetScopeID: target, Kinds: []Kind{KindOperation},
				AuditActorUserID: &browserActorID, AfterAuditBoundary: token})
			if !errors.Is(err, ErrInvalidCursor) {
				t.Fatalf("error=%v", err)
			}
		})
	}
}

func TestOBS09AuditBoundaryRejectsUnsafeModesAndDependencies(t *testing.T) {
	now := time.Date(2026, 8, 9, 10, 0, 0, 0, time.UTC)
	targetScopeID, actorID := uuid.New(), uuid.New()
	repository := &fakeRepository09{auditHeads: []int64{1}}
	service, err := NewService(repository, []byte("0123456789abcdef0123456789abcdef"), func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	authority := Actor{UserID: uuid.New(), ScopeID: uuid.New(), ScopeKind: ScopePlatform, SessionID: uuid.New(), Permissions: []string{"platform.admin"}}
	boundary, err := service.CaptureAuditBoundary(t.Context(), authority, targetScopeID)
	if err != nil {
		t.Fatal(err)
	}
	for name, input := range map[string]Query{
		"missing exact actor": {TargetScopeID: &targetScopeID, Kinds: []Kind{KindOperation}, AfterAuditBoundary: boundary.Token},
		"notification only":   {TargetScopeID: &targetScopeID, Kinds: []Kind{KindNotification}, AuditActorUserID: &actorID, AfterAuditBoundary: boundary.Token},
		"mixed notification":  {TargetScopeID: &targetScopeID, Kinds: []Kind{KindOperation, KindNotification}, AuditActorUserID: &actorID, AfterAuditBoundary: boundary.Token},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := service.List(t.Context(), authority, input); !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("error=%v", err)
			}
		})
	}
	repository.auditHeadErr = errors.New("postgres secret must not escape")
	if _, err := service.CaptureAuditBoundary(t.Context(), authority, targetScopeID); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("capture dependency error=%v", err)
	}
}

func TestOBS09ScopeCursorAndUnsafeFactsFailClosed(t *testing.T) {
	now := time.Date(2026, 8, 7, 10, 0, 0, 0, time.UTC)
	scopeID, userID, sessionID := uuid.New(), uuid.New(), uuid.New()
	repository := &fakeRepository09{rows: []Fact{
		{ID: "event-2", ScopeID: scopeID, Kind: KindOperation, ActorUserID: &userID, Action: "site.update", ReasonCode: "site.update", ResultCode: "success", SourceIP: "192.0.2.2", GeoCode: "unknown", OccurredAt: now.Add(-time.Minute)},
		{ID: "event-1", ScopeID: scopeID, Kind: KindLogin, ActorUserID: &userID, Action: "auth.login", ReasonCode: "credentials_accepted", ResultCode: "success", SourceIP: "192.0.2.1", GeoCode: "CN", OccurredAt: now.Add(-2 * time.Minute)},
	}}
	service, err := NewService(repository, []byte("0123456789abcdef0123456789abcdef"), func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	actor := Actor{UserID: userID, ScopeID: scopeID, ScopeKind: ScopeTenant, SessionID: sessionID, Permissions: []string{"identity.self.read"}}

	foreign := uuid.New()
	_, err = service.List(t.Context(), actor, Query{TargetScopeID: &foreign, Limit: 1})
	if !errors.Is(err, ErrPermissionDenied) || repository.listCalls != 0 {
		t.Fatalf("foreign scope result=(%v,%d)", err, repository.listCalls)
	}
	page, err := service.List(t.Context(), actor, Query{Kinds: []Kind{KindLogin, KindOperation}, Limit: 1})
	if err != nil || len(page.Items) != 1 || page.NextCursor == "" {
		t.Fatalf("first page=%#v err=%v", page, err)
	}
	otherSession := actor
	otherSession.SessionID = uuid.New()
	_, err = service.List(t.Context(), otherSession, Query{Kinds: []Kind{KindLogin, KindOperation}, Limit: 1, Cursor: page.NextCursor})
	if !errors.Is(err, ErrInvalidCursor) {
		t.Fatalf("cross-session cursor err=%v", err)
	}

	repository.rows = []Fact{{ID: "unsafe", ScopeID: scopeID, Kind: KindOperation, ActorUserID: &userID, Action: "site.update", ReasonCode: "site.update", ResultCode: "raw provider detail", SourceIP: "unknown", GeoCode: "unknown", OccurredAt: now.Add(-time.Minute)}}
	_, err = service.List(t.Context(), actor, Query{Limit: 10})
	if !errors.Is(err, ErrUnsafeFact) {
		t.Fatalf("unsafe result err=%v", err)
	}
}

func TestOBS09AccountLogFiltersAndProjectionStayBoundToCursor(t *testing.T) {
	now := time.Date(2026, 8, 27, 10, 0, 0, 0, time.UTC)
	scopeID, userID := uuid.New(), uuid.New()
	repository := &fakeRepository09{rows: []Fact{{
		ID: "event-1", ScopeID: scopeID, Kind: KindOperation, ActorUserID: &userID,
		Action: "site.update", ReasonCode: "site.update", ResultCode: "success", ResourceType: "site",
		ResourceID: "site-1", ChangeSummary: `{"revision":2}`, SourceIP: "192.0.2.1", GeoCode: "CN",
		OccurredAt: now.Add(-time.Minute), TotalCount: 1,
	}}}
	service, err := NewService(repository, []byte("0123456789abcdef0123456789abcdef"), func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	actor := Actor{UserID: userID, ScopeID: scopeID, ScopeKind: ScopeTenant, SessionID: uuid.New(), Permissions: []string{"identity.self.read"}}
	input := Query{Kinds: []Kind{KindOperation}, ActionVerb: "update", ResourceType: "site", ResourceID: "site-1", Change: "revision", Limit: 10}

	page, err := service.List(t.Context(), actor, input)
	if err != nil || page.TotalCount != 1 || len(page.Items) != 1 {
		t.Fatalf("page=%#v err=%v", page, err)
	}
	if repository.query.ActionVerb != "update" || repository.query.ResourceType != "site" ||
		repository.query.ResourceID != "site-1" || repository.query.Change != "revision" || repository.query.ResultCodes == nil {
		t.Fatalf("store query=%#v", repository.query)
	}
	platform := Actor{UserID: uuid.New(), ScopeID: uuid.New(), ScopeKind: ScopePlatform, SessionID: uuid.New(), Permissions: []string{"platform.admin"}}
	page, err = service.List(t.Context(), platform, Query{TargetScopeID: &scopeID, Kinds: []Kind{KindOperation}, AuditActorUserID: &userID, Limit: 10})
	if err != nil || page.TotalCount != 1 || repository.query.ExactActorUserID == nil || *repository.query.ExactActorUserID != userID {
		t.Fatalf("platform page=%#v query=%#v err=%v", page, repository.query, err)
	}

	for name, mutate := range map[string]func(Query) Query{
		"action":        func(value Query) Query { value.ActionVerb = "execute"; return value },
		"resource type": func(value Query) Query { value.ResourceType = "site type"; return value },
		"resource id":   func(value Query) Query { value.ResourceID = strings.Repeat("x", 257); return value },
		"change":        func(value Query) Query { value.Change = "revision\nsecret"; return value },
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := service.List(t.Context(), actor, mutate(input)); !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("error=%v", err)
			}
		})
	}
}

func TestOBS09TenantFactsRequireExactActorOrSubjectWhilePlatformKeepsExactScope(t *testing.T) {
	now := time.Date(2026, 8, 8, 10, 0, 0, 0, time.UTC)
	scopeID, userID, sessionID := uuid.New(), uuid.New(), uuid.New()
	otherUserID := uuid.New()
	repository := &fakeRepository09{rows: []Fact{
		{ID: "actor-fact", ScopeID: scopeID, Kind: KindOperation, ActorUserID: &userID,
			Action: "site.update", ReasonCode: "site.update", ResultCode: "success",
			SourceIP: "192.0.2.1", GeoCode: "unknown", OccurredAt: now.Add(-time.Minute)},
		{ID: "subject-fact", ScopeID: scopeID, Kind: KindNotification, ActorUserID: &otherUserID,
			SubjectUserID: userID.String(), Action: "notification.delivered", ReasonCode: "delivered",
			ResultCode: "delivered", SourceIP: "unknown", GeoCode: "unknown", OccurredAt: now.Add(-2 * time.Minute)},
	}}
	service, err := NewService(repository, []byte("0123456789abcdef0123456789abcdef"), func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	tenant := Actor{UserID: userID, ScopeID: scopeID, ScopeKind: ScopeTenant, SessionID: sessionID,
		Permissions: []string{"identity.self.read"}}
	page, err := service.List(t.Context(), tenant, Query{Kinds: []Kind{KindOperation, KindNotification}})
	if err != nil || len(page.Items) != 2 {
		t.Fatalf("tenant page=%#v err=%v", page, err)
	}
	if repository.query.ActorUserID == nil || *repository.query.ActorUserID != userID {
		t.Fatalf("tenant store query actor=%v", repository.query.ActorUserID)
	}

	repository.rows = []Fact{{ID: "foreign", ScopeID: scopeID, Kind: KindOperation, ActorUserID: &otherUserID,
		Action: "site.update", ReasonCode: "site.update", ResultCode: "success",
		SourceIP: "192.0.2.2", GeoCode: "unknown", OccurredAt: now.Add(-time.Minute)}}
	if _, err := service.List(t.Context(), tenant, Query{}); !errors.Is(err, ErrUnsafeFact) {
		t.Fatalf("foreign tenant fact err=%v", err)
	}

	platformScopeID := uuid.New()
	platform := Actor{UserID: uuid.New(), ScopeID: platformScopeID, ScopeKind: ScopePlatform,
		SessionID: uuid.New(), Permissions: []string{"platform.admin"}}
	repository.rows[0].ScopeID = scopeID
	if _, err := service.List(t.Context(), platform, Query{TargetScopeID: &scopeID}); err != nil {
		t.Fatalf("platform exact-scope list err=%v", err)
	}
	if repository.query.ScopeID != scopeID || repository.query.ActorUserID != nil {
		t.Fatalf("platform store query=%#v", repository.query)
	}
}

func TestOBS09FrontendAndCSVExcludeSensitivePayloads(t *testing.T) {
	now := time.Date(2026, 8, 7, 10, 0, 0, 0, time.UTC)
	scopeID, userID, sessionID := uuid.New(), uuid.New(), uuid.New()
	repository := &fakeRepository09{rows: []Fact{{ID: "event-1", ScopeID: scopeID, Kind: KindNotification, SubjectUserID: userID.String(), Action: "notification.provider_delivered", ReasonCode: "provider_delivered", ResultCode: "delivered", SourceIP: "unknown", GeoCode: "unknown", OccurredAt: now.Add(-time.Minute)}}}
	service, err := NewService(repository, []byte("0123456789abcdef0123456789abcdef"), func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	actor := Actor{UserID: userID, ScopeID: scopeID, ScopeKind: ScopeTenant, SessionID: sessionID, Permissions: []string{"identity.self.read"}, RequestID: "request-1", SourceIP: "2001:db8::1"}
	if err := service.RecordFrontend(t.Context(), actor, FrontendInput{EventCode: "render_error", Route: "/home", ReasonCode: "component_failed", ResultCode: "failure", Release: "2026.08.07"}); err != nil {
		t.Fatal(err)
	}
	if len(repository.frontends) != 1 || repository.frontends[0].ScopeID != scopeID || repository.frontends[0].SourceIP != "2001:db8::1" {
		t.Fatalf("frontend=%#v", repository.frontends)
	}
	if err := service.RecordFrontend(t.Context(), actor, FrontendInput{EventCode: "custom-secret", Route: "/home", ReasonCode: "x", ResultCode: "failure"}); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("unknown frontend code err=%v", err)
	}
	for _, route := range []string{"/home?token=secret", "/home#private"} {
		if err := service.RecordFrontend(t.Context(), actor, FrontendInput{EventCode: "render_error", Route: route,
			ReasonCode: "component_failed", ResultCode: "failure", Release: "2026.08.07"}); !errors.Is(err, ErrInvalidInput) {
			t.Fatalf("unsafe frontend route %q err=%v", route, err)
		}
	}
	if len(repository.frontends) != 1 {
		t.Fatalf("unsafe frontend routes persisted: %#v", repository.frontends)
	}

	artifact, err := service.Export(t.Context(), actor, Query{Limit: 50})
	if err != nil {
		t.Fatal(err)
	}
	text := string(artifact.Content)
	if !strings.HasPrefix(text, "event_id,occurred_at,kind") || strings.Contains(strings.ToLower(text), "body") || strings.Contains(strings.ToLower(text), "secret") || len(artifact.SHA256) != 64 {
		t.Fatalf("unsafe CSV %q digest=%q", text, artifact.SHA256)
	}
}

func TestOBS09ExportFreezesDefaultWindowAcrossPages(t *testing.T) {
	started := time.Date(2026, 8, 8, 11, 0, 0, 0, time.UTC)
	clockCalls := 0
	scopeID, userID := uuid.New(), uuid.New()
	repository := &fakeRepository09{}
	repository.list = func(query StoreQuery) []Fact {
		if repository.listCalls > 1 {
			return nil
		}
		rows := make([]Fact, maxPageSize+1)
		for index := range rows {
			rows[index] = Fact{ID: fmt.Sprintf("event-%03d", maxPageSize-index), ScopeID: scopeID,
				Kind: KindOperation, ActorUserID: &userID, Action: "site.update", ReasonCode: "site.update",
				ResultCode: "success", ResourceType: "site", ResourceID: fmt.Sprintf("site-%03d", index),
				RequestID: fmt.Sprintf("request-%03d", index), SourceIP: "192.0.2.1", GeoCode: "unknown",
				OccurredAt: query.SnapshotAt.Add(-time.Duration(index+1) * time.Second)}
		}
		return rows
	}
	service, err := NewService(repository, []byte("0123456789abcdef0123456789abcdef"), func() time.Time {
		value := started.Add(time.Duration(clockCalls) * time.Minute)
		clockCalls++
		return value
	})
	if err != nil {
		t.Fatal(err)
	}
	actor := Actor{UserID: userID, ScopeID: scopeID, ScopeKind: ScopeTenant, SessionID: uuid.New(),
		Permissions: []string{"identity.self.read"}}
	if _, err := service.Export(t.Context(), actor, Query{}); err != nil {
		t.Fatalf("multi-page export with advancing clock: %v", err)
	}
	if len(repository.queries) != 2 {
		t.Fatalf("export queries=%d", len(repository.queries))
	}
	first, second := repository.queries[0], repository.queries[1]
	if !first.From.Equal(second.From) || !first.To.Equal(second.To) || !first.SnapshotAt.Equal(second.SnapshotAt) {
		t.Fatalf("export window drifted: first=%#v second=%#v", first, second)
	}
}

func TestOBS09FactsRejectUnsafeEventRequestAndResourceFields(t *testing.T) {
	now := time.Date(2026, 8, 8, 12, 0, 0, 0, time.UTC)
	scopeID, userID := uuid.New(), uuid.New()
	base := Fact{ID: "event-1", ScopeID: scopeID, Kind: KindOperation, ActorUserID: &userID,
		Action: "site.update", ReasonCode: "site.update", ResultCode: "success", ResourceType: "site",
		ResourceID: "site-1", RequestID: "request-1", SourceIP: "192.0.2.1", GeoCode: "unknown",
		OccurredAt: now.Add(-time.Minute)}
	tests := map[string]func(*Fact){
		"event control":     func(fact *Fact) { fact.ID = "event-1\r\nsecret" },
		"request control":   func(fact *Fact) { fact.RequestID = "request-1\nsecret" },
		"request unbounded": func(fact *Fact) { fact.RequestID = strings.Repeat("r", 129) },
		"resource type":     func(fact *Fact) { fact.ResourceType = "site secret" },
		"resource control":  func(fact *Fact) { fact.ResourceID = "site-1\x00secret" },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			fact := base
			mutate(&fact)
			repository := &fakeRepository09{rows: []Fact{fact}}
			service, err := NewService(repository, []byte("0123456789abcdef0123456789abcdef"), func() time.Time { return now })
			if err != nil {
				t.Fatal(err)
			}
			actor := Actor{UserID: userID, ScopeID: scopeID, ScopeKind: ScopeTenant, SessionID: uuid.New(),
				Permissions: []string{"identity.self.read"}}
			if _, err := service.List(t.Context(), actor, Query{}); !errors.Is(err, ErrUnsafeFact) {
				t.Fatalf("unsafe fact err=%v fact=%#v", err, fact)
			}
		})
	}
}
