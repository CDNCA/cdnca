package qualitydiagnostics

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/analyticslog"
	"github.com/cdnca/cdnca/services/control-api/internal/analyticsrealtime"
	"github.com/google/uuid"
)

var (
	testTenantID       = uuid.MustParse("018f0000-0000-7000-8000-000000000001")
	testOtherTenantID  = uuid.MustParse("018f0000-0000-7000-8000-000000000002")
	testSiteID         = uuid.MustParse("018f0000-0000-7000-8000-000000000003")
	testNodeID         = uuid.MustParse("018f0000-0000-7000-8000-000000000004")
	testInstallationID = uuid.MustParse("018f0000-0000-7000-8000-000000000005")
	testConfigID       = uuid.MustParse("018f0000-0000-7000-8000-000000000006")
	testTaskID         = uuid.MustParse("018f0000-0000-7000-8000-000000000007")
)

type readerStub struct {
	requests []ReadRequest
	pages    []ReadPage
	err      error
}

func (stub *readerStub) ReadFinalizedLatest(ctx context.Context, request ReadRequest) (ReadPage, error) {
	stub.requests = append(stub.requests, request)
	if err := ctx.Err(); err != nil {
		return ReadPage{}, err
	}
	if stub.err != nil {
		return ReadPage{}, stub.err
	}
	if len(stub.pages) == 0 {
		return ReadPage{}, nil
	}
	page := stub.pages[0]
	if len(stub.pages) > 1 {
		stub.pages = stub.pages[1:]
	}
	return page, nil
}

func TestServiceClassifiesCorrelatesAndPaginatesOnOneFinalizedSnapshot(t *testing.T) {
	now := time.Date(2026, 8, 8, 6, 0, 0, 0, time.UTC)
	query := validQuery(now)
	snapshot := testSnapshot(now, query.To)
	facts := []ScopedAccessFact{
		fact(query.To.Add(-time.Minute), "event-z", 502, "cdn.example.test", "connection_reset"),
		fact(query.To.Add(-2*time.Minute), "event-y", 530, "cdn.example.test", ""),
		fact(query.To.Add(-3*time.Minute), "event-x", 400, "", "no_host"),
		fact(query.To.Add(-4*time.Minute), "event-w", 409, "cdn.example.test", "config_mismatch"),
	}
	reader := &readerStub{pages: []ReadPage{
		{Facts: facts, NextSourceCursor: "source-page-2", Snapshot: snapshot},
		{Facts: []ScopedAccessFact{fact(query.To.Add(-5*time.Minute), "event-v", 503, "cdn.example.test", "")}, Snapshot: snapshot},
	}}
	service := newTestService(t, reader, now)
	actor := tenantActor()

	first, err := service.Read(t.Context(), actor, query)
	if err != nil {
		t.Fatal(err)
	}
	if len(first.Items) != 4 || first.NextCursor == nil || first.EffectiveTenantID != nil {
		t.Fatalf("first page = %#v", first)
	}
	wantCategories := []Category{CategoryUpstream5xx, CategoryEdge530, CategoryNoHost, CategoryConfigMismatch}
	for index, want := range wantCategories {
		item := first.Items[index]
		if item.Category != want || item.ConfigVersionID != testConfigID.String() ||
			item.InstallationID != testInstallationID.String() || item.NodeID != testNodeID.String() ||
			item.RequestID == "" || item.TraceID == "" || item.TaskID == nil || *item.TaskID != testTaskID.String() {
			t.Fatalf("item[%d] = %#v", index, item)
		}
	}
	if first.Items[0].CauseCode != CauseUpstreamFailure || first.Items[0].ActionCode != ActionInspectUpstream ||
		first.Items[1].CauseCode != CauseStatus530 || first.Items[2].CauseCode != CauseHostMissing {
		t.Fatalf("classification = %#v", first.Items)
	}

	secondQuery := query
	secondQuery.Cursor = *first.NextCursor
	second, err := service.Read(t.Context(), actor, secondQuery)
	if err != nil {
		t.Fatal(err)
	}
	if len(second.Items) != 1 || second.NextCursor != nil || len(reader.requests) != 2 ||
		reader.requests[1].SourceCursor != "source-page-2" || reader.requests[1].Snapshot == nil ||
		!sameTestSnapshot(*reader.requests[1].Snapshot, snapshot) {
		t.Fatalf("second/page requests = %#v %#v", second, reader.requests)
	}
}

func TestServiceCursorIsStableAndBindsScopeFilterAndSnapshot(t *testing.T) {
	now := time.Date(2026, 8, 8, 6, 0, 0, 0, time.UTC)
	query := validQuery(now)
	snapshot := testSnapshot(now, query.To)
	page := ReadPage{Facts: []ScopedAccessFact{fact(query.To.Add(-time.Minute), "event-a", 502, "cdn.example.test", "mystery")},
		NextSourceCursor: "next", Snapshot: snapshot}
	reader := &readerStub{pages: []ReadPage{page, page}}
	service := newTestService(t, reader, now)

	first, err := service.Read(t.Context(), tenantActor(), query)
	if err != nil {
		t.Fatal(err)
	}
	second, err := service.Read(t.Context(), tenantActor(), query)
	if err != nil {
		t.Fatal(err)
	}
	if first.NextCursor == nil || second.NextCursor == nil || *first.NextCursor != *second.NextCursor ||
		first.Items[0].CauseCode != CauseUpstreamUnknown {
		t.Fatalf("unstable cursor/classification = %#v %#v", first, second)
	}

	for _, mutate := range []func(*Query){
		func(value *Query) { value.SiteID = uuid.Nil },
		func(value *Query) { value.Category = CategoryNoHost },
		func(value *Query) { value.Limit-- },
	} {
		changed := query
		changed.Cursor = *first.NextCursor
		mutate(&changed)
		if _, err := service.Read(t.Context(), tenantActor(), changed); !errors.Is(err, ErrInvalidCursor) {
			t.Fatalf("changed query error = %v", err)
		}
	}

	expiredNow := snapshot.ExpiresAt
	expiredService := newTestService(t, &readerStub{}, expiredNow)
	expired := query
	expired.Cursor = *first.NextCursor
	if _, err := expiredService.Read(t.Context(), tenantActor(), expired); !errors.Is(err, ErrInvalidCursor) {
		t.Fatalf("expired cursor error = %v", err)
	}
}

func TestServiceSeparatesTenantAndPlatformAuthorization(t *testing.T) {
	now := time.Date(2026, 8, 8, 6, 0, 0, 0, time.UTC)
	query := validQuery(now)
	reader := &readerStub{pages: []ReadPage{{Facts: []ScopedAccessFact{}, Snapshot: testSnapshot(now, query.To)}}}
	service := newTestService(t, reader, now)

	if _, err := service.Read(t.Context(), Actor{ScopeKind: "tenant", TenantID: testTenantID}, query); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("tenant permission error = %v", err)
	}
	platformQuery := query
	platformQuery.Audience = AudiencePlatform
	platformQuery.TenantID = testTenantID
	platform := Actor{ScopeKind: "platform", Permissions: []string{"platform.admin"}}
	response, err := service.Read(t.Context(), platform, platformQuery)
	if err != nil {
		t.Fatal(err)
	}
	if response.EffectiveTenantID == nil || *response.EffectiveTenantID != testTenantID.String() ||
		reader.requests[len(reader.requests)-1].Scope.TenantID != testTenantID {
		t.Fatalf("platform response/request = %#v %#v", response, reader.requests)
	}

	for _, test := range []struct {
		actor Actor
		query Query
		want  error
	}{
		{actor: tenantActor(), query: platformQuery, want: ErrScopeForbidden},
		{actor: Actor{ScopeKind: "platform", TenantID: testTenantID, Permissions: []string{"platform.admin"}}, query: platformQuery, want: ErrScopeForbidden},
		{actor: platform, query: query, want: ErrScopeForbidden},
		{actor: Actor{ScopeKind: "platform"}, query: platformQuery, want: ErrPermissionDenied},
	} {
		if _, err := service.Read(t.Context(), test.actor, test.query); !errors.Is(err, test.want) {
			t.Fatalf("actor/query %#v %#v error = %v, want %v", test.actor, test.query, err, test.want)
		}
	}
}

func TestServiceFailsClosedForSnapshotAndFactAuthorityViolations(t *testing.T) {
	now := time.Date(2026, 8, 8, 6, 0, 0, 0, time.UTC)
	query := validQuery(now)
	base := fact(query.To.Add(-time.Minute), "event-b", 502, "cdn.example.test", "")
	snapshot := testSnapshot(now, query.To)

	invalidSnapshots := []analyticsrealtime.Snapshot{
		{At: snapshot.At, FinalizedThrough: snapshot.FinalizedThrough, ExpiresAt: snapshot.ExpiresAt},
		{At: snapshot.At, SourceWatermark: 1, FinalizedThrough: query.To.Add(-time.Millisecond), ExpiresAt: snapshot.ExpiresAt},
		{At: snapshot.At, SourceWatermark: 1, FinalizedThrough: snapshot.FinalizedThrough, ExpiresAt: now},
		{At: snapshot.At.Add(time.Microsecond), SourceWatermark: 1, FinalizedThrough: snapshot.FinalizedThrough, ExpiresAt: snapshot.ExpiresAt},
	}
	for _, invalid := range invalidSnapshots {
		service := newTestService(t, &readerStub{pages: []ReadPage{{Facts: []ScopedAccessFact{base}, Snapshot: invalid}}}, now)
		if _, err := service.Read(t.Context(), tenantActor(), query); !errors.Is(err, ErrInvalidSnapshot) {
			t.Fatalf("snapshot %#v error = %v", invalid, err)
		}
	}

	violations := []func(*[]ScopedAccessFact){
		func(items *[]ScopedAccessFact) { (*items)[0].TenantID = testOtherTenantID },
		func(items *[]ScopedAccessFact) { (*items)[0].Log.InstallationID = uuid.Nil.String() },
		func(items *[]ScopedAccessFact) { (*items)[0].Log.TaskID = stringPointer("not-a-uuid") },
		func(items *[]ScopedAccessFact) { (*items)[0].Log.SiteID = testOtherTenantID.String() },
		func(items *[]ScopedAccessFact) { (*items)[0].Log.OccurredAt = query.To },
		func(items *[]ScopedAccessFact) { *items = append(*items, (*items)[0]) },
		func(items *[]ScopedAccessFact) {
			*items = append(*items, fact(query.To.Add(-30*time.Second), "event-a", 502, "cdn.example.test", ""))
		},
	}
	for _, violate := range violations {
		items := []ScopedAccessFact{base}
		violate(&items)
		service := newTestService(t, &readerStub{pages: []ReadPage{{Facts: items, Snapshot: snapshot}}}, now)
		if _, err := service.Read(t.Context(), tenantActor(), query); !errors.Is(err, ErrInvalidResponse) {
			t.Fatalf("facts %#v error = %v", items, err)
		}
	}

	mismatchReader := &readerStub{pages: []ReadPage{
		{Facts: []ScopedAccessFact{base}, NextSourceCursor: "next", Snapshot: snapshot},
		{Facts: []ScopedAccessFact{base}, Snapshot: analyticsrealtime.Snapshot{
			At: snapshot.At.Add(-time.Second), SourceWatermark: snapshot.SourceWatermark,
			FinalizedThrough: snapshot.FinalizedThrough, ExpiresAt: snapshot.ExpiresAt,
		}},
	}}
	service := newTestService(t, mismatchReader, now)
	first, err := service.Read(t.Context(), tenantActor(), query)
	if err != nil {
		t.Fatal(err)
	}
	query.Cursor = *first.NextCursor
	if _, err := service.Read(t.Context(), tenantActor(), query); !errors.Is(err, ErrInvalidSnapshot) {
		t.Fatalf("mismatched page snapshot error = %v", err)
	}
}

func TestServiceCategoryFilterAndReaderErrors(t *testing.T) {
	now := time.Date(2026, 8, 8, 6, 0, 0, 0, time.UTC)
	query := validQuery(now)
	query.Category = CategoryNoHost
	reader := &readerStub{pages: []ReadPage{{
		Facts:    []ScopedAccessFact{fact(query.To.Add(-time.Minute), "event-filter", 400, "", "")},
		Snapshot: testSnapshot(now, query.To),
	}}}
	service := newTestService(t, reader, now)
	response, err := service.Read(t.Context(), tenantActor(), query)
	if err != nil || len(response.Items) != 1 || response.Items[0].Category != CategoryNoHost ||
		reader.requests[0].Filter.Category != CategoryNoHost {
		t.Fatalf("filtered response/request/error = %#v %#v %v", response, reader.requests, err)
	}

	for _, test := range []struct {
		err  error
		want error
	}{
		{err: context.Canceled, want: context.Canceled},
		{err: context.DeadlineExceeded, want: context.DeadlineExceeded},
		{err: ErrUnavailable, want: ErrUnavailable},
		{err: errors.New("clickhouse password secret"), want: ErrUnavailable},
	} {
		service := newTestService(t, &readerStub{err: test.err}, now)
		if _, err := service.Read(t.Context(), tenantActor(), validQuery(now)); !errors.Is(err, test.want) ||
			(test.want == ErrUnavailable && err.Error() != ErrUnavailable.Error()) {
			t.Fatalf("reader error %v mapped to %v", test.err, err)
		}
	}
}

func newTestService(t *testing.T, reader FinalizedLatestStateReader, now time.Time) *Service {
	t.Helper()
	service, err := NewService(reader, Config{
		Now: func() time.Time { return now }, CursorKey: []byte("0123456789abcdef0123456789abcdef"),
	})
	if err != nil {
		t.Fatal(err)
	}
	return service
}

func tenantActor() Actor {
	return Actor{ScopeKind: "tenant", TenantID: testTenantID, Permissions: []string{analyticslog.ReadPermission}}
}

func validQuery(now time.Time) Query {
	return Query{
		Audience: AudienceTenant, From: now.Add(-time.Hour), To: now.Add(-time.Minute),
		SiteID: testSiteID, NodeID: testNodeID, Limit: 10,
	}
}

func testSnapshot(now, through time.Time) analyticsrealtime.Snapshot {
	return analyticsrealtime.Snapshot{
		At: now.Add(-30 * time.Second), SourceWatermark: 42, FinalizedThrough: through,
		ExpiresAt: now.Add(time.Minute),
	}
}

func fact(at time.Time, event string, status uint16, host, upstream string) ScopedAccessFact {
	task := testTaskID.String()
	return ScopedAccessFact{TenantID: testTenantID, Log: analyticslog.AccessLog{
		EventID: event, OccurredAt: at, SiteID: testSiteID.String(), NodeID: testNodeID.String(),
		RequestID: "request-" + event, TraceID: "trace-" + event, ConfigVersion: testConfigID.String(),
		InstallationID: testInstallationID.String(), TaskID: &task, Host: host, URIPath: "/secret/path",
		ClientIP: "203.0.113.9", RequestHeaders: map[string]string{"Authorization": "Bearer secret"},
		ResponseHeaders: map[string]string{"Set-Cookie": "secret"}, RequestBody: map[string]any{"password": "secret"},
		ResponseBody: map[string]any{"token": "secret"}, StatusCode: status, UpstreamResult: upstream,
	}}
}

func stringPointer(value string) *string { return &value }

func sameTestSnapshot(left, right analyticsrealtime.Snapshot) bool {
	return left.SourceWatermark == right.SourceWatermark && left.At.Equal(right.At) &&
		left.FinalizedThrough.Equal(right.FinalizedThrough) && left.ExpiresAt.Equal(right.ExpiresAt)
}
