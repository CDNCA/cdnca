package analyticsdiagnostic

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/analyticslog"
)

const (
	testTenantID = "018f0000-0000-7000-8000-000000000001"
	testSiteID   = "018f0000-0000-7000-8000-000000000002"
	testNodeID   = "018f0000-0000-7000-8000-000000000003"
)

type sourceStub struct {
	actor   Actor
	request QueryRequest
	page    analyticslog.AccessPage
	err     error
	cancel  context.CancelFunc
}

func (source *sourceStub) ReadAccess(ctx context.Context, actor Actor, request QueryRequest) (analyticslog.AccessPage, error) {
	source.actor, source.request = actor, request
	if source.cancel != nil {
		source.cancel()
	}
	return source.page, source.err
}

func diagnosticAccess(at time.Time, suffix string, status uint16, host, upstream string) analyticslog.AccessLog {
	return analyticslog.AccessLog{
		EventID: "diagnostic-" + suffix, OccurredAt: at, SiteID: testSiteID, NodeID: testNodeID,
		RequestID: "request-" + suffix, TraceID: "trace-" + suffix, ConfigVersion: "config-" + suffix,
		Host: host, URIPath: "/health", StatusCode: status, UpstreamResult: upstream,
	}
}

func TestServiceProjectsStableDiagnosticsFromAccessFacts(t *testing.T) {
	to := time.Date(2026, 8, 8, 2, 0, 0, 0, time.UTC)
	from := to.Add(-time.Hour)
	source := &sourceStub{page: analyticslog.AccessPage{
		Items: []analyticslog.AccessLog{
			diagnosticAccess(to.Add(-time.Minute), "no-host", 400, "", "no_host"),
			diagnosticAccess(to.Add(-2*time.Minute), "config", 530, "cdn.example.test", "config_mismatch"),
			diagnosticAccess(to.Add(-3*time.Minute), "upstream", 502, "cdn.example.test", "connection_reset"),
			diagnosticAccess(to.Add(-4*time.Minute), "unknown", 503, "cdn.example.test", ""),
			diagnosticAccess(to.Add(-5*time.Minute), "healthy", 200, "cdn.example.test", "ok"),
		},
		NextCursor: "signed-source-cursor", SnapshotAt: to.Add(-time.Second),
	}}
	service, err := NewService(source)
	if err != nil {
		t.Fatal(err)
	}
	actor := Actor{ScopeKind: "tenant", TenantID: testTenantID, Permissions: []string{analyticslog.ReadPermission}}
	page, err := service.List(t.Context(), actor, QueryRequest{Audience: AudienceTenant, From: from, To: to,
		SiteID: testSiteID, NodeID: testNodeID, Limit: 5})
	if err != nil {
		t.Fatal(err)
	}
	if source.actor.TenantID != testTenantID || source.request.SiteID != testSiteID || source.request.NodeID != testNodeID ||
		page.NextCursor != "signed-source-cursor" || !page.SnapshotAt.Equal(to.Add(-time.Second)) {
		t.Fatalf("scope/page = %#v %#v", source, page)
	}
	want := []Category{CategoryNoHost, CategoryConfigMismatch, CategoryUpstream5xx, CategoryUnknown}
	if len(page.Items) != len(want) {
		t.Fatalf("items = %#v", page.Items)
	}
	for index, category := range want {
		if page.Items[index].Category != category || page.Items[index].ConfigVersionID == "" ||
			page.Items[index].RequestID == "" || page.Items[index].TraceID == "" {
			t.Fatalf("item[%d] = %#v", index, page.Items[index])
		}
	}
}

func TestServiceFailsClosedForMissingIdentityAndCancellation(t *testing.T) {
	to := time.Date(2026, 8, 8, 2, 0, 0, 0, time.UTC)
	from := to.Add(-time.Hour)
	base := diagnosticAccess(to.Add(-time.Minute), "missing", 502, "cdn.example.test", "reset")
	for _, test := range []struct {
		name   string
		mutate func(*analyticslog.AccessLog)
	}{
		{name: "node", mutate: func(item *analyticslog.AccessLog) { item.NodeID = "" }},
		{name: "request", mutate: func(item *analyticslog.AccessLog) { item.RequestID = "" }},
		{name: "trace", mutate: func(item *analyticslog.AccessLog) { item.TraceID = "" }},
		{name: "config", mutate: func(item *analyticslog.AccessLog) { item.ConfigVersion = "" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			item := base
			test.mutate(&item)
			service, _ := NewService(&sourceStub{page: analyticslog.AccessPage{Items: []analyticslog.AccessLog{item}}})
			_, err := service.List(t.Context(), Actor{ScopeKind: "tenant", TenantID: testTenantID,
				Permissions: []string{analyticslog.ReadPermission}}, QueryRequest{Audience: AudienceTenant, From: from, To: to, Limit: 1})
			if !errors.Is(err, ErrInvalidResponse) {
				t.Fatalf("List() error = %v, want ErrInvalidResponse", err)
			}
		})
	}

	ctx, cancel := context.WithCancel(context.Background())
	source := &sourceStub{page: analyticslog.AccessPage{Items: []analyticslog.AccessLog{base}}, cancel: cancel}
	service, _ := NewService(source)
	_, err := service.List(ctx, Actor{ScopeKind: "tenant", TenantID: testTenantID,
		Permissions: []string{analyticslog.ReadPermission}}, QueryRequest{Audience: AudienceTenant, From: from, To: to, Limit: 1})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("List() cancellation = %v", err)
	}
}

type analyticsLogReaderStub struct {
	actor   analyticslog.Actor
	request analyticslog.QueryRequest
	page    analyticslog.AccessPage
	err     error
}

func (reader *analyticsLogReaderStub) ListAccess(_ context.Context, actor analyticslog.Actor, request analyticslog.QueryRequest) (analyticslog.AccessPage, error) {
	reader.actor, reader.request = actor, request
	return reader.page, reader.err
}

func TestAnalyticsLogAdapterPreservesAuthorityAndMapsUnavailable(t *testing.T) {
	reader := &analyticsLogReaderStub{}
	adapter, err := NewAnalyticsLogAdapter(reader)
	if err != nil {
		t.Fatal(err)
	}
	to := time.Date(2026, 8, 8, 2, 0, 0, 0, time.UTC)
	request := QueryRequest{Audience: AudiencePlatform, TenantID: testTenantID, From: to.Add(-time.Hour), To: to,
		SiteID: testSiteID, NodeID: testNodeID, Limit: 20, Cursor: "signed-source-cursor"}
	actor := Actor{ScopeKind: "platform", Permissions: []string{"platform.admin"}}
	if _, err := adapter.ReadAccess(t.Context(), actor, request); err != nil {
		t.Fatal(err)
	}
	if reader.request.Audience != analyticslog.AudiencePlatform || reader.request.TenantID != testTenantID ||
		reader.request.Filter.SiteID != testSiteID || reader.request.Filter.NodeID != testNodeID ||
		reader.request.Cursor != request.Cursor || reader.request.Limit != request.Limit {
		t.Fatalf("adapted request = %#v", reader.request)
	}
	reader.err = analyticslog.ErrStorageUnavailable
	if _, err := adapter.ReadAccess(t.Context(), actor, request); !errors.Is(err, ErrEvidenceUnavailable) {
		t.Fatalf("storage error = %v", err)
	}
}
