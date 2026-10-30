package analytics

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/analyticsrealtime"
	"github.com/jackc/pgx/v5"
)

type realtimeEvidenceQueryFixture struct {
	query string
	args  []any
	row   pgx.Row
}

func (fixture *realtimeEvidenceQueryFixture) QueryRow(_ context.Context, query string, args ...any) pgx.Row {
	fixture.query, fixture.args = query, args
	return fixture.row
}

type realtimeEvidenceRowFixture struct {
	scan func(...any) error
}

func (fixture realtimeEvidenceRowFixture) Scan(destinations ...any) error {
	return fixture.scan(destinations...)
}

func TestPostgresRealtimeExpectedEvidenceRequiresExactCompleteWindows(t *testing.T) {
	from := time.Date(2026, 8, 7, 1, 0, 0, 0, time.UTC)
	to := from.Add(time.Hour)
	queryer := &realtimeEvidenceQueryFixture{row: realtimeEvidenceRowFixture{scan: func(destinations ...any) error {
		*destinations[0].(*string) = "0"
		*destinations[1].(*string) = "1"
		*destinations[2].(*string) = "1"
		*destinations[3].(*bool) = true
		*destinations[4].(*string) = "2"
		*destinations[5].(*string) = "2"
		*destinations[6].(*string) = "1"
		*destinations[7].(*string) = "1"
		*destinations[8].(**time.Time) = &to
		*destinations[9].(**time.Time) = &to
		return nil
	}}}
	reader := &PostgresRealtimeExpectedCountReader{queryer: queryer}
	filter := RealtimeFilter{From: from, To: to, SiteID: "018f0000-0000-7000-8000-000000000002", Host: "cdn.example.test", ListenPort: 443}
	evidence, err := reader.ExpectedRealtimeEvidence(t.Context(), Scope{kind: scopeTenant, tenantID: "018f0000-0000-7000-8000-000000000001"}, filter)
	if err != nil {
		t.Fatal(err)
	}
	if evidence.ExpectedEvents != 0 || evidence.RequestedWindows != 1 || evidence.CoveredWindows != 1 ||
		evidence.AccessSourcesExpected != 2 || evidence.AccessSourcesFinalized != 2 ||
		evidence.ConnectionSourcesExpected != 1 || evidence.ConnectionSourcesFinalized != 1 ||
		!evidence.FinalizedThrough.Equal(to) || !evidence.SourceWatermark.Equal(to) {
		t.Fatalf("evidence = %#v", evidence)
	}
	for _, token := range []string{
		"generate_series", "analytics_realtime_source_windows_184", "analytics_realtime_expected_counts_131",
		"analytics_realtime_source_rosters_247", "source.host=dimensions.host", "source.listen_port=dimensions.listen_port",
		"nodes>0", "count(DISTINCT item->>'node_id')", "roster.evidence_sha256=sha256",
		"access_sources_finalized=access_sources_expected", "connection_sources_finalized=connection_sources_expected",
	} {
		if !strings.Contains(queryer.query, token) {
			t.Errorf("query missing %q", token)
		}
	}
	if len(queryer.args) != 8 || queryer.args[0] != evidence.TenantID || queryer.args[3] != filter.SiteID ||
		queryer.args[4] != filter.Host || queryer.args[5] != filter.ListenPort || queryer.args[6] != true {
		t.Fatalf("query args = %#v", queryer.args)
	}
}

func TestPostgresRealtimeExpectedEvidenceSupportsPlatformGlobalScope(t *testing.T) {
	from := time.Date(2026, 8, 7, 1, 0, 0, 0, time.UTC)
	to := from.Add(time.Hour)
	queryer := &realtimeEvidenceQueryFixture{row: realtimeEvidenceRowFixture{scan: func(destinations ...any) error {
		*destinations[0].(*string) = "12"
		*destinations[1].(*string) = "1"
		*destinations[2].(*string) = "1"
		*destinations[3].(*bool) = true
		*destinations[4].(*string) = "4"
		*destinations[5].(*string) = "4"
		*destinations[6].(*string) = "2"
		*destinations[7].(*string) = "2"
		*destinations[8].(**time.Time) = &to
		*destinations[9].(**time.Time) = &to
		return nil
	}}}
	reader := &PostgresRealtimeExpectedCountReader{queryer: queryer}
	evidence, err := reader.ExpectedRealtimeEvidence(t.Context(), AdminScope(), RealtimeFilter{From: from, To: to})
	if err != nil {
		t.Fatal(err)
	}
	if evidence.TenantID != "" || evidence.ExpectedEvents != 12 || len(queryer.args) != 8 ||
		queryer.args[0] != nilUUIDValue || queryer.args[6] != false {
		t.Fatalf("platform evidence=%#v args=%#v", evidence, queryer.args)
	}
	for _, token := range []string{"NOT $7::boolean", "(item->>'tenant_id')::uuid=$1::uuid", "scope.tenant_id=$1::uuid", "projected.covered", "projected.complete"} {
		if !strings.Contains(queryer.query, token) {
			t.Errorf("platform query missing %q", token)
		}
	}
}

func TestPostgresRealtimeExpectedEvidenceAcceptsOnlyProvenEmptyZeroSources(t *testing.T) {
	from := time.Date(2026, 8, 7, 1, 0, 0, 0, time.UTC)
	to := from.Add(2 * time.Hour)
	now := to.Add(10 * time.Minute)
	row := func(values ...string) realtimeEvidenceRowFixture {
		return realtimeEvidenceRowFixture{scan: func(destinations ...any) error {
			for index, value := range values[:3] {
				*destinations[index].(*string) = value
			}
			*destinations[3].(*bool) = true
			for index, value := range values[3:] {
				*destinations[index+4].(*string) = value
			}
			*destinations[8].(**time.Time) = &to
			*destinations[9].(**time.Time) = &to
			return nil
		}}
	}
	queryer := &realtimeEvidenceQueryFixture{row: row("0", "2", "2", "0", "0", "0", "0")}
	reader := &PostgresRealtimeExpectedCountReader{queryer: queryer, now: func() time.Time { return now }}
	evidence, err := reader.ExpectedRealtimeEvidence(t.Context(), AdminScope(), RealtimeFilter{From: from, To: to})
	if err != nil {
		t.Fatalf("proven empty evidence error = %v", err)
	}
	if evidence.ExpectedEvents != 0 || evidence.CoveredWindows != 2 || evidence.AccessSourcesExpected != 0 ||
		evidence.ConnectionSourcesExpected != 0 || !evidence.FinalizedThrough.Equal(to) {
		t.Fatalf("proven empty evidence = %#v", evidence)
	}
	if len(queryer.args) != 8 || !queryer.args[7].(time.Time).Equal(now.Add(-defaultRealtimeCoverageGrace)) {
		t.Fatalf("proven empty cutoff args = %#v", queryer.args)
	}
	for _, token := range []string{
		"empty_proven", "NOT EXISTS(SELECT 1 FROM dimensions WHERE dimensions.hour=requested.hour)", "analytics_access_source_window_contributions_208",
		"hour+interval '1 hour'<=$8::timestamptz", "NOT EXISTS",
	} {
		if !strings.Contains(queryer.query, token) {
			t.Errorf("proven empty query missing %q", token)
		}
	}
	for name, values := range map[string][]string{
		"expected events without sources":       {"1", "2", "2", "0", "0", "0", "0"},
		"access sources without connection":     {"0", "2", "2", "1", "1", "0", "0"},
		"connection sources without access":     {"0", "2", "2", "0", "0", "1", "1"},
		"finalized access sources without plan": {"0", "2", "2", "0", "1", "0", "0"},
		"uncovered window":                      {"0", "2", "1", "0", "0", "0", "0"},
	} {
		reader := &PostgresRealtimeExpectedCountReader{queryer: &realtimeEvidenceQueryFixture{row: row(values...)}, now: func() time.Time { return now }}
		if _, err := reader.ExpectedRealtimeEvidence(t.Context(), AdminScope(), RealtimeFilter{From: from, To: to}); !errors.Is(err, ErrRealtimeEvidenceUnavailable) {
			t.Errorf("%s accepted: %v", name, err)
		}
	}
}

func TestPostgresRealtimeExpectedEvidenceDependencyFailureIsUnavailable(t *testing.T) {
	dependencyErr := errors.New("postgres connection failed")
	reader := &PostgresRealtimeExpectedCountReader{queryer: &realtimeEvidenceQueryFixture{
		row: realtimeEvidenceRowFixture{scan: func(...any) error { return dependencyErr }},
	}}
	from := time.Date(2026, 8, 7, 1, 0, 0, 0, time.UTC)
	_, err := reader.ExpectedRealtimeEvidence(t.Context(), Scope{kind: scopeTenant, tenantID: "018f0000-0000-7000-8000-000000000001"},
		RealtimeFilter{From: from, To: from.Add(time.Hour)})
	if !errors.Is(err, ErrRealtimeEvidenceUnavailable) || errors.Is(err, dependencyErr) {
		t.Fatalf("ExpectedRealtimeEvidence() error = %v", err)
	}
}

func TestPostgresRealtimeV2CoverageProjectsEveryExactDimension(t *testing.T) {
	from := time.Date(2026, 8, 7, 1, 15, 0, 0, time.UTC)
	to := time.Date(2026, 8, 7, 2, 45, 0, 0, time.UTC)
	coverageTo := time.Date(2026, 8, 7, 3, 0, 0, 0, time.UTC)
	queryer := &realtimeEvidenceQueryFixture{row: realtimeEvidenceRowFixture{scan: func(destinations ...any) error {
		*destinations[0].(*string) = "2"
		*destinations[1].(*string) = "2"
		*destinations[2].(*bool) = true
		for index, value := range []string{"3", "3", "4", "4", "4", "4"} {
			*destinations[index+3].(*string) = value
		}
		*destinations[9].(**time.Time) = &coverageTo
		*destinations[10].(**time.Time) = &coverageTo
		return nil
	}}}
	reader := &PostgresRealtimeExpectedCountReader{queryer: queryer}
	filter := analyticsrealtime.Filter{
		From: from, To: to, Timezone: "UTC", SiteID: "018f0000-0000-7000-8000-000000000002",
		Domain: "cdn.example.test", ListenPort: 443, Bucket: time.Minute,
	}
	authority, err := reader.RealtimeV2Coverage(t.Context(),
		analyticsrealtime.Scope{TenantID: "018f0000-0000-7000-8000-000000000001"}, filter)
	if err != nil {
		t.Fatal(err)
	}
	if authority.RequestedWindows != 2 || authority.CoveredWindows != 2 ||
		authority.ExpectedDimensions != 3 || authority.CoveredDimensions != 3 ||
		authority.AccessSourcesExpected != 4 || authority.AccessSourcesFinalized != 4 ||
		authority.ConnectionSourcesExpected != 4 || authority.ConnectionSourcesFinalized != 4 ||
		!authority.FinalizedThrough.Equal(coverageTo) || !authority.SourceWatermark.Equal(coverageTo) {
		t.Fatalf("coverage authority=%#v", authority)
	}
	for _, token := range []string{
		"analytics_realtime_expected_counts_131", "analytics_access_source_window_contributions_208",
		"analytics_realtime_source_windows_184", "UNION", "dimensions_expected", "dimensions_covered",
		"source.site_id=dimensions.site_id", "source.host=dimensions.host", "source.listen_port=dimensions.listen_port",
		"dimensions_expected>0 AND dimensions_covered=dimensions_expected AND complete",
	} {
		if !strings.Contains(queryer.query, token) {
			t.Errorf("projection query missing %q", token)
		}
	}
	if len(queryer.args) != 6 || !queryer.args[1].(time.Time).Equal(from.Truncate(time.Hour)) ||
		!queryer.args[2].(time.Time).Equal(coverageTo) || queryer.args[3] != filter.SiteID ||
		queryer.args[4] != filter.Domain || queryer.args[5] != filter.ListenPort {
		t.Fatalf("projection args=%#v", queryer.args)
	}
}
