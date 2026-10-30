package analytics

import (
	"strings"
	"testing"
)

func TestPostgresRealtimeCoverageQueriesUseIndependentTopologyAndImmutableFacts(t *testing.T) {
	for _, token := range []string{
		"analytics_access_source_window_contributions_208", "analytics_realtime_source_windows_184",
		"JOIN access_scopes", "JOIN sites", "LIMIT ($2::integer+1)",
	} {
		if !strings.Contains(pendingRealtimeCoverageSQL, token) {
			t.Errorf("pending query missing %q", token)
		}
	}
	for _, token := range []string{
		"FROM node_config_state state", "JOIN nodes node", "JOIN config_versions",
		"scope.id=state.configuration_scope_id", "node.admin_state IN ('active','draining')",
	} {
		if !strings.Contains(realtimeRosterCandidatesSQL, token) {
			t.Errorf("topology query missing %q", token)
		}
	}
	for _, token := range []string{
		"site.created_at<=$6", "site.updated_at<=$6", "site_domain_facts",
		"changed.occurred_at>$6", "ANY(site.http_ports)", "ANY(site.https_ports)",
	} {
		if !strings.Contains(realtimeCoverageSiteSQL, token) {
			t.Errorf("site authority query missing %q", token)
		}
	}
}

func TestRealtimeCoverageSnapshotComparisonIsOrderIndependentAndDetectsDrift(t *testing.T) {
	_, snapshot, _, _ := realtimeCoverageFixture(t)
	reordered := snapshot
	reordered.Sources = append([]RealtimeCoverageSourceV1(nil), snapshot.Sources...)
	reordered.Sources[0], reordered.Sources[1] = reordered.Sources[1], reordered.Sources[0]
	if !equalRealtimeCoverageSnapshot(snapshot, reordered) {
		t.Fatal("source order changed snapshot identity")
	}
	reordered.Sources[0].ConfigVersionID = "018f0000-0000-7000-8000-000000000099"
	if equalRealtimeCoverageSnapshot(snapshot, reordered) {
		t.Fatal("config topology drift was accepted")
	}
}
