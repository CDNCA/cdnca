package systemconfig

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type allowExpansion struct{}

func (allowExpansion) AuthorizeSystemConfigurationExpansion(context.Context, pgx.Tx, ExpansionCheck) error {
	return nil
}

type rejectExpansion struct {
	calls int
}

func (authorizer *rejectExpansion) AuthorizeSystemConfigurationExpansion(context.Context, pgx.Tx, ExpansionCheck) error {
	authorizer.calls++
	return errors.New("expansion authorization unavailable")
}

func TestCategoryFreshInstallBootstrapReadAndFirstActivation(t *testing.T) {
	fixture := newSystemConfigFixture(t)
	manager, err := NewCategoryManager(fixture.service, allowExpansion{})
	if err != nil {
		t.Fatal(err)
	}

	initial, err := manager.GetActiveCategory(t.Context(), fixture.platform, CategoryNginx)
	if err != nil {
		t.Fatal(err)
	}
	bootstrap, _, _, err := CanonicalSnapshot(ProjectBootstrapConfiguration())
	if err != nil {
		t.Fatal(err)
	}
	if initial.HeadRevision != 0 || initial.ActiveRevision != 0 || initial.Revision != 0 ||
		initial.Status != StatusDraft || !reflect.DeepEqual(initial.Value, bootstrap.Nginx) {
		t.Fatalf("unexpected fresh-install document: %#v", initial)
	}
	if countRows(t, fixture.pool, "system_configuration_streams") != 0 ||
		countRows(t, fixture.pool, "system_configuration_revisions") != 0 {
		t.Fatal("fresh-install read mutated system configuration state")
	}

	nginx := bootstrap.Nginx
	nginx.WorkerConnections--
	draft, err := manager.SaveCategory(t.Context(), fixture.platform, SaveCategoryRequest{
		Category: CategoryNginx, ExpectedHeadRevision: 0, Change: CategoryChange{Nginx: &nginx},
		IdempotencyKey: "fresh-category-save", RequestID: "fresh-category-save",
	})
	if err != nil {
		t.Fatal(err)
	}
	if draft.HeadRevision != 1 || draft.ActiveRevision != 0 || draft.Revision != 1 || draft.Status != StatusDraft {
		t.Fatalf("unexpected first draft: %#v", draft)
	}
	pending, err := manager.GetActiveCategory(t.Context(), fixture.platform, CategoryNginx)
	if err != nil {
		t.Fatal(err)
	}
	if pending.HeadRevision != 1 || pending.ActiveRevision != 0 || pending.Revision != 1 ||
		pending.Status != StatusDraft || !reflect.DeepEqual(pending.Value, nginx) {
		t.Fatalf("fresh-install draft was not reloadable: %#v", pending)
	}

	validated, err := manager.PreflightRevision(t.Context(), fixture.platform, PreflightRevisionRequest{
		Revision: draft.Revision, SnapshotSHA256: draft.SnapshotSHA256,
		IdempotencyKey: "fresh-category-preflight", RequestID: "fresh-category-preflight",
	})
	if err != nil {
		t.Fatal(err)
	}
	if validated.Status != StatusValidated {
		t.Fatalf("first preflight status = %q", validated.Status)
	}
	active, err := manager.ActivateRevision(t.Context(), fixture.platform, ActivateRequest{
		Revision: draft.Revision, ExpectedActiveRevision: 0,
		IdempotencyKey: "fresh-category-activate", RequestID: "fresh-category-activate",
	})
	if err != nil {
		t.Fatal(err)
	}
	if active.Status != StatusActive || active.Revision != 1 {
		t.Fatalf("first activation = %#v", active)
	}

	reloaded, err := manager.GetActiveCategory(t.Context(), fixture.platform, CategoryNginx)
	if err != nil {
		t.Fatal(err)
	}
	if reloaded.HeadRevision != 1 || reloaded.ActiveRevision != 1 || reloaded.Revision != 1 ||
		reloaded.Status != StatusActive || !reflect.DeepEqual(reloaded.Value, nginx) {
		t.Fatalf("unexpected activated category: %#v", reloaded)
	}
}

func TestCategoryFreshInstallExposesEveryCanonicalCategoryWithoutPersistence(t *testing.T) {
	fixture := newSystemConfigFixture(t)
	manager, err := NewCategoryManager(fixture.service, allowExpansion{})
	if err != nil {
		t.Fatal(err)
	}
	bootstrap, _, snapshotHash, err := CanonicalSnapshot(ProjectBootstrapConfiguration())
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		category string
		value    any
	}{
		{CategoryNginx, bootstrap.Nginx},
		{CategoryResources, bootstrap.Resources},
		{CategoryDefaults, bootstrap.Defaults},
		{CategoryErrorPages, bootstrap.ErrorPages},
		{CategorySecrets, bootstrap.Secrets},
		{CategoryNodeMonitoring, effectiveNodeMonitoring(bootstrap.NodeMonitoring)},
	}
	for _, test := range tests {
		t.Run(test.category, func(t *testing.T) {
			first, err := manager.GetActiveCategory(t.Context(), fixture.platform, test.category)
			if err != nil {
				t.Fatal(err)
			}
			second, err := manager.GetActiveCategory(t.Context(), fixture.platform, test.category)
			if err != nil {
				t.Fatal(err)
			}
			if first.Schema != canonicalSchema || first.Category != test.category || first.HeadRevision != 0 ||
				first.ActiveRevision != 0 || first.Revision != 0 || first.Status != StatusDraft ||
				first.SnapshotSHA256 != snapshotHash || !reflect.DeepEqual(first.Value, test.value) ||
				!reflect.DeepEqual(first, second) {
				t.Fatalf("unexpected fresh-install %s document: first=%#v second=%#v", test.category, first, second)
			}
		})
	}
	if countRows(t, fixture.pool, "system_configuration_streams") != 0 ||
		countRows(t, fixture.pool, "system_configuration_revisions") != 0 {
		t.Fatal("fresh-install category reads mutated system configuration state")
	}
}

func TestCategoryFreshInstallPublicPagesCanSaveActivateAndReload(t *testing.T) {
	bootstrap, _, _, err := CanonicalSnapshot(ProjectBootstrapConfiguration())
	if err != nil {
		t.Fatal(err)
	}
	nginx := bootstrap.Nginx
	nginx.WorkerProcesses = 1
	resources := bootstrap.Resources
	resources.MaxDomainsPerSite--
	defaults := bootstrap.Defaults
	defaults.Website.Other.GzipEnabled = false
	errorPages := []ErrorPageMetadata{{
		StatusCode: 404, MIMEType: "text/html", SizeBytes: 1,
		SHA256: strings.Repeat("a", 64), StorageObjectKey: "errors/404.html",
	}}
	tests := []struct {
		category string
		change   CategoryChange
		value    any
	}{
		{CategoryNginx, CategoryChange{Nginx: &nginx}, nginx},
		{CategoryResources, CategoryChange{Resources: &resources}, resources},
		{CategoryDefaults, CategoryChange{Defaults: &defaults}, defaults},
		{CategoryErrorPages, CategoryChange{ErrorPages: &errorPages}, errorPages},
	}

	for _, test := range tests {
		t.Run(test.category, func(t *testing.T) {
			fixture := newSystemConfigFixture(t)
			manager, err := NewCategoryManager(fixture.service, allowExpansion{})
			if err != nil {
				t.Fatal(err)
			}
			draft, err := manager.SaveCategory(t.Context(), fixture.platform, SaveCategoryRequest{
				Category: test.category, ExpectedHeadRevision: 0, Change: test.change,
				IdempotencyKey: "fresh-" + test.category + "-save", RequestID: "fresh-" + test.category + "-save",
			})
			if err != nil {
				t.Fatal(err)
			}
			if draft.HeadRevision != 1 || draft.ActiveRevision != 0 || draft.Revision != 1 ||
				draft.Status != StatusDraft || !reflect.DeepEqual(draft.Value, test.value) {
				t.Fatalf("unexpected first %s draft: %#v", test.category, draft)
			}
			validated, err := manager.PreflightRevision(t.Context(), fixture.platform, PreflightRevisionRequest{
				Revision: 1, SnapshotSHA256: draft.SnapshotSHA256,
				IdempotencyKey: "fresh-" + test.category + "-preflight", RequestID: "fresh-" + test.category + "-preflight",
			})
			if err != nil || validated.Status != StatusValidated {
				t.Fatalf("validate first %s draft: revision=%#v err=%v", test.category, validated, err)
			}
			active, err := manager.ActivateRevision(t.Context(), fixture.platform, ActivateRequest{
				Revision: 1, ExpectedActiveRevision: 0,
				IdempotencyKey: "fresh-" + test.category + "-activate", RequestID: "fresh-" + test.category + "-activate",
			})
			if err != nil || active.Status != StatusActive || active.Revision != 1 {
				t.Fatalf("activate first %s draft: revision=%#v err=%v", test.category, active, err)
			}
			reloaded, err := manager.GetActiveCategory(t.Context(), fixture.platform, test.category)
			if err != nil {
				t.Fatal(err)
			}
			if reloaded.HeadRevision != 1 || reloaded.ActiveRevision != 1 || reloaded.Revision != 1 ||
				reloaded.Status != StatusActive || !reflect.DeepEqual(reloaded.Value, test.value) {
				t.Fatalf("unexpected active %s category: %#v", test.category, reloaded)
			}
		})
	}
}

func TestConfigurationReferencesAvailableUsesPlatformScopedTargets(t *testing.T) {
	fixture := newSystemConfigFixture(t)
	otherPlatformScopeID := uuid.New()
	// The canonical schema permits one platform per control plane. Remove that
	// test-schema-only fence so this test can prove stale foreign-platform facts
	// still cannot satisfy a reference owned by the current platform.
	if _, err := fixture.pool.Exec(t.Context(), `DROP INDEX access_scopes_single_platform_idx`); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.pool.Exec(t.Context(), `INSERT INTO access_scopes(id,kind) VALUES($1,'platform')`,
		otherPlatformScopeID); err != nil {
		t.Fatal(err)
	}

	insertRegion := func(scopeID uuid.UUID, name string) string {
		t.Helper()
		var displayID string
		if err := fixture.pool.QueryRow(t.Context(), `INSERT INTO region_catalog(id,platform_scope_id,name)
			VALUES($1,$2,$3) RETURNING display_id::text`, uuid.New(), scopeID, name).Scan(&displayID); err != nil {
			t.Fatal(err)
		}
		return displayID
	}
	platformRegionID := insertRegion(fixture.platform.ScopeID, "华东")
	otherPlatformRegionID := insertRegion(otherPlatformScopeID, "华北")
	insertNode := func(scopeID uuid.UUID, displayID int64, name string) uuid.UUID {
		t.Helper()
		nodeID := uuid.New()
		if _, err := fixture.pool.Exec(t.Context(), `INSERT INTO nodes(
			id,display_id,scope_id,name,admin_state,created_by_user_id
		) VALUES($1,$2,$3,$4,'active',$5)`, nodeID, displayID, scopeID, name, fixture.platform.UserID); err != nil {
			t.Fatal(err)
		}
		return nodeID
	}
	platformNodeID := insertNode(fixture.platform.ScopeID, 1, "platform-node")
	otherPlatformNodeID := insertNode(otherPlatformScopeID, 1, "other-platform-node")

	configurationForRegion := func(t *testing.T, regionID string, normalize bool) Configuration {
		t.Helper()
		configuration := ProjectBootstrapConfiguration()
		workerProcesses := configuration.Nginx.WorkerProcesses
		configuration.Nginx.Overrides = []ScopedNginxOverride{{
			ID: "nginxref1", Scope: ConfigurationScopeRegion, ScopeID: regionID,
			Values: NginxOverride{Worker: &NginxWorkerOverride{WorkerProcesses: &workerProcesses}},
		}}
		other := configuration.Defaults.Website.Other
		configuration.Defaults.Overrides = []ScopedDefaultOverride{{
			ID: "default1", Scope: ConfigurationScopeRegion, ScopeID: regionID,
			Values: DefaultOverrides{Website: &DefaultWebsiteOverride{Other: &other}},
		}}
		if !normalize {
			return configuration
		}
		normalized, _, _, err := CanonicalSnapshot(configuration)
		if err != nil {
			t.Fatal(err)
		}
		return normalized
	}
	configurationForNode := func(t *testing.T, nodeID string) Configuration {
		t.Helper()
		configuration := ProjectBootstrapConfiguration()
		workerProcesses := configuration.Nginx.WorkerProcesses
		configuration.Nginx.Overrides = []ScopedNginxOverride{{
			ID: "nginxnode1", Scope: ConfigurationScopeNode, ScopeID: nodeID,
			Values: NginxOverride{Worker: &NginxWorkerOverride{WorkerProcesses: &workerProcesses}},
		}}
		normalized, _, _, err := CanonicalSnapshot(configuration)
		if err != nil {
			t.Fatal(err)
		}
		return normalized
	}
	assertAvailable := func(t *testing.T, configuration Configuration, want bool) {
		t.Helper()
		var available bool
		err := pgx.BeginFunc(t.Context(), fixture.pool, func(tx pgx.Tx) error {
			var err error
			available, err = configurationReferencesAvailable(
				t.Context(), tx, fixture.platform.ScopeID, configuration,
			)
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
		if available != want {
			t.Fatalf("references available = %t, want %t", available, want)
		}
	}

	for _, test := range []struct {
		name      string
		regionID  string
		normalize bool
		want      bool
	}{
		{name: "current platform display ID", regionID: platformRegionID, normalize: true, want: true},
		{name: "other platform display ID", regionID: otherPlatformRegionID, normalize: true, want: false},
		{name: "unknown display ID", regionID: "999999999999", normalize: true, want: false},
		{name: "legacy region name", regionID: "华东", normalize: false, want: false},
	} {
		t.Run("region/"+test.name, func(t *testing.T) {
			assertAvailable(t, configurationForRegion(t, test.regionID, test.normalize), test.want)
		})
	}
	for _, test := range []struct {
		name   string
		nodeID string
		want   bool
	}{
		{name: "current platform ID", nodeID: platformNodeID.String(), want: true},
		{name: "other platform ID", nodeID: otherPlatformNodeID.String(), want: false},
		{name: "unknown ID", nodeID: uuid.NewString(), want: false},
	} {
		t.Run("node/"+test.name, func(t *testing.T) {
			assertAvailable(t, configurationForNode(t, test.nodeID), test.want)
		})
	}
}

func TestCategoryReadSaveReplayCASAndRestartPersistence(t *testing.T) {
	fixture := newSystemConfigFixture(t)
	activateInitialSystemConfiguration(t, fixture)
	manager, err := NewCategoryManager(fixture.service, allowExpansion{})
	if err != nil {
		t.Fatal(err)
	}

	active, err := manager.GetActiveCategory(t.Context(), fixture.platform, CategoryNginx)
	if err != nil {
		t.Fatal(err)
	}
	if active.HeadRevision != 1 || active.ActiveRevision != 1 || active.Revision != 1 || active.Status != StatusActive {
		t.Fatalf("unexpected active category document: %#v", active)
	}

	nginx := validConfiguration().Nginx
	nginx.WorkerConnections--
	request := SaveCategoryRequest{Category: CategoryNginx, ExpectedHeadRevision: 1,
		Change: CategoryChange{Nginx: &nginx}, IdempotencyKey: "category-save", RequestID: "category-save"}
	draft, err := manager.SaveCategory(t.Context(), fixture.platform, request)
	if err != nil {
		t.Fatal(err)
	}
	if draft.Revision != 2 || draft.HeadRevision != 2 || draft.ActiveRevision != 1 || draft.Status != StatusDraft {
		t.Fatalf("unexpected category draft: %#v", draft)
	}
	replayed, err := manager.SaveCategory(t.Context(), fixture.platform, request)
	if err != nil || !replayed.Replayed || replayed.Revision != draft.Revision {
		t.Fatalf("replay = %#v, error = %v", replayed, err)
	}
	request.Change.Nginx.WorkerConnections--
	if _, err := manager.SaveCategory(t.Context(), fixture.platform, request); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("different payload replay error = %v, want ErrIdempotencyConflict", err)
	}

	restartedCore, err := NewService(fixture.pool)
	if err != nil {
		t.Fatal(err)
	}
	restarted, err := NewCategoryManager(restartedCore, nil)
	if err != nil {
		t.Fatal(err)
	}
	afterRestart, err := restarted.GetActiveCategory(t.Context(), fixture.platform, CategoryNginx)
	if err != nil {
		t.Fatal(err)
	}
	if afterRestart.HeadRevision != 2 || afterRestart.ActiveRevision != 1 || afterRestart.Revision != 2 ||
		afterRestart.Status != StatusDraft || !reflect.DeepEqual(afterRestart.Value, draft.Value) ||
		afterRestart.SnapshotSHA256 != draft.SnapshotSHA256 {
		t.Fatalf("restart read lost stream facts: %#v", afterRestart)
	}
}

func TestCategoryReadUsesHeadSnapshotAndPreservesDraftOnSubsequentSave(t *testing.T) {
	for _, status := range []string{StatusDraft, StatusValidated} {
		t.Run(status, func(t *testing.T) {
			fixture := newSystemConfigFixture(t)
			activateInitialSystemConfiguration(t, fixture)
			initial, err := fixture.service.GetRevision(t.Context(), fixture.platform, 1)
			if err != nil {
				t.Fatal(err)
			}
			manager, err := NewCategoryManager(fixture.service, allowExpansion{})
			if err != nil {
				t.Fatal(err)
			}

			firstNginx := initial.Configuration.Nginx
			firstNginx.WorkerConnections--
			first, err := manager.SaveCategory(t.Context(), fixture.platform, SaveCategoryRequest{
				Category: CategoryNginx, ExpectedHeadRevision: 1, Change: CategoryChange{Nginx: &firstNginx},
				IdempotencyKey: "head-read-first-save", RequestID: "head-read-first-save",
			})
			if err != nil {
				t.Fatal(err)
			}
			if status == StatusValidated {
				validated, err := manager.PreflightRevision(t.Context(), fixture.platform, PreflightRevisionRequest{
					Revision: first.Revision, SnapshotSHA256: first.SnapshotSHA256,
					IdempotencyKey: "head-read-preflight", RequestID: "head-read-preflight",
				})
				if err != nil || validated.Status != StatusValidated {
					t.Fatalf("validate head: revision=%#v err=%v", validated, err)
				}
			}

			head, err := manager.GetActiveCategory(t.Context(), fixture.platform, CategoryNginx)
			if err != nil {
				t.Fatal(err)
			}
			headNginx, ok := head.Value.(NginxLimits)
			if !ok {
				t.Fatalf("unexpected category value: %#v", head.Value)
			}
			if head.HeadRevision != 2 || head.ActiveRevision != 1 || head.Revision != 2 ||
				head.Status != status || !reflect.DeepEqual(headNginx, firstNginx) ||
				head.SnapshotSHA256 != first.SnapshotSHA256 {
				t.Errorf("category read did not return head snapshot: %#v", head)
			}

			headNginx.WorkerShutdownTimeoutMS--
			second, err := manager.SaveCategory(t.Context(), fixture.platform, SaveCategoryRequest{
				Category: CategoryNginx, ExpectedHeadRevision: head.HeadRevision,
				Change:         CategoryChange{Nginx: &headNginx},
				IdempotencyKey: "head-read-second-save", RequestID: "head-read-second-save",
			})
			if err != nil {
				t.Fatal(err)
			}
			if second.Revision != 3 || second.HeadRevision != 3 || second.ActiveRevision != 1 || second.Status != StatusDraft {
				t.Fatalf("unexpected subsequent draft: %#v", second)
			}
			stored, err := fixture.service.GetRevision(t.Context(), fixture.platform, second.Revision)
			if err != nil {
				t.Fatal(err)
			}
			if stored.Configuration.Nginx.WorkerConnections != firstNginx.WorkerConnections ||
				stored.Configuration.Nginx.WorkerShutdownTimeoutMS != headNginx.WorkerShutdownTimeoutMS {
				t.Errorf("subsequent save overwrote head draft fields: %#v", stored.Configuration.Nginx)
			}
			active, err := fixture.service.GetRevision(t.Context(), fixture.platform, 1)
			if err != nil || active.Status != StatusActive || !reflect.DeepEqual(active.Configuration.Nginx, initial.Configuration.Nginx) {
				t.Fatalf("editing head changed active revision: status=%q nginx=%#v err=%v", active.Status, active.Configuration.Nginx, err)
			}
		})
	}
}

func TestCategoryConsecutiveWritesPreservePriorHeadDraftChanges(t *testing.T) {
	fixture := newSystemConfigFixture(t)
	activateInitialSystemConfiguration(t, fixture)
	manager, err := NewCategoryManager(fixture.service, nil)
	if err != nil {
		t.Fatal(err)
	}
	nginx := validConfiguration().Nginx
	nginx.WorkerConnections--
	if _, err := manager.SaveCategory(t.Context(), fixture.platform, SaveCategoryRequest{
		Category: CategoryNginx, ExpectedHeadRevision: 1, Change: CategoryChange{Nginx: &nginx},
		IdempotencyKey: "head-nginx", RequestID: "head-nginx",
	}); err != nil {
		t.Fatal(err)
	}
	resources := validConfiguration().Resources
	resources.MaxDomainsPerSite--
	second, err := manager.SaveCategory(t.Context(), fixture.platform, SaveCategoryRequest{
		Category: CategoryResources, ExpectedHeadRevision: 2, Change: CategoryChange{Resources: &resources},
		IdempotencyKey: "head-resources", RequestID: "head-resources",
	})
	if err != nil {
		t.Fatal(err)
	}
	stored, err := fixture.service.GetRevision(t.Context(), fixture.platform, second.Revision)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Configuration.Nginx.WorkerConnections != nginx.WorkerConnections ||
		stored.Configuration.Resources.MaxDomainsPerSite != resources.MaxDomainsPerSite {
		t.Fatalf("second category draft lost prior head change: %#v", stored.Configuration)
	}
}

func TestCategoryConcurrentCASHasOneWinner(t *testing.T) {
	fixture := newSystemConfigFixture(t)
	activateInitialSystemConfiguration(t, fixture)
	manager, err := NewCategoryManager(fixture.service, nil)
	if err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	results := make(chan error, 2)
	var wait sync.WaitGroup
	for index := 0; index < 2; index++ {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			<-start
			resources := validConfiguration().Resources
			resources.MaxDomainsPerSite -= index + 1
			_, err := manager.SaveCategory(context.Background(), fixture.platform, SaveCategoryRequest{
				Category: CategoryResources, ExpectedHeadRevision: 1,
				Change:         CategoryChange{Resources: &resources},
				IdempotencyKey: "category-race-" + string(rune('a'+index)),
				RequestID:      "category-race-" + string(rune('a'+index)),
			})
			results <- err
		}(index)
	}
	close(start)
	wait.Wait()
	close(results)
	var success, conflict int
	for err := range results {
		switch {
		case err == nil:
			success++
		case errors.Is(err, ErrRevisionConflict):
			conflict++
		default:
			t.Fatalf("unexpected race error: %v", err)
		}
	}
	if success != 1 || conflict != 1 || countRows(t, fixture.pool, "system_configuration_revisions") != 2 {
		t.Fatalf("race success=%d conflict=%d revisions=%d", success, conflict,
			countRows(t, fixture.pool, "system_configuration_revisions"))
	}
}

func TestCategoryExpansionFailsClosedButShrinkAndSecretClearWorkOffline(t *testing.T) {
	fixture := newSystemConfigFixture(t)
	activateInitialSystemConfiguration(t, fixture)
	manager, err := NewCategoryManager(fixture.service, nil)
	if err != nil {
		t.Fatal(err)
	}

	expanded := validConfiguration().Resources
	expanded.MaxCCRulesPerPolicy++
	if _, err := manager.SaveCategory(t.Context(), fixture.platform, SaveCategoryRequest{
		Category: CategoryResources, ExpectedHeadRevision: 1, Change: CategoryChange{Resources: &expanded},
		IdempotencyKey: "offline-expand", RequestID: "offline-expand",
	}); !errors.Is(err, ErrEntitlementDenied) {
		t.Fatalf("offline expansion error = %v, want ErrEntitlementDenied", err)
	}
	if countRows(t, fixture.pool, "system_configuration_revisions") != 1 ||
		countRows(t, fixture.pool, "system_configuration_write_requests") != 3 {
		t.Fatal("denied expansion left revision or write facts")
	}
	type persistedState struct {
		revisions int
		head      int64
		writes    int
		audits    int
		drafts    int
	}
	readState := func() persistedState {
		return persistedState{
			revisions: countRows(t, fixture.pool, "system_configuration_revisions"),
			head:      streamHead(t, fixture.pool),
			writes:    countRows(t, fixture.pool, "system_configuration_write_requests"),
			audits:    countRows(t, fixture.pool, "audit_events"),
			drafts:    countStatus(t, fixture.pool, StatusDraft),
		}
	}
	nginx := validConfiguration().Nginx
	nginx.GzipMinimumBytes--
	beforeLower := readState()
	if _, err := manager.SaveCategory(t.Context(), fixture.platform, SaveCategoryRequest{
		Category: CategoryNginx, ExpectedHeadRevision: 1, Change: CategoryChange{Nginx: &nginx},
		IdempotencyKey: "offline-gzip-expand", RequestID: "offline-gzip-expand",
	}); !errors.Is(err, ErrEntitlementDenied) {
		t.Fatalf("offline gzip coverage expansion error = %v, want ErrEntitlementDenied", err)
	}
	beforeLower.audits++ // Only a committed rejection audit may survive denial.
	if after := readState(); after != beforeLower || after.drafts != 0 {
		t.Fatalf("nil-authorizer denial changed persisted state: before=%#v after=%#v", beforeLower, after)
	}

	rejecting := &rejectExpansion{}
	rejectingManager, err := NewCategoryManager(fixture.service, rejecting)
	if err != nil {
		t.Fatal(err)
	}
	beforeRejected := readState()
	if _, err := rejectingManager.SaveCategory(t.Context(), fixture.platform, SaveCategoryRequest{
		Category: CategoryNginx, ExpectedHeadRevision: 1, Change: CategoryChange{Nginx: &nginx},
		IdempotencyKey: "rejected-gzip-expand", RequestID: "rejected-gzip-expand",
	}); !errors.Is(err, ErrEntitlementDenied) {
		t.Fatalf("rejected gzip coverage expansion error = %v, want ErrEntitlementDenied", err)
	}
	beforeRejected.audits++
	if after := readState(); rejecting.calls != 1 || after != beforeRejected || after.drafts != 0 {
		t.Fatalf("rejecting-authorizer denial calls=%d changed persisted state: before=%#v after=%#v",
			rejecting.calls, beforeRejected, after)
	}

	contracted := validConfiguration().Nginx
	contracted.GzipMinimumBytes++
	beforeContracted := readState()
	contractedDraft, err := manager.SaveCategory(t.Context(), fixture.platform, SaveCategoryRequest{
		Category: CategoryNginx, ExpectedHeadRevision: 1, Change: CategoryChange{Nginx: &contracted},
		IdempotencyKey: "offline-gzip-contract", RequestID: "offline-gzip-contract",
	})
	if err != nil {
		t.Fatalf("offline gzip coverage contraction: %v", err)
	}
	afterContracted := readState()
	if contractedDraft.Revision != 2 || contractedDraft.HeadRevision != 2 ||
		afterContracted.revisions != beforeContracted.revisions+1 ||
		afterContracted.head != beforeContracted.head+1 || afterContracted.writes != beforeContracted.writes+1 ||
		afterContracted.audits != beforeContracted.audits+1 || afterContracted.drafts != 1 {
		t.Fatalf("gzip coverage contraction result=%#v before=%#v after=%#v",
			contractedDraft, beforeContracted, afterContracted)
	}

	cleared, err := manager.SaveCategory(t.Context(), fixture.platform, SaveCategoryRequest{
		Category: CategorySecrets, ExpectedHeadRevision: 2,
		Change:         CategoryChange{Secret: &SecretChange{Intent: SecretIntentClear}},
		IdempotencyKey: "offline-clear", RequestID: "offline-clear",
	})
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(cleared)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "vault:error-pages/prod-html") || strings.Contains(string(encoded), "reference") {
		t.Fatalf("secret clear response leaked reference: %s", encoded)
	}
}

func TestCategorySecretReplaceMasksResponseAndAudit(t *testing.T) {
	fixture := newSystemConfigFixture(t)
	activateInitialSystemConfiguration(t, fixture)
	manager, err := NewCategoryManager(fixture.service, allowExpansion{})
	if err != nil {
		t.Fatal(err)
	}
	replacement := &SecretEnvelopeReference{Provider: SecretProviderVault, Reference: "vault:error-pages/replaced-prod",
		KeyID: "error-pages-key-v2", Algorithm: EnvelopeAES256GCM, CiphertextSHA256: strings.Repeat("e", 64)}
	result, err := manager.SaveCategory(t.Context(), fixture.platform, SaveCategoryRequest{
		Category: CategorySecrets, ExpectedHeadRevision: 1,
		Change:         CategoryChange{Secret: &SecretChange{Intent: SecretIntentReplace, Replacement: replacement}},
		IdempotencyKey: "secret-replace", RequestID: "secret-replace",
	})
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), replacement.Reference) || !strings.Contains(string(encoded), "****prod") {
		t.Fatalf("secret replace response was not masked: %s", encoded)
	}
	var auditText string
	if err := fixture.pool.QueryRow(t.Context(), `SELECT payload::text FROM audit_events
		WHERE request_id='secret-replace'`).Scan(&auditText); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(auditText, replacement.Reference) {
		t.Fatalf("audit leaked secret reference: %s", auditText)
	}
}

func TestCategoryPermissionRecheckAndAuditFailureRollback(t *testing.T) {
	fixture := newSystemConfigFixture(t)
	activateInitialSystemConfiguration(t, fixture)
	manager, err := NewCategoryManager(fixture.service, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.pool.Exec(t.Context(), `DELETE FROM role_permissions
		WHERE role_id IN (SELECT role_id FROM role_assignments WHERE scope_id=$1 AND user_id=$2)
		AND permission_name='system_configuration.manage'`, fixture.platform.ScopeID, fixture.platform.UserID); err != nil {
		t.Fatal(err)
	}
	resources := validConfiguration().Resources
	resources.MaxSitesPerTenant--
	if _, err := manager.SaveCategory(t.Context(), fixture.platform, SaveCategoryRequest{
		Category: CategoryResources, ExpectedHeadRevision: 1, Change: CategoryChange{Resources: &resources},
		IdempotencyKey: "revoked-category", RequestID: "revoked-category",
	}); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("revoked permission error = %v, want ErrPermissionDenied", err)
	}

	failingCore, err := NewServiceWithDependencies(fixture.pool, failingAuditor{}, fixture.clock.Now)
	if err != nil {
		t.Fatal(err)
	}
	failingManager, err := NewCategoryManager(failingCore, nil)
	if err != nil {
		t.Fatal(err)
	}
	// Restore the permission so the injected auditor is the failing boundary.
	if _, err := fixture.pool.Exec(t.Context(), `INSERT INTO role_permissions(role_id,permission_name)
		SELECT role_id,'system_configuration.manage' FROM role_assignments WHERE scope_id=$1 AND user_id=$2`,
		fixture.platform.ScopeID, fixture.platform.UserID); err != nil {
		t.Fatal(err)
	}
	beforeRevisions := countRows(t, fixture.pool, "system_configuration_revisions")
	beforeWrites := countRows(t, fixture.pool, "system_configuration_write_requests")
	if _, err := failingManager.SaveCategory(t.Context(), fixture.platform, SaveCategoryRequest{
		Category: CategoryResources, ExpectedHeadRevision: 1, Change: CategoryChange{Resources: &resources},
		IdempotencyKey: "audit-category", RequestID: "audit-category",
	}); !errors.Is(err, errInjectedAudit) {
		t.Fatalf("audit failure error = %v, want injected failure", err)
	}
	if countRows(t, fixture.pool, "system_configuration_revisions") != beforeRevisions ||
		countRows(t, fixture.pool, "system_configuration_write_requests") != beforeWrites {
		t.Fatal("audit failure did not roll back category revision and idempotency claim")
	}
	resources.MaxSitesPerTenant += 2
	if _, err := failingManager.SaveCategory(t.Context(), fixture.platform, SaveCategoryRequest{
		Category: CategoryResources, ExpectedHeadRevision: 1, Change: CategoryChange{Resources: &resources},
		IdempotencyKey: "denied-audit-category", RequestID: "denied-audit-category",
	}); !errors.Is(err, errInjectedAudit) {
		t.Fatalf("denial audit failure error = %v, want injected failure", err)
	}
	if countRows(t, fixture.pool, "system_configuration_revisions") != beforeRevisions ||
		countRows(t, fixture.pool, "system_configuration_write_requests") != beforeWrites {
		t.Fatal("denial audit failure left a revision or idempotency claim")
	}
}

func activateInitialSystemConfiguration(t *testing.T, fixture systemConfigFixture) {
	t.Helper()
	draft, err := fixture.service.CreateDraft(t.Context(), fixture.platform,
		createDraftRequest(0, "category-initial", validConfiguration()))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.service.RecordPreflight(t.Context(), fixture.platform,
		passingPreflight(1, draft.SnapshotSHA256, "category-initial-preflight")); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.service.Activate(t.Context(), fixture.platform, ActivateRequest{
		Revision: 1, ExpectedActiveRevision: 0,
		IdempotencyKey: "category-initial-activate", RequestID: "category-initial-activate",
	}); err != nil {
		t.Fatal(err)
	}
}

var _ AuditAppender = failingAuditor{}
