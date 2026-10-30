//go:build integration

package edgepublish_test

import (
	"bytes"
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/edgepublish"
	"github.com/cdnca/cdnca/services/control-api/internal/errorpagecontrol"
	"github.com/cdnca/cdnca/services/control-api/internal/theme"
	"github.com/google/uuid"
)

type themeAdmin struct {
	service *theme.Service
	actor   theme.Actor
}

func newThemeAdmin(t *testing.T, scope *edgepublish.SystemRepublishScope) themeAdmin {
	t.Helper()
	platformScopeID, userID := scope.PlatformAdmin(t)
	service, err := theme.NewService(scope.Pool, audit.New(scope.Pool), nil, officialFixtureCatalog(), time.Now)
	if err != nil {
		t.Fatal(err)
	}
	return themeAdmin{service: service, actor: theme.Actor{UserID: userID, ScopeID: platformScopeID,
		ScopeKind: "platform", IP: "198.51.100.9", RequestID: "theme-republish-1"}}
}

func (admin themeAdmin) activate(t *testing.T, themeID string) theme.ActivationResult {
	t.Helper()
	view, err := admin.service.Download(t.Context(), admin.actor, themeID)
	if err != nil {
		t.Fatal(err)
	}
	catalog, err := admin.service.Catalog(t.Context(), admin.actor)
	if err != nil {
		t.Fatal(err)
	}
	result, err := admin.service.Activate(t.Context(), admin.actor, view.PackageSHA256, catalog.ActivationRevision)
	if err != nil {
		t.Fatalf("activate %s: %v", themeID, err)
	}
	return result
}

func snapshotRevision(t *testing.T, wire []byte) (uint64, map[string][]byte) {
	t.Helper()
	var document errorpagecontrol.ProductionSnapshotDocument
	if err := json.Unmarshal(wire, &document); err != nil {
		t.Fatal(err)
	}
	pages := map[string][]byte{}
	for _, rule := range document.Global.Rules {
		pages[rule.ID] = rule.Resource.Body
	}
	return document.Binding.PublicationRevision, pages
}

func auditPayloads(t *testing.T, scope *edgepublish.SystemRepublishScope, action string) []map[string]any {
	t.Helper()
	rows, err := scope.Pool.Query(t.Context(), `SELECT payload FROM audit_events WHERE action=$1 ORDER BY occurred_at,stream_position`, action)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var payloads []map[string]any
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			t.Fatal(err)
		}
		var payload map[string]any
		if err := json.Unmarshal(raw, &payload); err != nil {
			t.Fatal(err)
		}
		payloads = append(payloads, payload)
	}
	return payloads
}

// TestThemeActivationRepublishesEveryTenantsErrorPages:
// activating a theme queues, in the activation's transaction, a
// system republication (trigger theme_activation) of every tenant scope that
// has published error pages; the worker publishes each scope's error page
// snapshot with the new theme's default pages to its nodes, as the system,
// with no tenant publish. Activating the active theme again queues nothing.
func TestThemeActivationRepublishesEveryTenantsErrorPages(t *testing.T) {
	first := edgepublish.NewSystemRepublishScope(t)
	second := first.SecondScope(t)
	idle := first.SecondScope(t) // never published error pages: not queued
	firstNode, secondNode := first.AddNode(t, 6), second.AddNode(t, 6)
	_ = idle.AddNode(t, 6)
	publisher := first.EnableErrorPagePublisher(t)
	second.EnableErrorPagePublisher(t)
	first.SeedErrorPagePublication(t)
	first.PublishErrorPages(t, publisher, "ep-first", firstNode)
	second.PublishErrorPages(t, second.NewErrorPagePublisher(t), "ep-second", secondNode)
	first.SettleDeployments(t)
	second.SettleDeployments(t)

	admin := newThemeAdmin(t, first)
	activated := admin.activate(t, officialFixtureID)
	if activated.ErrorPageRepublishScopes != 2 {
		t.Fatalf("activation queued %d scopes, want 2", activated.ErrorPageRepublishScopes)
	}
	for _, scope := range []*edgepublish.SystemRepublishScope{first, second} {
		if got := scope.Count(t, `SELECT count(*) FROM edge_system_republication_heads
			WHERE scope_id=$1 AND state='pending' AND 'theme_activation'=ANY(triggers)`); got != 1 {
			t.Fatalf("scope %s head pending theme_activation = %d", scope.ScopeID, got)
		}
	}
	if got := idle.Count(t, `SELECT count(*) FROM edge_system_republication_heads WHERE scope_id=$1`); got != 0 {
		t.Fatalf("scope without error pages queued: %d", got)
	}
	catalog, err := admin.service.Catalog(t.Context(), admin.actor)
	if err != nil || catalog.ErrorPageRepublication.Total != 2 || catalog.ErrorPageRepublication.Pending != 2 {
		t.Fatalf("catalog progress = %+v, %v", catalog.ErrorPageRepublication, err)
	}

	// The same theme again: nothing new is activated or queued.
	again, err := admin.service.Activate(t.Context(), admin.actor, activated.PackageSHA256, activated.Revision)
	if err != nil || !again.AlreadyActive || again.Revision != activated.Revision || again.ErrorPageRepublishScopes != 0 {
		t.Fatalf("re-activation = %+v, %v", again, err)
	}
	if got := first.Count(t, `SELECT count(*) FROM theme_error_page_republications WHERE scope_id=$1`); got != 1 {
		t.Fatalf("re-activation queued again: %d rows", got)
	}

	for _, scope := range []*edgepublish.SystemRepublishScope{first, second} {
		scope.MakeDue(t)
		scope.Run(t)
		attempt := scope.LatestAttempt(t)
		if attempt.Outcome != edgepublish.SystemOutcomePublished || !slices.Equal(attempt.Triggers, []string{"theme_activation"}) {
			t.Fatalf("scope %s attempt = %+v", scope.ScopeID, attempt)
		}
		rollouts := scope.ErrorPageRollouts(t)
		if len(rollouts) != 2 {
			t.Fatalf("scope %s error page rollouts = %d", scope.ScopeID, len(rollouts))
		}
		revision, pages := snapshotRevision(t, rollouts[1].Snapshot)
		if revision != uint64(activated.ErrorPagePublicationRevision) {
			t.Fatalf("republished revision %d, want %d", revision, activated.ErrorPagePublicationRevision)
		}
		if page := pages["theme.edge_connect.502"]; !bytes.Contains(page, []byte("#0f766e")) {
			t.Fatalf("republished page does not carry the new theme:\n%s", page)
		}
		if !slices.Equal(rollouts[1].NodeIDs, rollouts[0].NodeIDs) {
			t.Fatalf("republished to %v, last error page rollout went to %v", rollouts[1].NodeIDs, rollouts[0].NodeIDs)
		}
		if got := scope.Count(t, `SELECT count(*) FROM theme_error_page_republications
			WHERE scope_id=$1 AND state='published' AND rollout_id=$2`, rollouts[1].ID); got != 1 {
			t.Fatalf("scope %s progress not published", scope.ScopeID)
		}
	}
	catalog, err = admin.service.Catalog(t.Context(), admin.actor)
	if err != nil || catalog.ErrorPageRepublication.Published != 2 || catalog.ErrorPageRepublication.Pending != 0 {
		t.Fatalf("catalog progress after = %+v, %v", catalog.ErrorPageRepublication, err)
	}

	// Audit: the activation carries changes and the scope count; the system
	// event names the theme and the scopes; each publish is the system's.
	activations := auditPayloads(t, first, theme.ActionActivate)
	// Since migration 361 the changes live in their own column.
	var changes int
	if err := first.Pool.QueryRow(t.Context(), `SELECT jsonb_array_length(changes) FROM audit_events WHERE action=$1`,
		theme.ActionActivate).Scan(&changes); err != nil {
		t.Fatal(err)
	}
	if len(activations) != 1 || activations[0]["error_page_republish_scopes"] != float64(2) || changes == 0 {
		t.Fatalf("activation audits = %+v (changes %d)", activations, changes)
	}
	republish := auditPayloads(t, first, edgepublish.ThemeRepublicationAudit)
	if len(republish) != 1 || republish[0]["actor_kind"] != "system" || republish[0]["theme_id"] != officialFixtureID ||
		republish[0]["scope_count"] != float64(2) || republish[0]["ip"] != "198.51.100.9" {
		t.Fatalf("republish audits = %+v", republish)
	}
	systemPublishes := 0
	for _, payload := range auditPayloads(t, first, "edge_error_page.publish") {
		if payload["actor_kind"] == "system" {
			systemPublishes++
		}
	}
	if systemPublishes != 2 {
		t.Fatalf("system error page publishes = %d", systemPublishes)
	}
	var actorUser *uuid.UUID
	if err := first.Pool.QueryRow(t.Context(), `SELECT actor_user_id FROM audit_events WHERE action='edge_error_page.publish'
		AND payload->>'actor_kind'='system' LIMIT 1`).Scan(&actorUser); err != nil || actorUser != nil {
		t.Fatalf("system publish audit actor = %v, %v", actorUser, err)
	}
}

// TestThemeRepublicationRetriesAndSwitchesBack: a node still deploying makes
// the error page rollout fail; the attempt is retried (system channel
// backoff) and succeeds once the node is free. Switching back to the default
// theme queues again and the scope ends on the default pages; an earlier
// pending activation is superseded.
func TestThemeRepublicationRetriesAndSwitchesBack(t *testing.T) {
	scope := edgepublish.NewSystemRepublishScope(t)
	node := scope.AddNode(t, 6)
	publisher := scope.EnableErrorPagePublisher(t)
	scope.SeedErrorPagePublication(t)
	scope.PublishErrorPages(t, publisher, "ep-retry", node)
	admin := newThemeAdmin(t, scope)
	admin.activate(t, officialFixtureID)

	// The node's first error page deployment is still running.
	scope.MakeDue(t)
	if worked, err := scope.RunWithErrors(t); !worked || err != nil {
		t.Fatalf("busy node: worked=%v err=%v", worked, err)
	}
	attempt := scope.LatestAttempt(t)
	if attempt.Outcome != edgepublish.SystemOutcomeRetry || attempt.ErrorClass == nil {
		t.Fatalf("busy node attempt = %+v", attempt)
	}
	if got := scope.Count(t, `SELECT count(*) FROM theme_error_page_republications WHERE scope_id=$1 AND state='pending'`); got != 1 {
		t.Fatalf("pending after retry = %d", got)
	}

	// Switch back before the retry runs: one publication delivers the latest.
	back := admin.activate(t, theme.DefaultThemeID)
	if got := scope.Count(t, `SELECT count(*) FROM theme_error_page_republications WHERE scope_id=$1 AND state='skipped'
		AND error_class='superseded'`); got != 1 {
		t.Fatalf("earlier activation not superseded: %d", got)
	}
	scope.SettleDeployments(t)
	scope.MakeDue(t)
	scope.Run(t)
	if attempt := scope.LatestAttempt(t); attempt.Outcome != edgepublish.SystemOutcomePublished {
		t.Fatalf("after node freed attempt = %+v", attempt)
	}
	rollouts := scope.ErrorPageRollouts(t)
	revision, pages := snapshotRevision(t, rollouts[len(rollouts)-1].Snapshot)
	if revision != uint64(back.ErrorPagePublicationRevision) || !bytes.Contains(pages["theme.edge_connect.502"], []byte("#2d8cf0")) {
		t.Fatalf("switch back delivered revision %d:\n%s", revision, pages["theme.edge_connect.502"])
	}
}

// TestThemeRepublicationMergesWithConfigurationTrigger: a configuration
// trigger merged into the same head goes first; the error page publication
// follows in its own claim, so neither rollout finds the other running.
func TestThemeRepublicationMergesWithConfigurationTrigger(t *testing.T) {
	scope := edgepublish.NewSystemRepublishScope(t)
	node := scope.AddNode(t, 6)
	if err := scope.PublishManually(t, "config-first", node); err != nil {
		t.Fatal(err)
	}
	scope.SettleDeployments(t)
	publisher := scope.EnableErrorPagePublisher(t)
	scope.SeedErrorPagePublication(t)
	scope.PublishErrorPages(t, publisher, "ep-merge", node)
	scope.SettleDeployments(t)
	newThemeAdmin(t, scope).activate(t, officialFixtureID)
	scope.Request(t, edgepublish.SystemTriggerNodeSync)
	scope.MakeDue(t)
	if worked, err := scope.RunWithErrors(t); !worked || err != nil {
		t.Fatalf("first run: %v", err)
	}
	attempt := scope.LatestAttempt(t)
	if slices.Contains(attempt.Triggers, "theme_activation") || attempt.Outcome != edgepublish.SystemOutcomePublished {
		t.Fatalf("configuration attempt = %+v", attempt)
	}
	if got := scope.Count(t, `SELECT count(*) FROM edge_system_republication_heads WHERE scope_id=$1 AND state='pending'
		AND triggers=ARRAY['theme_activation']`); got != 1 {
		t.Fatalf("theme_activation not queued again: %d", got)
	}
	scope.SettleDeployments(t)
	scope.MakeDue(t)
	scope.Run(t)
	if attempt := scope.LatestAttempt(t); attempt.Outcome != edgepublish.SystemOutcomePublished ||
		!slices.Equal(attempt.Triggers, []string{"theme_activation"}) {
		t.Fatalf("theme attempt = %+v", attempt)
	}
}

// Without an error page publisher (the error page runtime is off) the claim
// fails and is retried, never dropped.
func TestThemeRepublicationWithoutPublisherRetries(t *testing.T) {
	scope := edgepublish.NewSystemRepublishScope(t)
	node := scope.AddNode(t, 6)
	scope.SeedErrorPagePublication(t)
	scope.PublishErrorPages(t, scope.NewErrorPagePublisher(t), "ep-none", node)
	newThemeAdmin(t, scope).activate(t, officialFixtureID)
	scope.MakeDue(t)
	if worked, err := scope.RunWithErrors(t); !worked || err != nil {
		t.Fatalf("missing publisher: %v", err)
	}
	if attempt := scope.LatestAttempt(t); attempt.Outcome != edgepublish.SystemOutcomeRetry || attempt.ErrorClass == nil ||
		!strings.Contains(*attempt.ErrorClass, "error page publisher") {
		t.Fatalf("attempt = %+v", attempt)
	}
	if got := scope.Count(t, `SELECT count(*) FROM theme_error_page_republications WHERE scope_id=$1 AND state='pending'`); got != 1 {
		t.Fatalf("pending dropped: %d", got)
	}
}

// officialFixtureID / officialFixtureCatalog: the community edition ships only
// the default theme; these tests need a second downloadable theme, so they use
// the default package under an official id with its own primary color.
const officialFixtureID = "official.slate"

func officialFixtureRaw() []byte {
	var document map[string]any
	if err := json.Unmarshal(theme.BuiltinCatalog()[0].Raw, &document); err != nil {
		panic(err)
	}
	document["id"] = officialFixtureID
	document["tokens"] = map[string]any{"colorPrimary": "#0f766e"}
	raw, err := json.Marshal(document)
	if err != nil {
		panic(err)
	}
	return raw
}

func officialFixtureCatalog() []theme.CatalogEntry {
	return append(theme.BuiltinCatalog(), theme.CatalogEntry{ID: officialFixtureID, Raw: officialFixtureRaw()})
}
