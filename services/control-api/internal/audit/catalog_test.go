package audit

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

func TestEventCatalogIntegrity(t *testing.T) {
	if len(duplicateActions) > 0 {
		t.Fatalf("actions registered twice: %v", duplicateActions)
	}
	for _, entry := range Entries() {
		for _, problem := range validateEntry(entry) {
			t.Errorf("%s: %s", entry.Action, problem)
		}
	}
}

// The audit_events.category CHECK (migration 361) must list exactly the
// catalog categories.
func TestCategoriesMatchMigrationCheck(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "migrations", "361_audit_unified_fields.up.sql"))
	if err != nil {
		t.Fatal(err)
	}
	check := regexp.MustCompile(`(?s)audit_events_category_361 CHECK \(category IN \((.*?)\)\)`).FindSubmatch(raw)
	if check == nil {
		t.Fatal("category CHECK not found in migration 361")
	}
	var inSQL []string
	for _, quoted := range regexp.MustCompile(`'([a-z]+)'`).FindAllSubmatch(check[1], -1) {
		inSQL = append(inSQL, string(quoted[1]))
	}
	var inGo []string
	for _, info := range Categories() {
		inGo = append(inGo, string(info.Category))
	}
	sort.Strings(inSQL)
	sort.Strings(inGo)
	if strings.Join(inSQL, ",") != strings.Join(inGo, ",") {
		t.Fatalf("migration categories %v != catalog categories %v", inSQL, inGo)
	}
}

// TestEventCatalogCoversProductionActions is the埋点 gate: every action the
// control-api production code can write must be in the catalog, every
// dynamic (statically unresolvable) Action site must be listed in
// dynamicActionSites with its possible values, and every catalog entry must
// still be written somewhere.
func TestEventCatalogCoversProductionActions(t *testing.T) {
	scanner := loadActionScanner(t, filepath.Join("..", ".."))
	written := map[string]bool{}
	seenDynamic := map[string]bool{}
	for _, site := range scanner.sites() {
		values := site.Values
		if !site.Resolved {
			listed, ok := dynamicActionSites[site.Key]
			if !ok {
				t.Errorf("%s (%s): Action is not a constant the scanner can resolve; resolved so far %v. "+
					"Use catalogued constants, or list every possible value in dynamicActionSites[%q]",
					site.Position, site.Key, site.Values, site.Key)
				continue
			}
			seenDynamic[site.Key] = true
			values = append(append([]string(nil), values...), listed...)
		}
		for _, action := range values {
			written[action] = true
			if _, ok := Lookup(action); !ok {
				t.Errorf("%s: action %q is not in the event catalog (internal/audit/catalog_*.go)", site.Position, action)
			}
		}
	}
	for key := range dynamicActionSites {
		if !seenDynamic[key] {
			t.Errorf("dynamicActionSites[%q] no longer matches an unresolved Action site; remove it", key)
		}
	}
	for _, entry := range Entries() {
		if !written[entry.Action] && !catalogOnlyActions[entry.Action] && !communityCatalogOnly(entry.Action) {
			t.Errorf("catalog entry %q is not written by any production code; remove it or list it in catalogOnlyActions", entry.Action)
		}
	}
}

// catalogOnlyActions are catalogued actions written by something the scanner
// does not see (another service writing into this catalog, SQL).
var catalogOnlyActions = map[string]bool{
	"system.signer_trust.publish":  true, // license-service signercheckpointstore.EdgeSignerTrustAuditAction
	"rule.intel.report.ingest":     true, // license-service licensing.RuleIntelIngestAction
	"rule.intel.job.run":           true, // license-service licensing.RuleIntelJobAction
	"rule.intel.candidate.reject":  true, // license-service licensing.RuleIntelCandidateRejectAction
	"rule.intel.candidate.restore": true, // license-service licensing.RuleIntelCandidateRestoreAction
	"rule.intel.corpus.add":        true, // license-service licensing.RuleIntelCorpusAddAction
	"rule.intel.merge.create":      true, // license-service licensing.RuleIntelMergeCreateAction
	"rule.intel.merge.gate":        true, // license-service licensing.RuleIntelMergeGateAction
	"rule.intel.merge.publish":     true, // license-service licensing.RuleIntelMergePublishAction
	"rule.intel.merge.abandon":     true, // license-service licensing.RuleIntelMergeAbandonAction
	"rule.intel.rollout.advance":   true, // license-service licensing.RuleIntelRolloutAdvanceAction
	"rule.intel.rollout.pause":     true, // license-service licensing.RuleIntelRolloutPauseAction
	"rule.intel.rollout.resume":    true, // license-service licensing.RuleIntelRolloutResumeAction
	"rule.intel.rollout.rollback":  true, // license-service licensing.RuleIntelRolloutRollbackAction
	"rule.intel.rule.withdraw":     true, // license-service licensing.RuleIntelRuleWithdrawAction
	"rule.intel.rule.restore":      true, // license-service licensing.RuleIntelRuleRestoreAction
}

// dynamicActionSites lists, per "<file>:<function>", every action an Action
// expression the scanner cannot resolve may produce. Keep it in step with the
// code: a new value there must be added here (and to the catalog).
var dynamicActionSites = map[string][]string{
	// fix-dnscert3 卡 2-B: the system switches a delivered renewal in.
	"internal/certificateasset/renewal_activation.go:ActivateRenewalTx": {"certificate.asset.bind",
		"certificate.asset.activate", "certificate.order.transition"},
	// controlbackuphttp/handler.go: settings, submit(job.Kind ∈ nativebackup.Request*), recovery kit.
	// fix-migrollback: + stop, rollback (rollback.go); the auditor is shared with the frozen console.
	"cmd/control-api/native_backup.go:controlBackupAuditor": {"control_backup.settings_update",
		"control_backup.backup_request", "control_backup.delete_request", "control_backup.migrate_request",
		"control_backup.recovery_kit_export", "control_backup.migrate_stop", "control_backup.rollback_request"},
	// operationFor(Kind matcher|filter, create|update|delete).
	"internal/ccreference/store.go:appendAudit": {"cc_reference.matcher.create", "cc_reference.matcher.update",
		"cc_reference.matcher.delete", "cc_reference.filter.create", "cc_reference.filter.update", "cc_reference.filter.delete"},
	// validateRolloutActionRequest: Operation ∈ PlanStart/PlanPauseAction/PlanResume/PlanRollback.
	"internal/controlupgrade/runtime_action.go:FinalizeRolloutAction": {"control_upgrade_rollout.start",
		"control_upgrade_rollout.pause", "control_upgrade_rollout.resume", "control_upgrade_rollout.rollback"},
	"internal/controlupgrade/runtime_action.go:appendRolloutDeniedAuditOnce": {"control_upgrade_rollout.start",
		"control_upgrade_rollout.pause", "control_upgrade_rollout.resume", "control_upgrade_rollout.rollback"},
	// dnsCommandAuditEvent rejects anything but ActionApply/ActionCommit/ActionCancel.
	"internal/dnsreconcile/postgres_store.go:dnsCommandAuditEvent": {"dns.reconcile.apply", "dns.reconcile.commit",
		"dns.reconcile.cancel"},
	// outcome: StateFailed (deadline, claim failures) or classifyPersistedRollout (StateSucceeded/StateFailed).
	"internal/edgeautopublish/store.go:appendTerminalAudit": {"edge_automatic_publication.succeeded",
		"edge_automatic_publication.failed"},
	// systemAttempt outcomes plus SystemOutcomeRetry/Failed from fail().
	"internal/edgepublish/system_republish.go:appendSystemRepublicationAudit": {"edge_system_republication.published",
		"edge_system_republication.unchanged", "edge_system_republication.blocked_unpublished_changes",
		"edge_system_republication.no_baseline", "edge_system_republication.no_capable_target",
		"edge_system_republication.automatic_scope", "edge_system_republication.retry", "edge_system_republication.failed"},
	// CommandOperation ∈ CommandCancel/CommandRetry/CommandReplay.
	"internal/jobhttp/command_postgres.go:appendCommandAudit": {"job.cancel", "job.retry", "job.replay"},
	// "l4_line_switch.state." + after.State for every CompareAndSwap target state in service.go.
	"internal/l4lineswitch/postgres.go:CompareAndSwap": {"l4_line_switch.state.health_gate",
		"l4_line_switch.state.draining_old", "l4_line_switch.state.completed", "l4_line_switch.state.compensating_old",
		"l4_line_switch.state.rolled_back", "l4_line_switch.state.needs_attention"},
	// RecordFrontend allows route_error/api_error/render_error only.
	"internal/observabilitylog/store.go:AppendFrontend": {"frontend.route_error", "frontend.api_error",
		"frontend.render_error"},
	// packageaddon.Valid: product.create/update/delete, assignment.create/update/delete.
	"internal/packageaddon/store.go:Write": {"package.addon.product.create", "package.addon.product.update",
		"package.addon.product.delete", "package.addon.assignment.create", "package.addon.assignment.update",
		"package.addon.assignment.delete"},
	// receipt.Action ∈ ActionConfirm/ActionUpgrade/ActionDisable/ActionResume/ActionUninstall.
	"internal/plugininstallation/postgres.go:Save": {"plugin_installation.confirm", "plugin_installation.upgrade",
		"plugin_installation.disable", "plugin_installation.resume", "plugin_installation.uninstall"},
	// input.Action: opCreate/opTest/opReplay/opRotate/opActivate/opRevoke (and checkRate with the same ops).
	"internal/pluginwebhookcontrol/audit.go:appendWebhookAudit": {"plugin_webhook.subscription.create",
		"plugin_webhook.test_delivery.create", "plugin_webhook.delivery.replay", "plugin_webhook.secret.rotate",
		"plugin_webhook.secret.activate", "plugin_webhook.subscription.revoke"},
	// statusRecoveryKind + "." + validRecoveryTrigger.
	"internal/site/status_recovery.go:requestStatusRecovery": {"site.status_recovery.renewal",
		"site.status_recovery.traffic_top_up", "site.status_recovery.unlock"},
	// validBatchAction.
	"internal/site/store.go:appendBatchAudit": {"site.batch.enable", "site.batch.disable", "site.batch.delete",
		"site.batch.regenerate_cname", "site.batch.set_protocols"},
}

// communityCatalogOnly: cdncaCE keeps the commercial modules' audit entries
// (the schema and audit history are shared with the commercial edition, so a
// database written by it still renders here) but compiles no code writing
// them: automatic defense and adaptive WAF, aggregated edge (and its fallback
// chain), migration import, and billing / package commerce (balances, orders,
// recharge and payment channels, finance-system bridge, resellers, sold
// packages and their cycle / traffic enforcement, package monitor, traffic
// packages, TCP billing, promotions), the website and tenant themes, attack
// escalation.
func communityCatalogOnly(action string) bool {
	for _, prefix := range []string{"security.autodefense.", "security.waf.auto_exclusion_", "security.waf.grey_",
		"aggregated_edge.", "fallback_chain.", "migrate_import.", "system.migrate_import.",
		"billing.", "billing_bridge.", "finance.", "reseller.", "tcp_billing.", "traffic_package.", "promotion.",
		"package.auto_renew.", "package.commerce.", "package.period_reset.", "package.product.", "package.group.",
		"package.addon.assignment.purchase", "site.package.sync", "site.package.delete",
		"package.sold.", "package.traffic.", "package_cycle.", "package_monitor.",
		"site.package_traffic.", "stream.package_traffic.", "plugin.provider.payment_alert",
		// the website (官网) and tenant / white-label themes.
		"control_site.", "theme.tenant.", "theme.tenant_domain.", "theme.tenant_policy.",
		// attack escalation (攻击自动升级): line group tiers / grants and package policies.
		"security.escalate.", "package.escalate_policy.", "node.line_group.grant", "node.line_group.tier_update"} {
		if strings.HasPrefix(action, prefix) {
			return true
		}
	}
	return false
}
