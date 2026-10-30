//go:build integration

package artifactsync_test

import (
	"bytes"
	"crypto/rand"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/entitlement/ruleintel"
	"github.com/cdnca/cdnca/libs/rulepack"
	"github.com/google/uuid"
)

// crsTuningSource is an official system/crs-tuning pack as the license
// service publishes it from rule intelligence (RI-12).
func crsTuningSource(version string) []byte {
	return []byte(`{"schema":"cdnca.rule-pack/v1","pack_id":"system/crs-tuning","version":"` + version + `",
		"layer":"system","engine":"modsecurity","engine_min_version":1,"name":"CRS 官方调优","description":"d",
		"params_schema":{},"exports":["1"],"defaults":{},
		"rules":[{"id":"1","name":"排除 942100","tuning":{"min_paranoia":1,"rule":942100,
		"targets":[{"loc":"args","name":"content"}]}}]}`)
}

// TestSystemRulePacksReachNodesWithoutMounts: an
// enabled official system pack goes to every node by its current version,
// with no site mount — sealed bytes plus a key wrap per active node key —
// and leaves once the platform disables it; node receipts are summed by
// official pack version for the rule intel report (PackReceipts).
func TestSystemRulePacksReachNodesWithoutMounts(t *testing.T) {
	f := newFixture(t)
	ctx := t.Context()
	installationPrivate, installationPublic := x25519(t)
	cek := make([]byte, rulepack.CEKSize)
	if _, err := rand.Read(cek); err != nil {
		t.Fatal(err)
	}
	entry, sealed := sealFor(t, crsTuningSource("1.0.0"), cek, installationPublic)
	f.license.Publish(entry, sealed)
	if err := f.syncerWithKey(installationPrivate).SyncOnce(ctx); err != nil {
		t.Fatal(err)
	}
	var current *string
	var policy string
	if err := f.pool.QueryRow(ctx, `SELECT current_version,update_policy FROM rule_packs WHERE pack_id='system/crs-tuning'`).
		Scan(&current, &policy); err != nil || current == nil || *current != "1.0.0" || policy != "auto" {
		t.Fatalf("system pack current=%v policy=%s err=%v", current, policy, err)
	}
	if mounted, err := f.store.MountedRulePacks(ctx); err != nil || len(mounted) != 0 {
		t.Fatalf("mounted = %+v, %v (no site mounts it)", mounted, err)
	}
	system, err := f.store.SystemRulePacks(ctx)
	if err != nil || len(system) != 1 || system[0].PackID != "system/crs-tuning" || system[0].Version != "1.0.0" ||
		!system[0].Sealed || system[0].SHA256 != entry.SHA256 || !bytes.Equal(system[0].Content, sealed) {
		t.Fatalf("system packs = %+v, %v", system, err)
	}
	nodeID, keyID, nodePrivate := f.node(t, "sys")
	if added, err := f.store.WrapNodeKeys(ctx, installationPrivate); err != nil || added != 1 {
		t.Fatalf("wraps for the system pack = %d, %v", added, err)
	}
	wraps, err := f.store.NodeKeyWraps(ctx, nodeID)
	if err != nil || len(wraps) != 1 || wraps[0].SealedSHA256 != entry.SHA256 {
		t.Fatalf("node wraps = %+v, %v", wraps, err)
	}
	opened, err := rulepack.UnwrapKey(nodePrivate, wraps[0].WrappedKey, rulepack.WrapContext{Purpose: rulepack.WrapPurposeNode,
		RecipientKeyID: keyID, PackID: "system/crs-tuning", Version: "1.0.0", SealedSHA256: entry.SHA256})
	if err != nil || !bytes.Equal(opened, cek) {
		t.Fatalf("node cannot open the system pack key: %v", err)
	}
	// Receipt summary by official pack version (pack_receipts): node A applied
	// the tuning pack and crs-pl2; node B rejected the tuning pack itself and
	// carried crs-pl2 as set_rejected (not counted); a tenant pack never leaves.
	otherNode, _, _ := f.node(t, "sys-b")
	receipt := func(node uuid.UUID, result string, items string) {
		active := 1
		if result != "applied" {
			active = 0
		}
		f.replica(t, `INSERT INTO node_artifact_set_receipts(node_id,revision,set_sha256,result,active_revision,receipt,
			deployment_id,reported_at,recorded_at) VALUES($1,1,repeat('a',64),$2,$3,$4::jsonb,$5,now(),now())`,
			node, result, active, `{"items":`+items+`}`, uuid.New())
	}
	receipt(nodeID, "applied", `[{"artifact_id":"rule_pack/`+entry.SHA256+`","version":"1.0.0","sha256":"`+entry.SHA256+`","result":"applied"},
		{"artifact_id":"crs_profile/crs-pl2","version":"1.0.1","sha256":"`+strings.Repeat("b", 64)+`","result":"applied"},
		{"artifact_id":"rule_pack/`+strings.Repeat("c", 64)+`","version":"2.0.0","sha256":"`+strings.Repeat("c", 64)+`","result":"applied"}]`)
	receipt(otherNode, "rejected", `[{"artifact_id":"rule_pack/`+entry.SHA256+`","version":"1.0.0","sha256":"`+entry.SHA256+`","result":"rejected","reason":"install_rejected"},
		{"artifact_id":"crs_profile/crs-pl2","version":"1.0.1","sha256":"`+strings.Repeat("b", 64)+`","result":"rejected","reason":"set_rejected"}]`)
	summary, err := f.store.PackReceipts(ctx)
	want := []ruleintel.PackReceipt{{PackID: "system/crs-pl2", Version: "1.0.1", Applied: 1},
		{PackID: "system/crs-tuning", Version: "1.0.0", Applied: 1, Rejected: 1}}
	if err != nil || !reflect.DeepEqual(summary, want) {
		t.Fatalf("pack receipts = %+v, %v", summary, err)
	}
	report := ruleintel.Report{WAFExclusions: []ruleintel.Item{}, WAFRejections: []ruleintel.Item{}, WAFTighten: []ruleintel.Item{},
		WAFRuleStats: []ruleintel.RuleStat{}, AutodefenseSignatures: []ruleintel.Item{}, CCRuleStats: []ruleintel.RuleStat{},
		CCRuleTunes: []ruleintel.Item{}, FalsePositives: []ruleintel.Item{}, ScannerFingerprints: []ruleintel.Item{}, PackReceipts: summary}
	if err := ruleintel.Validate(report); err != nil {
		t.Fatalf("summary is not a valid report section: %v", err)
	}

	// Platform-level disable: no longer a node item, its wraps are dropped. The official free pack's
	// platform row (state enabled, migration 544) was written on arrival (openOfficialPack); the administrator sets it disabled.
	f.replica(t, `INSERT INTO rule_pack_enablements(id,level,level_object_id,pack_id,rule_id,state,updated_by_user_id,updated_at)
		VALUES($1,'platform',NULL,'system/crs-tuning',NULL,'disabled',$2,$3)
		ON CONFLICT (level,level_object_id,pack_id,rule_id) DO UPDATE SET state='disabled',updated_by_user_id=EXCLUDED.updated_by_user_id,
		updated_at=EXCLUDED.updated_at`, uuid.New(), f.admin, time.Now())
	if system, err = f.store.SystemRulePacks(ctx); err != nil || len(system) != 0 {
		t.Fatalf("disabled system pack still listed: %+v, %v", system, err)
	}
	if _, err := f.store.WrapNodeKeys(ctx, installationPrivate); err != nil {
		t.Fatal(err)
	}
	if got := f.count(`SELECT count(*) FROM node_rule_pack_keys WHERE node_id=$1`, nodeID); got != 0 {
		t.Fatalf("disabled system pack keeps %d wraps", got)
	}
}
