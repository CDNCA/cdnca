//go:build integration

package rulepackcontrol

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/libs/rulepack"
	"github.com/jackc/pgx/v5"
)

// TestSealedCatalogPackIsManagedByManifest (PA-14): a sealed catalog pack
// (as artifactsync stores it) is listed with metadata and params only,
// enabled and published like any pack; neither the page nor the published
// security document carries its rules, and the node recompiles the same
// resolved_sha256 once it opens the pack.
func TestSealedCatalogPackIsManagedByManifest(t *testing.T) {
	w := newWorld(t)
	ctx := t.Context()
	plain := mustRead(t, "packs/system-sqli.json")
	compiled, err := rulepack.Compile(plain)
	if err != nil {
		t.Fatal(err)
	}
	cek := make([]byte, rulepack.CEKSize)
	if _, err := rand.Read(cek); err != nil {
		t.Fatal(err)
	}
	sealed, err := rulepack.Seal(compiled.Canonical, cek, nil)
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := rulepack.OpenManifest(sealed, digest(sealed))
	if err != nil {
		t.Fatal(err)
	}
	err = pgx.BeginFunc(ctx, w.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO rule_packs(pack_id,layer,current_version,update_policy,created_at,updated_at)
			VALUES('system/sqli-basic','system','1.0.0','auto',now(),now())`); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO rule_pack_artifacts(pack_id,version,engine,engine_min_version,name,sha256,size_bytes,
			content,source,state,downloaded_at,created_at,sealed,wrapped_key) VALUES('system/sqli-basic','1.0.0','waf_v2',1,$1,$2,$3,$4,
			'catalog','downloaded',now(),now(),true,$5)`, manifest.Pack.Name, manifest.SHA256, len(sealed), sealed, strings.Repeat("A", 107))
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	level, object := platformLevel()
	if err := w.put(t, w.platform, with(OverrideInput{Level: level, LevelObjectID: object}, "system/sqli-basic",
		rulepack.StateEnabled, false)); err != nil {
		t.Fatal(err)
	}
	view, err := w.service.View(ctx, w.tenantA, LevelInput{Level: rulepack.LevelSite, ObjectID: &w.siteA1})
	if err != nil {
		t.Fatal(err)
	}
	page, _ := json.Marshal(view)
	if !bytes.Contains(page, []byte("参数注入")) || !bytes.Contains(page, []byte(`"action"`)) {
		t.Fatalf("page lacks the manifest (export names / params): %s", page)
	}
	if bytes.Contains(page, []byte("detect")) || bytes.Contains(page, []byte("wp-admin")) {
		t.Fatalf("page shows sealed rules: %s", page)
	}
	published, err := w.service.PublishSite(ctx, w.tenantA, w.siteA1)
	if err != nil || mountIDs(published) != "system/sqli-basic" {
		t.Fatalf("publish = %q, %v", mountIDs(published), err)
	}
	document, _ := json.Marshal(published.Resolution.Security)
	if bytes.Contains(document, []byte("detect")) || bytes.Contains(document, []byte("wp-admin")) {
		t.Fatalf("security document carries sealed rules: %s", document)
	}
	// The node: opens the pack with its key and reproduces the digest.
	opened, err := rulepack.Open(sealed, manifest.SHA256, cek)
	if err != nil {
		t.Fatal(err)
	}
	rules, err := rulepack.Verify(*published.Resolution.Security, map[string]*rulepack.CompiledPack{manifest.SHA256: opened})
	if err != nil || len(rules) != 2 {
		t.Fatalf("node verify = %d rules, %v", len(rules), err)
	}
}

func digest(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
