//go:build integration

package artifactsync_test

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"io"
	"log/slog"
	"time"

	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"github.com/jackc/pgx/v5"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/libs/entitlement/artifactcatalog"
	"github.com/cdnca/cdnca/libs/rulepack"
	"github.com/cdnca/cdnca/services/control-api/internal/artifactsync"
	"github.com/google/uuid"
)

// A pack whose rule bodies carry a marker that only the plaintext has.
const sealedMarker = "pa14-secret-signature-xyz"

func sealedPackSource(version string) []byte {
	return []byte(`{"schema":"cdnca.rule-pack/v1","pack_id":"dev/acme/secret","version":"` + version + `",
		"layer":"developer","engine":"waf_v2","engine_min_version":1,"name":"Acme secret","description":"d",
		"params_schema":{},"exports":["r1"],"defaults":{},
		"rules":[{"id":"r1","name":"block secret","waf":{"match":{"path":{"kind":"prefix","value":"/` + sealedMarker + `"}},
		"action":"block","flow":"stop"}}]}`)
}

func x25519(t *testing.T) ([]byte, []byte) {
	t.Helper()
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key.Bytes(), key.PublicKey().Bytes()
}

// sealFor does what the license service does for one installation.
func sealFor(t *testing.T, source, cek, installationPublic []byte) (artifactcatalog.Entry, []byte) {
	t.Helper()
	compiled, err := rulepack.Compile(source)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := rulepack.Seal(compiled.Canonical, cek, nil)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(sealed)
	digest := hex.EncodeToString(sum[:])
	pack := compiled.Pack
	wrapped, err := rulepack.WrapKey(installationPublic, cek, rulepack.WrapContext{Purpose: rulepack.WrapPurposeInstallation,
		RecipientKeyID: rulepack.X25519KeyID(installationPublic), PackID: pack.PackID, Version: pack.Version, SealedSHA256: digest})
	if err != nil {
		t.Fatal(err)
	}
	entry := artifactcatalog.Entry{ArtifactID: artifactcatalog.RulePackArtifactID(pack.PackID), Kind: artifactcatalog.KindRulePack,
		MediaType: artifactcatalog.MediaTypeRulePack, Encryption: artifactcatalog.EncryptionInstallWrapped, Resident: true,
		Revision: 1, Version: pack.Version, SHA256: digest, Size: int64(len(sealed)), WrappedKey: wrapped}
	if err := artifactcatalog.ValidateEntry(entry); err != nil {
		t.Fatal(err)
	}
	return entry, sealed
}

func (f *fixture) syncerWithKey(key []byte) *artifactsync.Syncer {
	f.t.Helper()
	syncer, err := artifactsync.NewSyncer(artifactsync.SyncerConfig{Client: f.license, Store: f.store, Trust: f.license.Trust(),
		InstallationID: installationID, PrivateKey: testInstallationKey(), EncryptionKey: key, ControlVersion: "1.0.35",
		Now: f.syncerNow(), Logger: discardLogger()})
	if err != nil {
		f.t.Fatal(err)
	}
	return syncer
}

// TestSealedRulePackSync: the control plane stores the sealed bytes of an
// encrypted pack only when its wrapped key opens with the installation key,
// never decrypts it, lists only the manifest, and wraps the content key to
// each active node key of a node whose site mounts it.
func TestSealedRulePackSync(t *testing.T) {
	f := newFixture(t)
	ctx := t.Context()
	installationPrivate, installationPublic := x25519(t)
	otherPrivate, _ := x25519(t)
	cek := make([]byte, rulepack.CEKSize)
	if _, err := rand.Read(cek); err != nil {
		t.Fatal(err)
	}
	entry, sealed := sealFor(t, sealedPackSource("1.0.0"), cek, installationPublic)
	f.license.Publish(entry, sealed)

	// Another installation's key (a copied pack): rejected, nothing stored.
	other := f.syncerWithKey(otherPrivate)
	if err := other.SyncOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if got := f.count(`SELECT count(*) FROM rule_pack_artifacts`); got != 0 {
		t.Fatalf("pack stored with a key that does not open it: %d", got)
	}
	if f.audits("rule.pack.decrypt_reject", "failure") != 1 {
		t.Fatal("rule.pack.decrypt_reject not audited")
	}
	var code string
	if err := f.pool.QueryRow(ctx, `SELECT last_error_code FROM local_artifacts WHERE artifact_id=$1`, entry.ArtifactID).
		Scan(&code); err != nil || code != artifactsync.CodeDecryptRejected {
		t.Fatalf("last_error_code = %q, %v", code, err)
	}
	// No encryption key configured: rejected as well (after the retry window).
	f.now = f.now.Add(2 * time.Hour)
	if err := f.syncerWithKey(nil).SyncOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if got := f.count(`SELECT count(*) FROM rule_pack_artifacts`); got != 0 {
		t.Fatalf("pack stored without an encryption key: %d", got)
	}

	// The right key: stored sealed, materialized as a catalog version.
	f.now = f.now.Add(2 * time.Hour)
	if err := f.syncerWithKey(installationPrivate).SyncOnce(ctx); err != nil {
		t.Fatal(err)
	}
	var stored []byte
	var isSealed bool
	var wrapped, source string
	var creator *uuid.UUID
	if err := f.pool.QueryRow(ctx, `SELECT content,sealed,wrapped_key,source,created_by_user_id FROM rule_pack_artifacts
		WHERE pack_id='dev/acme/secret' AND version='1.0.0'`).Scan(&stored, &isSealed, &wrapped, &source, &creator); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(stored, sealed) || !isSealed || wrapped != entry.WrappedKey || source != "catalog" || creator != nil {
		t.Fatalf("stored artifact sealed=%v source=%s creator=%v", isSealed, source, creator)
	}
	var current *string
	if err := f.pool.QueryRow(ctx, `SELECT current_version FROM rule_packs WHERE pack_id='dev/acme/secret'`).Scan(&current); err != nil ||
		current == nil || *current != "1.0.0" {
		t.Fatalf("current_version = %v, %v", current, err)
	}
	if f.audits("rule.pack.version.create", "success") != 1 {
		t.Fatal("catalog version not audited")
	}
	// The marker only exists in plaintext: nowhere in the control database.
	if !bytes.Contains(sealedPackSource("1.0.0"), []byte(sealedMarker)) {
		t.Fatal("fixture marker missing")
	}
	if got := f.count(`SELECT count(*) FROM (
		SELECT content::text AS v FROM artifact_objects UNION ALL
		SELECT encode(content,'escape') FROM artifact_objects UNION ALL
		SELECT encode(content,'escape') FROM rule_pack_artifacts UNION ALL
		SELECT payload::text FROM audit_events) all_values WHERE v LIKE '%' || $1 || '%'`, sealedMarker); got != 0 {
		t.Fatalf("plaintext found in the control database (%d rows)", got)
	}

	// Node wraps: only nodes with an active key, only mounted sealed objects.
	nodeA, nodeAKey, nodeAPrivate := f.node(t, "a")
	_, _, _ = f.node(t, "b")
	added, err := f.store.WrapNodeKeys(ctx, installationPrivate)
	if err != nil || added != 0 {
		t.Fatalf("wraps before any mount = %d, %v", added, err)
	}
	f.mount(t, "dev/acme/secret", "1.0.0")
	if added, err = f.store.WrapNodeKeys(ctx, installationPrivate); err != nil || added != 2 {
		t.Fatalf("wraps = %d, %v", added, err)
	}
	if added, err = f.store.WrapNodeKeys(ctx, installationPrivate); err != nil || added != 0 {
		t.Fatalf("second round wraps = %d, %v (must be idempotent)", added, err)
	}
	// F2: the mounted pack is a node artifact set input (sealed bytes).
	mounted, err := f.store.MountedRulePacks(ctx)
	if err != nil || len(mounted) != 1 || !mounted[0].Sealed || mounted[0].SHA256 != entry.SHA256 ||
		!bytes.Equal(mounted[0].Content, sealed) || mounted[0].PackID != "dev/acme/secret" {
		t.Fatalf("mounted packs = %+v, %v", mounted, err)
	}
	if f.audits("rule.pack.key_wrap", "success") != 2 {
		t.Fatal("rule.pack.key_wrap not audited per node")
	}
	wraps, err := f.store.NodeKeyWraps(ctx, nodeA)
	if err != nil || len(wraps) != 1 || wraps[0].RecipientKeyID != nodeAKey || wraps[0].SealedSHA256 != entry.SHA256 {
		t.Fatalf("node A wraps = %+v, %v", wraps, err)
	}
	context := rulepack.WrapContext{Purpose: rulepack.WrapPurposeNode, RecipientKeyID: nodeAKey, PackID: "dev/acme/secret",
		Version: "1.0.0", SealedSHA256: entry.SHA256}
	opened, err := rulepack.UnwrapKey(nodeAPrivate, wraps[0].WrappedKey, context)
	if err != nil || !bytes.Equal(opened, cek) {
		t.Fatalf("node A cannot open its key: %v", err)
	}
	pack, err := rulepack.Open(sealed, entry.SHA256, opened)
	if err != nil || len(pack.Pack.Rules) != 1 {
		t.Fatalf("node A opens the pack: %v", err)
	}
	// Node B's private key does not open node A's wrap.
	if _, err := rulepack.UnwrapKey(otherPrivate, wraps[0].WrappedKey, context); err == nil {
		t.Fatal("another key opened node A's wrap")
	}
	// A retired node key drops its wraps.
	if _, err := f.pool.Exec(ctx, `UPDATE node_artifact_encryption_keys SET status='retired',deactivated_at=now(),
		deactivation_reason='test' WHERE id=$1`, nodeAKey); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.WrapNodeKeys(ctx, installationPrivate); err != nil {
		t.Fatal(err)
	}
	if got := f.count(`SELECT count(*) FROM node_rule_pack_keys WHERE node_id=$1`, nodeA); got != 0 {
		t.Fatalf("retired key keeps %d wraps", got)
	}
	if !strings.HasPrefix(entry.ArtifactID, "rule_pack/") {
		t.Fatal(entry.ArtifactID)
	}
}

func testInstallationKey() ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, 32))
}

func discardLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func (f *fixture) syncerNow() func() time.Time { return func() time.Time { return f.now } }

// replica inserts rows without their foreign key chain (enrollment,
// identity authorization, site publication) this test does not exercise.
func (f *fixture) replica(t *testing.T, query string, args ...any) {
	t.Helper()
	if err := pgx.BeginFunc(t.Context(), f.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(t.Context(), `SET LOCAL session_replication_role = replica`); err != nil {
			return err
		}
		_, err := tx.Exec(t.Context(), query, args...)
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

// node seeds a node with an active artifact encryption key.
func (f *fixture) node(t *testing.T, name string) (uuid.UUID, string, []byte) {
	t.Helper()
	private, public := x25519(t)
	nodeID := uuid.New()
	keyID := rulepack.X25519KeyID(public)
	digest := sha256.Sum256(public)
	f.replica(t, `INSERT INTO nodes(id,scope_id,name,admin_state,created_by_user_id,display_id)
		VALUES($1,$2,$3,'active',$4,(SELECT coalesce(max(display_id),0)+1 FROM nodes))`, nodeID, f.platform, "pa14-"+name, f.admin)
	f.replica(t, `INSERT INTO node_artifact_encryption_keys(id,node_id,authorization_id,public_key,public_key_sha256,status,
		created_at,activated_at) VALUES($1,$2,$3,$4,$5,'active',now(),now())`, keyID, nodeID, uuid.New(), public, digest[:])
	return nodeID, keyID, private
}

// mount records that a published site mounts pack@version.
func (f *fixture) mount(t *testing.T, packID, version string) {
	t.Helper()
	siteID := uuid.New()
	f.replica(t, `INSERT INTO site_security_mounts(site_id,revision,security,resolved_sha256,published_by_user_id,published_at)
		VALUES($1,1,'{}',$2,$3,now())`, siteID, strings.Repeat("0", 64), f.admin)
	f.replica(t, `INSERT INTO rule_pack_site_mount_artifacts(site_id,pack_id,version) VALUES($1,$2,$3)`, siteID, packID, version)
}
