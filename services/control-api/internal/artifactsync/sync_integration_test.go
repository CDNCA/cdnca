//go:build integration

package artifactsync_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/entitlement/artifactcatalog"
	"github.com/cdnca/cdnca/libs/entitlement/ipintel"
	"github.com/cdnca/cdnca/libs/entitlement/rulecatalog"
	"github.com/cdnca/cdnca/services/control-api/internal/artifactsync"
	"github.com/cdnca/cdnca/services/control-api/internal/artifactsync/artifactsynctest"
	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	"github.com/cdnca/cdnca/services/control-api/internal/rulepackcontrol"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var installationID = uuid.MustParse("00000000-0000-4000-8000-0000000000a1")

// grants is the local lease stand-in (entitlementguard.Guard.ReadValidFeatures).
type grants struct{ features map[string]bool }

func (grants *grants) ReadValidFeatures(context.Context, pgx.Tx) (map[string]bool, error) {
	return maps.Clone(grants.features), nil
}

type republication struct {
	source               uuid.UUID
	previousSHA, nextSHA string
	previous, next       []byte
}

type recordingRepublisher struct {
	calls     []republication
	packs     [][]string
	crawlers  int
	defaultOn [][]rulepackcontrol.DefaultOnScope
}

func (recorder *recordingRepublisher) RepublishDefaultOnPackMountsTx(_ context.Context, _ pgx.Tx, _ uuid.UUID,
	scopes []rulepackcontrol.DefaultOnScope) error {
	recorder.defaultOn = append(recorder.defaultOn, slices.Clone(scopes))
	return nil
}

func (recorder *recordingRepublisher) RepublishTrustedCrawlersChangeTx(context.Context, pgx.Tx, uuid.UUID) ([]uuid.UUID, error) {
	recorder.crawlers++
	return nil, nil
}

func (recorder *recordingRepublisher) RepublishCRSProfilePackChangeTx(_ context.Context, _ pgx.Tx, _ uuid.UUID,
	previousSHA256 []string) ([]uuid.UUID, error) {
	recorder.packs = append(recorder.packs, slices.Clone(previousSHA256))
	return nil, nil
}

func (recorder *recordingRepublisher) RepublishCRSPackageChangeTx(_ context.Context, _ pgx.Tx, source uuid.UUID,
	previousSHA, nextSHA string, previous, next []byte) ([]uuid.UUID, error) {
	recorder.calls = append(recorder.calls, republication{source, previousSHA, nextSHA, previous, next})
	return nil, nil
}

type fixture struct {
	t        *testing.T
	pool     *pgxpool.Pool
	now      time.Time
	license  *artifactsynctest.License
	grants   *grants
	recorder *recordingRepublisher
	store    *artifactsync.Store
	syncer   *artifactsync.Syncer
	changed  int
	platform uuid.UUID
	admin    uuid.UUID
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	pool := databasetest.ClonedMigratedPool(t, nil)
	if pool == nil {
		t.Skip("TEST_DATABASE_TEMPLATE is not set (scripts/control-api-integration-sharded.sh)")
	}
	f := &fixture{t: t, pool: pool, now: time.Now().UTC().Truncate(time.Second), grants: &grants{features: map[string]bool{}},
		recorder: &recordingRepublisher{}, platform: uuid.New(), admin: uuid.New()}
	clock := func() time.Time { return f.now }
	f.license = artifactsynctest.NewLicense(t, installationID, clock)
	for _, statement := range []string{
		`INSERT INTO access_scopes(id,kind,tenant_id) VALUES('` + f.platform.String() + `','platform',NULL)`,
		`INSERT INTO users(id,username,display_name,password_hash) VALUES('` + f.admin.String() + `','artifact-admin','管理员','unused')`,
	} {
		if _, err := pool.Exec(t.Context(), statement); err != nil {
			t.Fatal(err)
		}
	}
	f.store = artifactsync.NewStore(pool, clock).WithFeatures(f.grants).WithCRSRepublisher(f.recorder)
	f.syncer = f.newSyncer()
	return f
}

func (f *fixture) newSyncer() *artifactsync.Syncer {
	f.t.Helper()
	syncer, err := artifactsync.NewSyncer(artifactsync.SyncerConfig{Client: f.license, Store: f.store, Trust: f.license.Trust(),
		InstallationID: installationID, PrivateKey: ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, 32)), ControlVersion: "1.0.35",
		Now: func() time.Time { return f.now }, OnChanged: func(context.Context) { f.changed++ },
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		f.t.Fatal(err)
	}
	return syncer
}

func (f *fixture) sync() {
	f.t.Helper()
	if err := f.syncer.SyncOnce(f.t.Context()); err != nil {
		f.t.Fatalf("SyncOnce: %v", err)
	}
}

func (f *fixture) local() map[string]uint64 {
	f.t.Helper()
	artifacts, err := f.store.LocalArtifacts(f.t.Context())
	if err != nil {
		f.t.Fatal(err)
	}
	result := map[string]uint64{}
	for _, artifact := range artifacts {
		result[artifact.ArtifactID] = artifact.Revision
	}
	return result
}

func (f *fixture) count(query string, args ...any) int {
	f.t.Helper()
	var count int
	if err := f.pool.QueryRow(f.t.Context(), query, args...).Scan(&count); err != nil {
		f.t.Fatalf("%s: %v", query, err)
	}
	return count
}

func (f *fixture) ruleStatus(systemKey string) string {
	f.t.Helper()
	var status string
	err := f.pool.QueryRow(f.t.Context(), `SELECT status FROM security_system_rules WHERE system_key=$1`, systemKey).Scan(&status)
	if errors.Is(err, pgx.ErrNoRows) {
		return ""
	}
	if err != nil {
		f.t.Fatal(err)
	}
	return status
}

func (f *fixture) audits(action, result string) int {
	f.t.Helper()
	return f.count(`SELECT count(*) FROM audit_events WHERE action=$1 AND result=$2`, action, result)
}

func (f *fixture) lastErrorCode() string {
	f.t.Helper()
	var code string
	if err := f.pool.QueryRow(f.t.Context(), `SELECT last_error_code FROM artifact_catalog_state`).Scan(&code); err != nil {
		f.t.Fatal(err)
	}
	return code
}

func (f *fixture) head() uint64 {
	f.t.Helper()
	head, err := f.store.Head(f.t.Context())
	if err != nil {
		f.t.Fatal(err)
	}
	if head == nil {
		return 0
	}
	return head.ScopeRevision
}

func buildIPIntel(t *testing.T, revision uint64, carrier uint64) (artifactcatalog.Entry, []byte) {
	t.Helper()
	generated := time.Date(2026, 10, 17, 0, 0, 0, 0, time.UTC)
	artifact, err := ipintel.Build(ipintel.BuildInput{Revision: revision, BuildID: fmt.Sprintf("ipintel-base-%04d", revision),
		GeneratedAt: generated, DataUpdatedAt: generated.Add(-time.Hour), StaleAfter: generated.Add(30 * 24 * time.Hour),
		Sources: []ipintel.Source{{ID: "fixture", Name: "fixture", URL: "https://example.test", License: "CC0-1.0", Ref: "1", Role: "test"}},
		Facts:   []ipintel.Fact{{Prefix: netip.MustParsePrefix("1.0.0.0/24"), Tags: carrier, Country: "CN"}}})
	if err != nil {
		t.Fatal(err)
	}
	release, err := ipintel.NewRelease(artifact)
	if err != nil {
		t.Fatal(err)
	}
	entry, err := artifactcatalog.IPIntelEntry(release)
	if err != nil {
		t.Fatal(err)
	}
	return entry, artifact.Bytes
}

func flip(_ artifactcatalog.Entry, content []byte) []byte {
	content[len(content)/2] ^= 0x01
	return content
}

const (
	paidFeature = "module.rules.pro"
	freeRule    = "cc_filter:1"
	paidRule    = "cc_filter:10000"
	onDemand    = "cc_filter:10001"
)

// TestArtifactSyncLifecycle drives the syncer against an in-memory license
// service on the real schema (ADR 0007 §4.1, §5.4).
func TestArtifactSyncLifecycle(t *testing.T) {
	f := newFixture(t)
	ctx := t.Context()
	seed := rulecatalog.CurrentSeed()
	crsItem := artifactsynctest.SystemRule(t, seed, artifactsync.CRSRuleSystemKey)
	f.license.PublishRule(artifactsynctest.SystemRule(t, seed, freeRule), "", true)
	f.license.PublishRule(artifactsynctest.SystemRule(t, seed, paidRule), paidFeature, true)
	f.license.PublishRule(artifactsynctest.SystemRule(t, seed, onDemand), "", false)
	crs := f.license.PublishRule(crsItem, "", true)
	ipEntry, ipBytes := buildIPIntel(t, 3, ipintel.TagCNTelecom)
	f.license.Publish(ipEntry, ipBytes)
	freeID, paidID, onDemandID := "ruleset/"+freeRule, "ruleset/"+paidRule, "ruleset/"+onDemand

	// 1. Empty control plane: the whole catalog is available, only free
	// resident entries are downloaded; downloading enables nothing.
	f.sync()
	if got := f.count(`SELECT count(*) FROM artifact_catalog_entries WHERE status='active'`); got != 5 {
		t.Fatalf("available entries = %d", got)
	}
	want := map[string]uint64{freeID: 2, crs.ArtifactID: crs.Revision, artifactcatalog.IPIntelBaseID: 3}
	if got := f.local(); !maps.Equal(got, want) {
		t.Fatalf("downloaded after first sync = %v, want %v", got, want)
	}
	if slices.Contains(f.license.Fetched, paidID) || slices.Contains(f.license.Fetched, onDemandID) {
		t.Fatalf("fetched %v", f.license.Fetched)
	}
	if f.ruleStatus(freeRule) != "active" || f.ruleStatus(artifactsync.CRSRuleSystemKey) != "active" ||
		f.ruleStatus(paidRule) != "" || f.ruleStatus(onDemand) != "" {
		t.Fatal("materialized system rules do not follow the downloads")
	}
	if len(f.recorder.calls) != 1 || f.recorder.calls[0].previousSHA != "" || f.recorder.calls[0].nextSHA != crs.SHA256 ||
		f.recorder.calls[0].source.String() != f.license.Last().Envelope.DeliveryID {
		t.Fatalf("CRS republication calls = %+v", f.recorder.calls)
	}
	if f.count(`SELECT count(*) FROM artifact_enablement_overrides`) != 0 || f.changed != 1 ||
		f.audits("plugin.artifact_catalog.apply", "success") != 1 || f.audits("plugin.artifact.download", "success") != 3 {
		t.Fatalf("overrides/changed/audits after first sync: changed=%d", f.changed)
	}
	library, err := f.store.Current(ctx, artifactcatalog.IPIntelBaseID)
	if err != nil || library == nil || library.Revision != 3 || library.SHA256 != ipEntry.SHA256 || library.Size != int64(len(ipBytes)) ||
		library.MediaType != artifactcatalog.MediaTypeIPIntel || library.RequiresCapability == nil ||
		*library.RequiresCapability != (artifactcatalog.Capability{Name: "IP_INTEL", MinVersion: 2}) || library.Version != "ipintel-base-0003" {
		t.Fatalf("Current(ipintel/base) = %+v, %v", library, err)
	}
	if object, err := f.store.Object(ctx, library.SHA256); err != nil || !bytes.Equal(object, ipBytes) {
		t.Fatalf("Object = %d bytes, %v", len(object), err)
	}
	if _, err := f.store.Object(ctx, string(bytes.Repeat([]byte{'e'}, 64))); !errors.Is(err, artifactsync.ErrNotFound) {
		t.Fatalf("missing object error = %v", err)
	}

	// 2. The license service lists a paid entry the local lease lacks: it is
	// not returned, not downloadable, and the refusal is audited.
	if current, err := f.store.Current(ctx, paidID); err != nil || current != nil {
		t.Fatalf("Current(paid) = %+v, %v", current, err)
	}
	request := artifactsync.DownloadRequest{ActorUserID: f.admin, ScopeID: f.platform, SourceIP: "203.0.113.9", RequestID: "req-paid"}
	request.ArtifactID = paidID
	if err := f.store.RequestDownload(ctx, request); !errors.Is(err, artifactsync.ErrNotEntitled) {
		t.Fatalf("paid download request error = %v", err)
	}
	if f.count(`SELECT count(*) FROM audit_events WHERE action='plugin.artifact.download_request' AND result='failure'
		AND actor_user_id=$1 AND payload->>'reason'='entitlement_feature_denied' AND payload->>'ip'='203.0.113.9'`, f.admin) != 1 {
		t.Fatal("refused download request not audited")
	}
	// An on-demand free entry is fetched after an administrator asks for it.
	request.ArtifactID, request.RequestID = onDemandID, "req-free"
	if err := f.store.RequestDownload(ctx, request); err != nil {
		t.Fatal(err)
	}
	f.sync()
	if got := f.local(); got[onDemandID] != 2 || f.ruleStatus(onDemand) != "active" ||
		f.audits("plugin.artifact.download_request", "success") != 1 {
		t.Fatalf("after download request: %v", got)
	}

	// 3. The lease gains the feature: the paid resident entry downloads with
	// no new delivery. It loses it again: not returned, rule withdrawn (kept).
	f.grants.features[paidFeature] = true
	f.sync()
	if got := f.local(); got[paidID] != 2 || f.ruleStatus(paidRule) != "active" {
		t.Fatalf("after grant: %v, rule %q", got, f.ruleStatus(paidRule))
	}
	delete(f.grants.features, paidFeature)
	f.sync()
	if got := f.local(); got[paidID] != 0 || f.ruleStatus(paidRule) != "withdrawn" {
		t.Fatalf("after revoke: %v, rule %q", got, f.ruleStatus(paidRule))
	}
	fetchedPaid := len(slices.DeleteFunc(slices.Clone(f.license.Fetched), func(id string) bool { return id != paidID }))
	f.grants.features[paidFeature] = true
	f.sync()
	if again := len(slices.DeleteFunc(slices.Clone(f.license.Fetched), func(id string) bool { return id != paidID })); again != fetchedPaid ||
		f.ruleStatus(paidRule) != "active" {
		t.Fatalf("re-grant fetched again (%d -> %d) or rule %q", fetchedPaid, again, f.ruleStatus(paidRule))
	}

	// 4. A tampered delivery (catalog edited after signing, or a forged
	// signature) is rejected and audited; head and downloads stay.
	headBefore, localBefore := f.head(), f.local()
	newer := artifactsynctest.SystemRule(t, seed, freeRule)
	newer.Revision++
	f.license.PublishRule(newer, "", true)
	for code, tamper := range map[string]func(*artifactcatalog.Signed){
		artifactsync.CodeDigestMismatch: func(signed *artifactcatalog.Signed) { signed.Catalog.Entries[0].Version = "999" },
		artifactsync.CodeInvalidSignature: func(signed *artifactcatalog.Signed) {
			signature, _ := base64.RawURLEncoding.DecodeString(signed.Signature)
			signature[0] ^= 0x01
			signed.Signature = base64.RawURLEncoding.EncodeToString(signature)
		},
	} {
		f.license.TamperDelivery = tamper
		f.sync()
		if f.head() != headBefore || !maps.Equal(f.local(), localBefore) || f.lastErrorCode() != code {
			t.Fatalf("%s: head %d -> %d, local %v, code %q", code, headBefore, f.head(), f.local(), f.lastErrorCode())
		}
	}
	if f.audits("plugin.artifact_catalog.reject", "failure") != 2 {
		t.Fatal("rejected deliveries not audited")
	}
	f.license.TamperDelivery = nil
	f.sync()
	if f.head() != headBefore+1 || f.local()[freeID] != 3 {
		t.Fatalf("untampered delivery: head %d, local %v", f.head(), f.local())
	}

	// 5. Bytes that do not match the signed entry: rejected and audited, the
	// previous download (LKG) and its system rule stay; not refetched within
	// the retry window; fetched again after it.
	newer.Revision++
	f.license.PublishRule(newer, "", true)
	nextIP, nextIPBytes := buildIPIntel(t, 4, ipintel.TagCNMobile)
	f.license.Publish(nextIP, nextIPBytes)
	f.license.TamperContent = flip
	f.sync()
	if got := f.local(); got[freeID] != 3 || got[artifactcatalog.IPIntelBaseID] != 3 || f.ruleStatus(freeRule) != "active" {
		t.Fatalf("after tampered bytes: %v", got)
	}
	if f.count(`SELECT count(*) FROM local_artifacts WHERE rejected_revision IS NOT NULL AND last_error_code=$1`,
		artifactsync.CodeContentMismatch) != 2 || f.audits("plugin.artifact.download_reject", "failure") != 2 {
		t.Fatal("rejected downloads not recorded")
	}
	f.license.TamperContent = nil
	fetched := len(f.license.Fetched)
	f.sync()
	if len(f.license.Fetched) != fetched {
		t.Fatalf("rejected revisions refetched within the retry window: %v", f.license.Fetched[fetched:])
	}
	f.now = f.now.Add(2 * time.Hour)
	f.sync()
	if got := f.local(); got[freeID] != 4 || got[artifactcatalog.IPIntelBaseID] != 4 {
		t.Fatalf("after the retry window: %v", got)
	}

	// 6. A new CRS rule package republishes; the same package again does not.
	calls := len(f.recorder.calls)
	nextCRS := f.license.PublishRule(artifactsynctest.NextCRSRevision(t, crsItem, "REQUEST-942-APPLICATION-ATTACK-SQLI.conf"), "", true)
	f.sync()
	if len(f.recorder.calls) != calls+1 || f.recorder.calls[calls].previousSHA != crs.SHA256 ||
		f.recorder.calls[calls].nextSHA != nextCRS.SHA256 || len(f.recorder.calls[calls].previous) == 0 {
		t.Fatalf("CRS package change calls = %+v", f.recorder.calls[calls:])
	}
	f.sync()
	if len(f.recorder.calls) != calls+1 {
		t.Fatal("unchanged CRS package republished")
	}

	// 7. A delivery listing an older revision of an entry keeps the stored one.
	older := artifactsynctest.SystemRule(t, seed, onDemand)
	older.Revision = 1
	f.license.PublishRule(older, "", false)
	f.sync()
	if f.lastErrorCode() != artifactsync.CodeEntryOutOfOrder ||
		f.count(`SELECT count(*) FROM artifact_catalog_entries WHERE artifact_id=$1 AND revision=2`, onDemandID) != 1 ||
		f.local()[onDemandID] != 2 {
		t.Fatalf("older entry revision: code %q, local %v", f.lastErrorCode(), f.local())
	}

	// 8. An entry the license service no longer lists is withdrawn: not
	// returned, its system rule frozen as withdrawn (never deleted).
	f.license.Withdraw(onDemandID)
	f.sync()
	if _, ok := f.local()[onDemandID]; ok || f.ruleStatus(onDemand) != "withdrawn" ||
		f.count(`SELECT count(*) FROM artifact_catalog_entries WHERE artifact_id=$1 AND status='withdrawn'`, onDemandID) != 1 {
		t.Fatalf("withdrawn entry: local %v, rule %q", f.local(), f.ruleStatus(onDemand))
	}

	// 9. Outage: the round fails, everything applied stays. A restarted
	// syncer resumes from the stored head (not modified).
	localBefore = f.local()
	f.license.ResolveErr = errors.New("license service unreachable")
	if err := f.syncer.SyncOnce(ctx); err == nil || f.lastErrorCode() != artifactsync.CodeResolveFailed || !maps.Equal(f.local(), localBefore) {
		t.Fatalf("outage: %v, code %q", err, f.lastErrorCode())
	}
	f.license.ResolveErr = nil
	headBefore = f.head()
	f.syncer = f.newSyncer()
	f.sync()
	if f.head() != headBefore || f.lastErrorCode() != "" {
		t.Fatalf("restart: head %d -> %d, code %q", headBefore, f.head(), f.lastErrorCode())
	}

	// 10. Objects are immutable and downloads only move forward.
	if _, err := f.pool.Exec(ctx, `UPDATE artifact_objects SET stored_at=now()`); err == nil {
		t.Fatal("artifact object updated")
	}
	if _, err := f.pool.Exec(ctx, `UPDATE local_artifacts SET current_revision=1 WHERE artifact_id=$1`, freeID); err == nil {
		t.Fatal("local artifact moved backwards")
	}
}
