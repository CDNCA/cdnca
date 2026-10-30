package artifactcatalog

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/entitlement/ipintel"
	"github.com/cdnca/cdnca/libs/entitlement/rulecatalog"
)

type testSigner struct {
	id      string
	private ed25519.PrivateKey
}

func (signer testSigner) KeyID() string { return signer.id }
func (signer testSigner) Sign(_ context.Context, payload []byte) ([]byte, error) {
	return ed25519.Sign(signer.private, payload), nil
}

type testVerifier struct{ public map[string]ed25519.PublicKey }

func (verifier testVerifier) VerifyDetached(keyID string, payload, signature []byte, _, _ time.Time) error {
	key, ok := verifier.public[keyID]
	if !ok {
		return errors.New("unknown key")
	}
	if !ed25519.Verify(key, payload, signature) {
		return errors.New("bad signature")
	}
	return nil
}

const (
	testInstallationID = "00000000-0000-4000-8000-0000000000a1"
	testDeliveryID     = "00000000-0000-4000-8000-0000000000b1"
	testKeyID          = "artifact-catalog-test-1"
)

func testKey(seed byte) ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, ed25519.SeedSize))
}

func testEnvelope() Envelope {
	return Envelope{DeliveryID: testDeliveryID, InstallationID: testInstallationID, ScopeRevision: 1,
		SignedAt: 1_900_000_000, ValidFrom: 1_899_999_940, ExpiresAt: 1_900_604_800}
}

// seedEntries builds ruleset entries from the shared rule seed plus the CRS
// rule text entry, exactly as the license service does.
func seedEntries(t *testing.T) ([]Entry, map[string][]byte) {
	t.Helper()
	entries := []Entry{}
	content := map[string][]byte{}
	for _, item := range rulecatalog.CurrentSeed() {
		entry, encoded, err := RulesetEntry(item, "", true)
		if err != nil {
			t.Fatalf("RulesetEntry(%s): %v", item.SystemKey, err)
		}
		entries = append(entries, entry)
		content[entry.SHA256] = encoded
	}
	SortEntries(entries)
	return entries, content
}

func testCatalog(t *testing.T) Catalog {
	entries, _ := seedEntries(t)
	return Catalog{Schema: CatalogSchema, Entries: entries}
}

func TestRulesetEntriesRoundTripAndKinds(t *testing.T) {
	entries, content := seedEntries(t)
	if _, _, err := CanonicalCatalog(Catalog{Schema: CatalogSchema, Entries: entries}); err != nil {
		t.Fatalf("seed catalog invalid: %v", err)
	}
	kinds := map[string]int{}
	for _, entry := range entries {
		kinds[entry.Kind]++
		if !entry.Resident || entry.Encryption != EncryptionNone || entry.RequiresFeature != "" {
			t.Fatalf("seed entry %s = %+v", entry.ArtifactID, entry)
		}
		item, err := DecodeRulesetItem(entry, content[entry.SHA256])
		if err != nil {
			t.Fatalf("DecodeRulesetItem(%s): %v", entry.ArtifactID, err)
		}
		if RulesetArtifactID(item) != entry.ArtifactID || item.Revision != entry.Revision {
			t.Fatalf("decoded %s = %s rev %d", entry.ArtifactID, item.SystemKey, item.Revision)
		}
	}
	if kinds[KindCRSProfile] != 1 || kinds[KindRuleset] != len(entries)-1 {
		t.Fatalf("kinds = %v", kinds)
	}
	crs := entryByID(entries, "crs_profile/crs_rules")
	if crs == nil || crs.MediaType != MediaTypeCRSProfile || crs.LicenseSPDX != "Apache-2.0" {
		t.Fatalf("crs entry = %+v", crs)
	}
	ruleset := entryByID(entries, "ruleset/cc_rule:6")
	if ruleset == nil || ruleset.MediaType != MediaTypeRuleset || ruleset.Version != "1" {
		t.Fatalf("ruleset entry = %+v", ruleset)
	}
	// Bytes that are not exactly the entry are rejected.
	tampered := append([]byte(nil), content[ruleset.SHA256]...)
	tampered[len(tampered)-2] ^= 1
	if _, err := DecodeRulesetItem(*ruleset, tampered); !errors.Is(err, ErrContentMismatch) {
		t.Fatalf("tampered ruleset bytes error = %v", err)
	}
	other := *entryByID(entries, "ruleset/cc_rule:1")
	if _, err := DecodeRulesetItem(other, content[ruleset.SHA256]); !errors.Is(err, ErrContentMismatch) {
		t.Fatalf("bytes of another entry error = %v", err)
	}
	gated, _, err := RulesetEntry(rulecatalog.CurrentSeed()[0], "pack.cc.pro", false)
	if err != nil || gated.RequiresFeature != "pack.cc.pro" || gated.Resident {
		t.Fatalf("gated entry = %+v, %v", gated, err)
	}
	if _, _, err := RulesetEntry(rulecatalog.CurrentSeed()[0], "Bad Feature", true); err == nil {
		t.Fatal("invalid feature code accepted")
	}
}

func TestCatalogValidationRejectsMalformedEntries(t *testing.T) {
	mutations := map[string]func(*Catalog){
		"unsorted":       func(c *Catalog) { c.Entries[0], c.Entries[1] = c.Entries[1], c.Entries[0] },
		"duplicate":      func(c *Catalog) { c.Entries[1] = c.Entries[0] },
		"bad id":         func(c *Catalog) { c.Entries[0].ArtifactID = "ruleset" },
		"kind prefix":    func(c *Catalog) { c.Entries[0].Kind = KindIPIntel },
		"media type":     func(c *Catalog) { c.Entries[0].MediaType = "application/json" },
		"revision zero":  func(c *Catalog) { c.Entries[0].Revision = 0 },
		"sha256":         func(c *Catalog) { c.Entries[0].SHA256 = "ABC" },
		"size":           func(c *Catalog) { c.Entries[0].Size = 0 },
		"encryption":     func(c *Catalog) { c.Entries[0].Encryption = "rot13" },
		"wrapped key":    func(c *Catalog) { c.Entries[0].WrappedKey = "AAAA" },
		"feature":        func(c *Catalog) { c.Entries[0].RequiresFeature = "Pack X" },
		"capability":     func(c *Catalog) { c.Entries[0].RequiresCapability = &Capability{Name: "ip intel", MinVersion: 1} },
		"capability ver": func(c *Catalog) { c.Entries[0].RequiresCapability = &Capability{Name: "IP_INTEL", MinVersion: 0} },
		"self supersede": func(c *Catalog) { c.Entries[0].Supersedes = c.Entries[0].ArtifactID },
		"spdx":           func(c *Catalog) { c.Entries[0].LicenseSPDX = "not a license" },
		"nil entries":    func(c *Catalog) { c.Entries = nil },
		"schema":         func(c *Catalog) { c.Schema = "x" },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			catalog := testCatalog(t)
			mutate(&catalog)
			if _, _, err := CanonicalCatalog(catalog); !errors.Is(err, ErrInvalidCatalog) {
				t.Fatalf("CanonicalCatalog() error = %v, want ErrInvalidCatalog", err)
			}
		})
	}
	// Unknown kinds are valid catalog data (a newer license service); the
	// consumer decides whether it can use them.
	catalog := testCatalog(t)
	digest := sha256.Sum256([]byte("x"))
	catalog.Entries = append(catalog.Entries, Entry{ArtifactID: "zz_future/x", Kind: "zz_future", Version: "1", Revision: 1,
		SHA256: hex.EncodeToString(digest[:]), Size: 1, MediaType: "application/vnd.cdnca.future", Encryption: EncryptionNone})
	if _, _, err := CanonicalCatalog(catalog); err != nil {
		t.Fatalf("future kind rejected: %v", err)
	}
	if Supported(catalog.Entries[len(catalog.Entries)-1]) {
		t.Fatal("future kind reported as supported")
	}
}

func TestSignVerifyAndMonotonicRevisions(t *testing.T) {
	private := testKey(0x41)
	signer := testSigner{id: testKeyID, private: private}
	trust := testVerifier{public: map[string]ed25519.PublicKey{testKeyID: private.Public().(ed25519.PublicKey)}}
	now := time.Unix(1_900_000_000, 0).UTC()
	first, err := Sign(context.Background(), testEnvelope(), testCatalog(t), signer)
	if err != nil {
		t.Fatal(err)
	}
	options := VerifyOptions{Now: now, InstallationID: testInstallationID}
	verified, err := Verify(first, trust, options)
	if err != nil || verified.Duplicate {
		t.Fatalf("Verify(first) = %+v, %v", verified.Duplicate, err)
	}
	if err := VerifyEd25519(first, private.Public().(ed25519.PublicKey)); err != nil {
		t.Fatalf("VerifyEd25519: %v", err)
	}
	head := &Head{DeliveryID: first.Envelope.DeliveryID, ScopeRevision: 1, CatalogSHA256: first.Envelope.CatalogSHA256}
	if again, err := Verify(first, trust, VerifyOptions{Now: now, InstallationID: testInstallationID, Head: head}); err != nil || !again.Duplicate {
		t.Fatalf("Verify(duplicate) = %v, %v", again.Duplicate, err)
	}
	next := func(revision uint64, supersedes *string, id string) Signed {
		envelope := testEnvelope()
		envelope.DeliveryID, envelope.ScopeRevision, envelope.Supersedes = id, revision, supersedes
		catalog := testCatalog(t)
		catalog.Entries = catalog.Entries[1:]
		signed, err := Sign(context.Background(), envelope, catalog, signer)
		if err != nil {
			t.Fatal(err)
		}
		return signed
	}
	headID := head.DeliveryID
	wrong := "00000000-0000-4000-8000-0000000000ff"
	for name, test := range map[string]struct {
		signed Signed
		want   error
	}{
		"direct successor":     {next(2, &headID, "00000000-0000-4000-8000-0000000000b2"), nil},
		"gap after lost reply": {next(4, &wrong, "00000000-0000-4000-8000-0000000000b4"), nil},
		"successor wrong link": {next(2, &wrong, "00000000-0000-4000-8000-0000000000b3"), ErrSupersedesMismatch},
		"same revision fork":   {next(1, nil, "00000000-0000-4000-8000-0000000000b5"), ErrRevisionOutOfOrder},
	} {
		_, err := Verify(test.signed, trust, VerifyOptions{Now: now, InstallationID: testInstallationID, Head: head})
		if !errors.Is(err, test.want) {
			t.Fatalf("%s: Verify() error = %v, want %v", name, err, test.want)
		}
	}
	higher := &Head{DeliveryID: "00000000-0000-4000-8000-0000000000b9", ScopeRevision: 3, CatalogSHA256: first.Envelope.CatalogSHA256}
	if _, err := Verify(next(2, &headID, "00000000-0000-4000-8000-0000000000b2"), trust, VerifyOptions{Now: now, InstallationID: testInstallationID, Head: higher}); !errors.Is(err, ErrRevisionOutOfOrder) {
		t.Fatalf("Verify(older) error = %v", err)
	}
	if _, err := Verify(first, trust, VerifyOptions{Now: now, InstallationID: "00000000-0000-4000-8000-0000000000a2"}); !errors.Is(err, ErrTargetMismatch) {
		t.Fatalf("Verify(other installation) error = %v", err)
	}
	if _, err := Verify(first, trust, VerifyOptions{Now: time.Unix(1_900_604_800, 0), InstallationID: testInstallationID}); !errors.Is(err, ErrExpired) {
		t.Fatalf("Verify(expired) error = %v", err)
	}
	if _, err := Verify(first, trust, VerifyOptions{Now: time.Unix(1_899_999_800, 0), InstallationID: testInstallationID}); !errors.Is(err, ErrNotYetValid) {
		t.Fatalf("Verify(not yet valid) error = %v", err)
	}
	tampered := first
	tampered.Catalog = testCatalog(t)
	tampered.Catalog.Entries[0].SHA256 = hex.EncodeToString(make([]byte, 32))
	if _, err := Verify(tampered, trust, options); !errors.Is(err, ErrDigestMismatch) {
		t.Fatalf("Verify(tampered catalog) error = %v", err)
	}
	forged := first
	forged.Envelope.ExpiresAt++
	if _, err := Verify(forged, trust, options); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("Verify(tampered envelope) error = %v", err)
	}
	other := testKey(0x55)
	if _, err := Verify(first, testVerifier{public: map[string]ed25519.PublicKey{testKeyID: other.Public().(ed25519.PublicKey)}}, options); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("Verify(untrusted key) error = %v", err)
	}
}

func TestDecodeIsStrict(t *testing.T) {
	signed, err := Sign(context.Background(), testEnvelope(), testCatalog(t), testSigner{id: testKeyID, private: testKey(0x41)})
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := signed.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Decode(encoded); err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	for name, input := range map[string][]byte{
		"duplicate key": bytes.Replace(encoded, []byte(`"signature":`), []byte(`"signature":"x","signature":`), 1),
		"unknown field": bytes.Replace(encoded, []byte(`"signature":`), []byte(`"extra":1,"signature":`), 1),
		"trailing":      append(append([]byte(nil), encoded...), []byte(` {}`)...),
	} {
		if _, err := Decode(input); err == nil {
			t.Fatalf("Decode(%s) accepted", name)
		}
	}
}

func TestProofMessagesBindEveryField(t *testing.T) {
	resolve := ResolveRequest{Schema: ResolveRequestSchema, RequestID: "r1", InstallationID: testInstallationID,
		RequestedAt: 1, ControlVersion: "1.0.35", KnownDeliveryID: testDeliveryID, KnownScopeRevision: 2,
		KnownCatalogSHA256: "x"}
	base := ResolveProofMessage(resolve)
	changed := resolve
	changed.KnownScopeRevision = 3
	if bytes.Equal(ResolveProofMessage(changed), base) {
		t.Fatal("resolve proof ignores known_scope_revision")
	}
	fetch := FetchRequest{Schema: FetchRequestSchema, RequestID: "f1", InstallationID: testInstallationID, RequestedAt: 1,
		ArtifactID: "ruleset/cc_rule:6", Revision: 1, SHA256: "y"}
	fetchBase := FetchProofMessage(fetch)
	moved := fetch
	moved.ArtifactID = "ruleset/cc_rule:1"
	if bytes.Equal(FetchProofMessage(moved), fetchBase) || bytes.Equal(fetchBase, base) {
		t.Fatal("fetch proof does not bind artifact_id or collides with resolve")
	}
}

func entryByID(entries []Entry, id string) *Entry {
	for index := range entries {
		if entries[index].ArtifactID == id {
			return &entries[index]
		}
	}
	return nil
}

func sampleIPIntel(t *testing.T, revision uint64) (ipintel.Release, []byte) {
	t.Helper()
	generated := time.Unix(1_900_000_000, 0).UTC()
	artifact, err := ipintel.Build(ipintel.BuildInput{Revision: revision, BuildID: "ipintel-20300317-000007",
		GeneratedAt: generated, DataUpdatedAt: generated.Add(-time.Hour), StaleAfter: generated.Add(30 * 24 * time.Hour),
		Sources: []ipintel.Source{{ID: "s", Name: "s", URL: "https://example.invalid/s", License: "CC0-1.0", Ref: "x", Role: "asn",
			Files: []ipintel.SourceFile{{Path: "a", SHA256: "aa", Bytes: 1}}}},
		Facts:   []ipintel.Fact{{Prefix: netip.MustParsePrefix("1.0.0.0/24"), Tags: ipintel.TagCNTelecom, Country: "CN"}},
		Regions: map[uint32]string{}})
	if err != nil {
		t.Fatal(err)
	}
	release, err := ipintel.NewRelease(artifact)
	if err != nil {
		t.Fatal(err)
	}
	return release, artifact.Bytes
}

func TestIPIntelEntryChecksBytesAndMetadata(t *testing.T) {
	release, data := sampleIPIntel(t, 7)
	entry, err := IPIntelEntry(release)
	if err != nil {
		t.Fatal(err)
	}
	if entry.ArtifactID != IPIntelBaseID || !entry.Resident || entry.RequiresFeature != "" ||
		entry.RequiresCapability == nil || entry.RequiresCapability.Name != ipintel.Capability ||
		entry.RequiresCapability.MinVersion != ipintel.CapabilityVersion || !Supported(entry) {
		t.Fatalf("ip intel entry = %+v", entry)
	}
	if table, err := VerifyIPIntel(entry, data); err != nil || table.Metadata.Revision != 7 {
		t.Fatalf("VerifyIPIntel = %v", err)
	}
	tampered := append([]byte(nil), data...)
	tampered[len(tampered)-1] ^= 1
	if _, err := VerifyIPIntel(entry, tampered); !errors.Is(err, ErrContentMismatch) {
		t.Fatalf("tampered library error = %v", err)
	}
	// A library whose metadata disagrees with the signed entry is rejected
	// even when the digest is recomputed.
	_, other := sampleIPIntel(t, 8)
	forged := entry
	digest := sha256.Sum256(other)
	forged.SHA256, forged.Size = hex.EncodeToString(digest[:]), int64(len(other))
	if _, err := VerifyIPIntel(forged, other); !errors.Is(err, ErrContentMismatch) {
		t.Fatalf("metadata mismatch error = %v", err)
	}
}

func TestCRSProfilePackEntry(t *testing.T) {
	content := []byte(`{"schema":"cdnca.rule-pack/v1","pack_id":"system/crs-pl1"}`)
	entry, err := CRSProfilePackEntry("system/crs-pl1", "1.0.0", 1, content, "")
	if err != nil || entry.ArtifactID != "crs_profile/crs-pl1" || entry.Kind != KindCRSProfile ||
		entry.MediaType != MediaTypeCRSProfilePack || entry.LicenseSPDX != "Apache-2.0" || !entry.Resident ||
		entry.Size != int64(len(content)) || VerifyContent(entry, content) != nil || !Supported(entry) {
		t.Fatalf("entry = %+v, %v", entry, err)
	}
	if packID, ok := CRSProfilePackID(entry); !ok || packID != "system/crs-pl1" {
		t.Fatalf("pack id = %s %v", packID, ok)
	}
	// The rule text package is a crs_profile entry too, but no pack.
	text := entry
	text.ArtifactID, text.MediaType = CRSRulesID, MediaTypeCRSProfile
	if _, ok := CRSProfilePackID(text); ok {
		t.Fatal("rule text package named a pack")
	}
	if _, err := DecodeRulesetItem(entry, content); !errors.Is(err, ErrContentMismatch) {
		t.Fatalf("pack decoded as a system rule: %v", err)
	}
	for _, bad := range []string{"system/sqli", "dev/x/crs-pl1", "crs-pl1"} {
		if _, err := CRSProfilePackEntry(bad, "1.0.0", 1, content, ""); err == nil {
			t.Fatalf("pack id %s accepted", bad)
		}
	}
	wrong := entry
	wrong.MediaType = MediaTypeRuleset
	if ValidateEntry(wrong) == nil {
		t.Fatal("crs_profile with ruleset media type accepted")
	}
}
