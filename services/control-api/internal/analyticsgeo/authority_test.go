package analyticsgeo

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/netip"
	"sync"
	"testing"
	"time"
)

const authorityTestKeyID = "geo-authority-2026"

type authorityTestClock struct {
	mu  sync.RWMutex
	now time.Time
}

func (clock *authorityTestClock) Now() time.Time {
	clock.mu.RLock()
	defer clock.mu.RUnlock()
	return clock.now
}

func (clock *authorityTestClock) Set(now time.Time) {
	clock.mu.Lock()
	clock.now = now
	clock.mu.Unlock()
}

func TestAuthoritySignedSnapshotResolvesVersionedIPv4IPv6AndUnknown(t *testing.T) {
	authority, privateKey, clock := newAuthorityFixture(t, 1<<20)
	oldInput, currentInput := authorityCatalogInputs()
	expiresAt := clock.Now().Add(time.Hour)
	snapshot := signedAuthoritySnapshot(t, privateKey, 1, "geo-2026.08", expiresAt, []CatalogInput{oldInput, currentInput})
	if err := authority.Reload(t.Context(), snapshot); err != nil {
		t.Fatal(err)
	}

	for _, test := range []struct {
		name, version, address, country, region, carrier, catalogVersion string
		asn, bits                                                        int
		resolution                                                       Resolution
	}{
		{name: "ipv4 longest prefix", address: "203.0.113.129", country: "JP", region: "JP-13", carrier: "specific", asn: 64512, bits: 25, resolution: ResolutionMatched, catalogVersion: "geo-2026.08"},
		{name: "ipv6 documentation range", address: "2001:db8::7", country: "CN", region: "CN-BJ", carrier: "ipv6-current", asn: 64511, bits: 32, resolution: ResolutionMatched, catalogVersion: "geo-2026.08"},
		{name: "historical version", version: "geo-2026.07", address: "203.0.113.129", country: "CN", region: "CN-SH", carrier: "carrier-old", asn: 64510, bits: 24, resolution: ResolutionMatched, catalogVersion: "geo-2026.07"},
		{name: "unknown", address: "198.51.100.7", country: "__unknown__", region: "__unknown__", carrier: "__unknown__", resolution: ResolutionUnknown, catalogVersion: "geo-2026.08"},
	} {
		t.Run(test.name, func(t *testing.T) {
			result, err := authority.Lookup(t.Context(), test.version, netip.MustParseAddr(test.address))
			if err != nil {
				t.Fatal(err)
			}
			if result.Attribution.CountryCode != test.country || result.Attribution.Region != test.region ||
				result.Attribution.Carrier != test.carrier || result.Attribution.ASN != uint32(test.asn) ||
				result.Attribution.PrefixLength != test.bits || result.Attribution.Resolution != test.resolution ||
				result.Provenance.Version != test.catalogVersion || len(result.Provenance.SHA256) != sha256.Size*2 ||
				result.Revision != 1 || !result.ExpiresAt.Equal(expiresAt) ||
				result.State != AuthorityStateActive || result.Reason != AuthorityReasonNone {
				t.Fatalf("Lookup() = %#v", result)
			}
		})
	}
}

func TestAuthorityRejectedRefreshPreservesLastKnownGoodWithoutPartialInstall(t *testing.T) {
	authority, privateKey, clock := newAuthorityFixture(t, 1<<20)
	oldInput, currentInput := authorityCatalogInputs()
	initial := signedAuthoritySnapshot(t, privateKey, 10, "geo-2026.08", clock.Now().Add(time.Hour), []CatalogInput{oldInput, currentInput})
	if err := authority.Reload(t.Context(), initial); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name       string
		wantErr    error
		wantReason AuthorityReason
		mutate     func(*SignedAuthoritySnapshot)
	}{
		{name: "tampered catalog data", wantErr: ErrAuthoritySnapshot, wantReason: AuthorityReasonSnapshotRejected, mutate: func(snapshot *SignedAuthoritySnapshot) {
			snapshot.Catalogs[1].Data = append(bytes.Clone(snapshot.Catalogs[1].Data), ' ')
		}},
		{name: "tampered signature", wantErr: ErrAuthoritySignature, wantReason: AuthorityReasonSignatureRejected, mutate: func(snapshot *SignedAuthoritySnapshot) {
			snapshot.Signature[0] ^= 0xff
		}},
		{name: "equal revision", wantErr: ErrAuthorityRevision, wantReason: AuthorityReasonRevisionRejected, mutate: func(snapshot *SignedAuthoritySnapshot) {
			snapshot.Revision = initial.Revision
			resignAuthoritySnapshot(t, privateKey, snapshot)
		}},
		{name: "rollback revision", wantErr: ErrAuthorityRevision, wantReason: AuthorityReasonRevisionRejected, mutate: func(snapshot *SignedAuthoritySnapshot) {
			snapshot.Revision = initial.Revision - 1
			resignAuthoritySnapshot(t, privateKey, snapshot)
		}},
		{name: "expired candidate", wantErr: ErrAuthorityExpired, wantReason: AuthorityReasonCandidateExpired, mutate: func(snapshot *SignedAuthoritySnapshot) {
			snapshot.ExpiresAt = clock.Now()
			resignAuthoritySnapshot(t, privateKey, snapshot)
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := signedAuthoritySnapshot(t, privateKey, 11, "geo-2026.08", clock.Now().Add(2*time.Hour), []CatalogInput{oldInput, currentInput})
			test.mutate(&candidate)
			if err := authority.Reload(t.Context(), candidate); !errors.Is(err, test.wantErr) {
				t.Fatalf("Reload() error = %v, want %v", err, test.wantErr)
			}
			assertAuthorityLKG(t, authority, initial, test.wantReason)
		})
	}
}

func TestAuthorityEnforcesCapacityAndCanonicalExpiry(t *testing.T) {
	authority, privateKey, clock := newAuthorityFixture(t, 1024)
	oldInput, currentInput := authorityCatalogInputs()
	initial := signedAuthoritySnapshot(t, privateKey, 1, "geo-2026.08", clock.Now().Add(time.Hour), []CatalogInput{oldInput, currentInput})
	if err := authority.Reload(t.Context(), initial); err != nil {
		t.Fatal(err)
	}

	t.Run("aggregate bytes", func(t *testing.T) {
		data := bytes.Repeat([]byte{'x'}, 1025)
		digest := sha256.Sum256(data)
		oversized := CatalogInput{Data: data, ExpectedSHA256: hex.EncodeToString(digest[:])}
		candidate := signedAuthoritySnapshot(t, privateKey, 2, "geo-oversized", clock.Now().Add(time.Hour), []CatalogInput{oversized})
		if err := authority.Reload(t.Context(), candidate); !errors.Is(err, ErrAuthorityCapacity) {
			t.Fatalf("Reload() error = %v, want capacity rejection", err)
		}
		assertAuthorityLKG(t, authority, initial, AuthorityReasonCapacityRejected)
	})

	t.Run("document count", func(t *testing.T) {
		catalogs := make([]CatalogInput, 17)
		for index := range catalogs {
			catalogs[index] = currentInput
		}
		candidate := signedAuthoritySnapshot(t, privateKey, 2, "geo-2026.08", clock.Now().Add(time.Hour), catalogs)
		if err := authority.Reload(t.Context(), candidate); !errors.Is(err, ErrAuthorityCapacity) {
			t.Fatalf("Reload() error = %v, want capacity rejection", err)
		}
	})

	t.Run("non canonical expiry", func(t *testing.T) {
		candidate := signedAuthoritySnapshot(t, privateKey, 2, "geo-2026.08",
			clock.Now().Add(time.Hour+time.Nanosecond), []CatalogInput{oldInput, currentInput})
		if err := authority.Reload(t.Context(), candidate); !errors.Is(err, ErrAuthoritySnapshot) {
			t.Fatalf("Reload() error = %v, want canonical expiry rejection", err)
		}
	})
}

func TestAuthorityInstalledSnapshotAgesToExplicitExpiredLKG(t *testing.T) {
	authority, privateKey, clock := newAuthorityFixture(t, 1<<20)
	_, currentInput := authorityCatalogInputs()
	expiresAt := clock.Now().Add(time.Minute)
	snapshot := signedAuthoritySnapshot(t, privateKey, 1, "geo-2026.08", expiresAt, []CatalogInput{currentInput})
	if err := authority.Reload(t.Context(), snapshot); err != nil {
		t.Fatal(err)
	}
	clock.Set(expiresAt.Add(time.Millisecond))
	result, err := authority.Lookup(t.Context(), "", netip.MustParseAddr("203.0.113.129"))
	if err != nil {
		t.Fatal(err)
	}
	if result.State != AuthorityStateLKGExpired || result.Reason != AuthorityReasonLKGExpired ||
		result.Revision != snapshot.Revision || result.Attribution.Carrier != "specific" {
		t.Fatalf("expired LKG lookup = %#v", result)
	}
}

func TestAuthorityLookupReloadIsAtomicAndCancellationPreservesLKG(t *testing.T) {
	authority, privateKey, clock := newAuthorityFixture(t, 1<<20)
	first := authorityCurrentInput("geo-atomic-1", "carrier-one", 64520)
	second := authorityCurrentInput("geo-atomic-2", "carrier-two", 64521)
	initial := signedAuthoritySnapshot(t, privateKey, 1, "geo-atomic-1", clock.Now().Add(time.Hour), []CatalogInput{first})
	if err := authority.Reload(t.Context(), initial); err != nil {
		t.Fatal(err)
	}
	candidate := signedAuthoritySnapshot(t, privateKey, 2, "geo-atomic-2", clock.Now().Add(time.Hour), []CatalogInput{second})

	start := make(chan struct{})
	results := make(chan AuthorityLookup, 64)
	errorsSeen := make(chan error, 65)
	var wait sync.WaitGroup
	for range 64 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			result, err := authority.Lookup(context.Background(), "", netip.MustParseAddr("203.0.113.7"))
			if err != nil {
				errorsSeen <- err
				return
			}
			results <- result
		}()
	}
	wait.Add(1)
	go func() {
		defer wait.Done()
		<-start
		if err := authority.Reload(context.Background(), candidate); err != nil {
			errorsSeen <- err
		}
	}()
	close(start)
	wait.Wait()
	close(results)
	close(errorsSeen)
	for err := range errorsSeen {
		t.Fatalf("concurrent authority operation failed: %v", err)
	}
	for result := range results {
		if result.Revision == 1 && result.Attribution.Carrier == "carrier-one" && result.Provenance.Version == "geo-atomic-1" {
			continue
		}
		if result.Revision == 2 && result.Attribution.Carrier == "carrier-two" && result.Provenance.Version == "geo-atomic-2" {
			continue
		}
		t.Fatalf("partially installed authority result = %#v", result)
	}

	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	third := signedAuthoritySnapshot(t, privateKey, 3, "geo-atomic-2", clock.Now().Add(time.Hour), []CatalogInput{second})
	if err := authority.Reload(cancelled, third); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled Reload() error = %v", err)
	}
	if _, err := authority.Lookup(cancelled, "", netip.MustParseAddr("203.0.113.7")); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled Lookup() error = %v", err)
	}
	result, err := authority.Lookup(t.Context(), "", netip.MustParseAddr("203.0.113.7"))
	if err != nil || result.Revision != 2 || result.Attribution.Carrier != "carrier-two" {
		t.Fatalf("cancelled reload changed LKG: %#v, %v", result, err)
	}
}

func newAuthorityFixture(t *testing.T, maximum int) (*Authority, ed25519.PrivateKey, *authorityTestClock) {
	t.Helper()
	seed := bytes.Repeat([]byte{0x42}, ed25519.SeedSize)
	privateKey := ed25519.NewKeyFromSeed(seed)
	clock := &authorityTestClock{now: time.Date(2026, 8, 8, 4, 0, 0, 0, time.UTC)}
	authority, err := NewAuthority(AuthorityConfig{
		KeyID: authorityTestKeyID, PublicKey: privateKey.Public().(ed25519.PublicKey),
		Now: clock.Now, MaxAggregateBytes: maximum,
	})
	if err != nil {
		t.Fatal(err)
	}
	return authority, privateKey, clock
}

func authorityCatalogInputs() (CatalogInput, CatalogInput) {
	oldData := catalogDocument("geo-2026.07", "2026-07-01T00:00:00Z",
		`{"prefix":"203.0.113.0/24","country_code":"CN","region":"CN-SH","carrier":"carrier-old","asn":64510},`+
			`{"prefix":"2001:db8::/32","country_code":"CN","region":"CN-BJ","carrier":"ipv6-old","asn":64511}`)
	currentData := catalogDocument("geo-2026.08", "2026-08-01T00:00:00Z",
		`{"prefix":"203.0.113.0/24","country_code":"CN","region":"CN-SH","carrier":"carrier-current","asn":64510},`+
			`{"prefix":"203.0.113.128/25","country_code":"JP","region":"JP-13","carrier":"specific","asn":64512},`+
			`{"prefix":"2001:db8::/32","country_code":"CN","region":"CN-BJ","carrier":"ipv6-current","asn":64511}`)
	return catalogInput(oldData), catalogInput(currentData)
}

func authorityCurrentInput(version, carrier string, asn uint32) CatalogInput {
	data := catalogDocument(version, "2026-08-01T00:00:00Z",
		`{"prefix":"203.0.113.0/24","country_code":"CN","region":"CN-SH","carrier":"`+carrier+`","asn":`+
			jsonNumber(asn)+`}`)
	return catalogInput(data)
}

func jsonNumber(value uint32) string {
	encoded, _ := json.Marshal(value)
	return string(encoded)
}

func signedAuthoritySnapshot(
	t *testing.T,
	privateKey ed25519.PrivateKey,
	revision uint64,
	current string,
	expiresAt time.Time,
	catalogs []CatalogInput,
) SignedAuthoritySnapshot {
	t.Helper()
	snapshot := SignedAuthoritySnapshot{
		SchemaVersion: AuthoritySchemaV1, Revision: revision, KeyID: authorityTestKeyID,
		CurrentCatalogVersion: current, ExpiresAt: expiresAt, Catalogs: catalogs,
	}
	resignAuthoritySnapshot(t, privateKey, &snapshot)
	return snapshot
}

func resignAuthoritySnapshot(t *testing.T, privateKey ed25519.PrivateKey, snapshot *SignedAuthoritySnapshot) {
	t.Helper()
	digests := make([]string, len(snapshot.Catalogs))
	for index, catalog := range snapshot.Catalogs {
		digests[index] = catalog.ExpectedSHA256
	}
	manifest, err := json.Marshal(AuthorityManifest{
		SchemaVersion: snapshot.SchemaVersion, Revision: snapshot.Revision, KeyID: snapshot.KeyID,
		CurrentCatalogVersion: snapshot.CurrentCatalogVersion,
		ExpiresAt:             snapshot.ExpiresAt.UTC().Format(time.RFC3339Nano), CatalogSHA256: digests,
	})
	if err != nil {
		t.Fatal(err)
	}
	snapshot.Signature = ed25519.Sign(privateKey, manifest)
}

func assertAuthorityLKG(t *testing.T, authority *Authority, installed SignedAuthoritySnapshot, reason AuthorityReason) {
	t.Helper()
	result, err := authority.Lookup(t.Context(), "", netip.MustParseAddr("203.0.113.129"))
	if err != nil {
		t.Fatal(err)
	}
	if result.Revision != installed.Revision || !result.ExpiresAt.Equal(installed.ExpiresAt) ||
		result.Attribution.Carrier != "specific" || result.Provenance.Version != installed.CurrentCatalogVersion ||
		result.State != AuthorityStateLKG || result.Reason != reason {
		t.Fatalf("last known good changed after rejected refresh: %#v", result)
	}
}
