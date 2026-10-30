package artifactsynctest

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/entitlement/artifactcatalog"
	"github.com/cdnca/cdnca/libs/entitlement/rulecatalog"
	"github.com/cdnca/cdnca/services/control-api/internal/artifactsync"
	"github.com/google/uuid"
)

const KeyID = "artifact-test-key"

// License is an in-memory license service for one installation: it signs a
// new delivery (scope_revision+1, superseding the previous one) whenever the
// published entries change, serves exactly the published bytes, and records
// what the control plane fetched. Tamper* damage what goes over the wire,
// never what is published.
type License struct {
	InstallationID uuid.UUID
	Now            func() time.Time
	// TamperDelivery, when set, edits a copy of the delivery returned.
	TamperDelivery func(*artifactcatalog.Signed)
	// TamperContent, when set, returns the bytes served for an entry.
	TamperContent func(artifactcatalog.Entry, []byte) []byte
	// ResolveErr, when set, fails resolves.
	ResolveErr error
	Fetched    []string

	t       testing.TB
	key     ed25519.PrivateKey
	entries map[string]artifactcatalog.Entry
	content map[string][]byte
	last    *artifactcatalog.Signed
}

func NewLicense(t testing.TB, installationID uuid.UUID, now func() time.Time) *License {
	return &License{InstallationID: installationID, Now: now, t: t,
		key: ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x5a}, 32)), entries: map[string]artifactcatalog.Entry{},
		content: map[string][]byte{}}
}

// Trust verifies the license signature (the entitlementguard.TrustStore stand-in).
func (license *License) Trust() artifactcatalog.Verifier {
	return trust{license.key.Public().(ed25519.PublicKey)}
}

// PublishRule lists a system rule as a ruleset / crs_profile entry.
func (license *License) PublishRule(item rulecatalog.Item, requiresFeature string, resident bool) artifactcatalog.Entry {
	license.t.Helper()
	entry, content, err := artifactcatalog.RulesetEntry(item, requiresFeature, resident)
	if err != nil {
		license.t.Fatalf("publish %s: %v", item.SystemKey, err)
	}
	license.Publish(entry, content)
	return entry
}

// Publish lists entry with its bytes (replacing an entry of the same id).
func (license *License) Publish(entry artifactcatalog.Entry, content []byte) {
	license.entries[entry.ArtifactID], license.content[entry.ArtifactID] = entry, bytes.Clone(content)
}

// Withdraw stops listing artifactID.
func (license *License) Withdraw(artifactID string) {
	delete(license.entries, artifactID)
	delete(license.content, artifactID)
}

// Last is the last delivery signed.
func (license *License) Last() *artifactcatalog.Signed { return license.last }

func (license *License) catalog() artifactcatalog.Catalog {
	entries := make([]artifactcatalog.Entry, 0, len(license.entries))
	for _, entry := range license.entries {
		entries = append(entries, entry)
	}
	artifactcatalog.SortEntries(entries)
	return artifactcatalog.Catalog{Schema: artifactcatalog.CatalogSchema, Entries: entries}
}

func (license *License) Resolve(ctx context.Context, installationID uuid.UUID, _ string, head *artifactcatalog.Head,
	_ ed25519.PrivateKey, _ time.Time) (artifactcatalog.ResolveResponse, error) {
	if license.ResolveErr != nil {
		return artifactcatalog.ResolveResponse{}, license.ResolveErr
	}
	if installationID != license.InstallationID {
		return artifactcatalog.ResolveResponse{}, errors.New("unknown installation")
	}
	catalog := license.catalog()
	_, digest, err := artifactcatalog.CanonicalCatalog(catalog)
	if err != nil {
		return artifactcatalog.ResolveResponse{}, err
	}
	if license.last == nil || license.last.Envelope.CatalogSHA256 != artifactcatalog.DigestString(digest) {
		now := license.Now()
		envelope := artifactcatalog.Envelope{DeliveryID: uuid.Must(uuid.NewV7()).String(), InstallationID: installationID.String(),
			ScopeRevision: 1, SignedAt: now.Unix(), ValidFrom: now.Add(-time.Minute).Unix(), ExpiresAt: now.Add(7 * 24 * time.Hour).Unix()}
		if license.last != nil {
			previous := license.last.Envelope.DeliveryID
			envelope.ScopeRevision, envelope.Supersedes = license.last.Envelope.ScopeRevision+1, &previous
		}
		signed, err := artifactcatalog.Sign(ctx, envelope, catalog, signer{license.key})
		if err != nil {
			return artifactcatalog.ResolveResponse{}, err
		}
		license.last = &signed
	}
	response := artifactcatalog.ResolveResponse{Schema: artifactcatalog.ResolveResponseSchema, InstallationID: installationID.String(),
		ResolvedAt: license.Now().Unix()}
	if head != nil && head.DeliveryID == license.last.Envelope.DeliveryID && head.CatalogSHA256 == license.last.Envelope.CatalogSHA256 {
		response.NotModified = true
		return response, nil
	}
	delivery := *license.last
	delivery.Catalog.Entries = slices.Clone(delivery.Catalog.Entries)
	if license.TamperDelivery != nil {
		license.TamperDelivery(&delivery)
	}
	response.Delivery = &delivery
	return response, nil
}

func (license *License) Fetch(_ context.Context, _ uuid.UUID, requested artifactcatalog.Entry, _ ed25519.PrivateKey,
	_ time.Time) ([]byte, error) {
	entry, ok := license.entries[requested.ArtifactID]
	if !ok || entry.Revision != requested.Revision || entry.SHA256 != requested.SHA256 {
		return nil, &artifactsync.ServiceError{StatusCode: 404, Code: "artifact_unavailable"}
	}
	license.Fetched = append(license.Fetched, requested.ArtifactID)
	content := bytes.Clone(license.content[requested.ArtifactID])
	if license.TamperContent != nil {
		content = license.TamperContent(entry, content)
	}
	return content, nil
}

type signer struct{ key ed25519.PrivateKey }

func (signer signer) KeyID() string { return KeyID }
func (signer signer) Sign(_ context.Context, payload []byte) ([]byte, error) {
	return ed25519.Sign(signer.key, payload), nil
}

type trust struct{ key ed25519.PublicKey }

func (trust trust) VerifyDetached(keyID string, payload, signature []byte, _, _ time.Time) error {
	if keyID != KeyID || !ed25519.Verify(trust.key, payload, signature) {
		return errors.New("untrusted artifact catalog signature")
	}
	return nil
}

// NextCRSRevision returns item (the CRS rule text) at revision+1 with one
// line appended to file, so that file's digest changes.
func NextCRSRevision(t testing.TB, item rulecatalog.Item, file string) rulecatalog.Item {
	t.Helper()
	files, err := rulecatalog.DecodeWAFEngineBundle(*item.Body.WAFRuleSet.Bundle)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := files[file]; !ok {
		t.Fatalf("CRS bundle has no %s", file)
	}
	files[file] = append(bytes.Clone(files[file]), []byte("\n# test revision\n")...)
	bundle, err := rulecatalog.BuildWAFEngineBundle(item.Body.WAFRuleSet.Bundle.Version, files)
	if err != nil {
		t.Fatal(err)
	}
	next := item
	ruleSet := *item.Body.WAFRuleSet
	ruleSet.Bundle = &bundle
	next.Body.WAFRuleSet = &ruleSet
	next.Revision++
	return next
}

// SystemRule returns the seed item with systemKey.
func SystemRule(t testing.TB, items []rulecatalog.Item, systemKey string) rulecatalog.Item {
	t.Helper()
	for _, item := range items {
		if item.SystemKey == systemKey {
			return item
		}
	}
	t.Fatalf("no system rule %s", systemKey)
	return rulecatalog.Item{}
}
