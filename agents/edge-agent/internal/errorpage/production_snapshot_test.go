package errorpage

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"testing"
)

func TestSITE13AggregateSnapshotUpdateKeepsUnrelatedSiteAndLKG(t *testing.T) {
	publisher, runtime := testPublisher(t)
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x75}, ed25519.SeedSize))
	installer, err := NewProductionSnapshotInstaller(publisher, site13Trust{key: private.Public().(ed25519.PublicKey)})
	if err != nil {
		t.Fatal(err)
	}
	binding := ProductionSnapshotBinding{
		TenantID:             "01990000-0000-7000-8000-000000000001",
		ConfigurationScopeID: "01990000-0000-7000-8000-000000000010", PublicationRevision: 80,
	}
	first := site13SignedSnapshot(t, private, binding, "a-v1\n", "b-v1\n")
	if _, err := installer.Install(t.Context(), first, binding); err != nil {
		t.Fatal(err)
	}
	binding.PublicationRevision++
	second := site13SignedSnapshot(t, private, binding, "a-v2\n", "b-v1\n")
	receipt, err := installer.Install(t.Context(), second, binding)
	if err != nil || receipt.State != ActivationStateActivated {
		t.Fatalf("receipt=%+v err=%v", receipt, err)
	}
	currentPolicy := site13CurrentPolicy(t, publisher)
	artifact, err := Compile(currentPolicy, "")
	if err != nil {
		t.Fatal(err)
	}
	resource, found := artifact.Lookup("01990000-0000-7000-8000-000000000002", CategoryEdgeRoute, 404)
	if !found || string(resource.Body) != "a-v2\n" {
		t.Fatalf("site A resource=%q found=%t", resource.Body, found)
	}
	resource, found = artifact.Lookup("01990000-0000-7000-8000-000000000003", CategoryOriginResponse, 503)
	if !found || string(resource.Body) != "b-v1\n" {
		t.Fatalf("site B was dropped: resource=%q found=%t", resource.Body, found)
	}
	runtime.precheckFail = true
	binding.PublicationRevision++
	if _, err := installer.Install(t.Context(), site13SignedSnapshot(t, private, binding, "a-v3\n", "b-v1\n"), binding); !errors.Is(err, ErrPrecheck) {
		t.Fatalf("precheck error=%v", err)
	}
	assertPointers(t, publisher, 81, receipt.ActiveDigest)
}

func site13SignedSnapshot(t *testing.T, private ed25519.PrivateKey, binding ProductionSnapshotBinding, siteABody, siteBBody string) SignedProductionSnapshot {
	t.Helper()
	document := ProductionSnapshotDocument{
		Schema: ProductionSnapshotSchema, Binding: binding, Global: ProductionSnapshotScope{Rules: []ProductionSnapshotRule{}},
		Sites: []ProductionSnapshotSite{
			{SiteKey: "01990000-0000-7000-8000-000000000002", Rules: []ProductionSnapshotRule{site13InlineRule("a", CategoryEdgeRoute, 404, siteABody)}},
			{SiteKey: "01990000-0000-7000-8000-000000000003", Rules: []ProductionSnapshotRule{site13InlineRule("b", CategoryOriginResponse, 503, siteBBody)}},
		},
	}
	wire, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(wire)
	return SignedProductionSnapshot{WireBytes: wire, SHA256: hex.EncodeToString(digest[:]), Signature: ed25519.Sign(private, wire), SigningKeyID: "error-page-signing-v1"}
}

func site13InlineRule(id string, category Category, status int, body string) ProductionSnapshotRule {
	digest := sha256.Sum256([]byte(body))
	return ProductionSnapshotRule{ID: id, Category: category, Match: StatusMatch{Codes: []int{status}},
		Resource: ProductionSnapshotResource{MIMEType: "text/plain", Size: int64(len(body)), SHA256: hex.EncodeToString(digest[:]), Body: []byte(body)}}
}

func site13CurrentPolicy(t *testing.T, publisher *Publisher) Policy {
	t.Helper()
	state, err := publisher.openState()
	if err != nil {
		t.Fatal(err)
	}
	defer state.close()
	target, _, found, err := publisher.readPointer(state, "current")
	if err != nil || !found {
		t.Fatalf("current found=%t err=%v", found, err)
	}
	release, err := openOwnedDirectoryAt(state.versions, target[len("versions/"):], 0o500, false)
	if err != nil {
		t.Fatal(err)
	}
	defer release.Close()
	raw, err := readImmutableAt(release, "policy.json")
	if err != nil {
		t.Fatal(err)
	}
	var canonical canonicalPolicy
	if err := json.Unmarshal(raw, &canonical); err != nil {
		t.Fatal(err)
	}
	return policyFromCanonicalForTest(canonical)
}

func policyFromCanonicalForTest(canonical canonicalPolicy) Policy {
	policy := Policy{Schema: canonical.Schema, Version: canonical.Version, Revision: canonical.Revision, Global: Scope{Rules: []Rule{}}}
	resources := make(map[string]Resource, len(canonical.Resources))
	for _, item := range canonical.Resources {
		body, _ := base64.StdEncoding.DecodeString(item.BodyBase64)
		inline := string(body)
		resources[item.Key] = Resource{MIMEType: item.MIMEType, Size: item.Size, SHA256: item.SHA256, Inline: &inline}
	}
	sites := make(map[string][]Rule)
	for _, binding := range canonical.Bindings {
		rule := Rule{ID: binding.RuleID, Category: binding.Category, Match: StatusMatch{Codes: []int{binding.Status}}, Resource: resources[binding.ResourceKey]}
		if binding.SiteKey == "" {
			policy.Global.Rules = append(policy.Global.Rules, rule)
		} else {
			sites[binding.SiteKey] = append(sites[binding.SiteKey], rule)
		}
	}
	for _, key := range []string{"01990000-0000-7000-8000-000000000002", "01990000-0000-7000-8000-000000000003"} {
		policy.Sites = append(policy.Sites, SiteScope{SiteKey: key, Rules: sites[key]})
	}
	return policy
}
