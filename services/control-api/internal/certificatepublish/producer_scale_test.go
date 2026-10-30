package certificatepublish

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/certificateasset"
	"github.com/google/uuid"
)

// decodeProducedDocument decrypts a Build artifact (frozen recipient) into the
// document fields the node orders and binds by.
type producedDocument struct {
	Activation struct {
		Certificates []struct {
			SiteID          string `json:"site_id"`
			BindingRevision uint64 `json:"binding_revision"`
		} `json:"certificates"`
		RemovedSites []struct {
			TenantID        string `json:"tenant_id"`
			TenantScopeID   string `json:"tenant_scope_id"`
			SiteID          string `json:"site_id"`
			BindingRevision uint64 `json:"binding_revision"`
		} `json:"removed_sites"`
	} `json:"activation"`
	Bundle struct {
		Bindings []struct {
			SiteID  string   `json:"site_id"`
			Domains []string `json:"domains"`
		} `json:"bindings"`
	} `json:"bundle"`
}

func produceDocument(t *testing.T, build func(*Producer, BuildRequest) (BuildRequest, error)) producedDocument {
	t.Helper()
	request, receiverPrivate := frozenBuildRequest(t)
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x41}, ed25519.SeedSize))
	producer, err := newProducer(&testArtifactSigner{id: "certificate-signing-v1", private: key}, bytes.NewReader(bytes.Repeat([]byte{0x42}, 256)))
	if err != nil {
		t.Fatal(err)
	}
	var artifactRequest BuildRequest
	var plaintext []byte
	artifactRequest, err = build(producer, request)
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := producer.Build(t.Context(), artifactRequest)
	if err != nil {
		t.Fatal(err)
	}
	info, aad := frozenConsumerContext(t, metadataFromArtifact(artifactRequest, artifact))
	plaintext = decryptFrozenArtifact(t, receiverPrivate, artifact.WireBytes, info, aad)
	defer clearBytes(plaintext)
	var document producedDocument
	if err := json.Unmarshal(plaintext, &document); err != nil {
		t.Fatal(err)
	}
	return document
}

// A publication carries any number of sites (one asset bound to many sites);
// only its encrypted size is bounded. Each site names all its domains and its
// binding revision.
func TestProducerCarriesMoreThan64SitesWithDomainsAndBindingRevision(t *testing.T) {
	document := produceDocument(t, func(_ *Producer, request BuildRequest) (BuildRequest, error) {
		base := request.Materials[0]
		request.Materials = nil
		for index := 0; index < 65; index++ {
			material := base
			material.SiteID[15] = byte(index + 1)
			material.BindingRevision = int64(10 + index)
			material.SiteDomain = "edge.example.test"
			material.SiteDomains = []string{"edge.example.test", "www.edge.example.test"}
			request.Materials = append(request.Materials, material)
		}
		return request, nil
	})
	if len(document.Activation.Certificates) != 65 || len(document.Bundle.Bindings) != 65 {
		t.Fatalf("certificates=%d bindings=%d", len(document.Activation.Certificates), len(document.Bundle.Bindings))
	}
	for index, certificate := range document.Activation.Certificates {
		if certificate.BindingRevision != uint64(10+index) {
			t.Fatalf("certificate %d binding revision = %d", index, certificate.BindingRevision)
		}
	}
	if domains := document.Bundle.Bindings[0].Domains; len(domains) != 2 || domains[0] != "edge.example.test" || domains[1] != "www.edge.example.test" {
		t.Fatalf("domains = %v, want every site domain", domains)
	}
}

// An unpublication names the sites it removes and their binding revision; it
// does not resend the sites that stay.
func TestProducerBuildRemovalNamesRemovedSites(t *testing.T) {
	request, receiverPrivate := frozenBuildRequest(t)
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x43}, ed25519.SeedSize))
	producer, err := newProducer(&testArtifactSigner{id: "certificate-signing-v1", private: key}, bytes.NewReader(bytes.Repeat([]byte{0x44}, 256)))
	if err != nil {
		t.Fatal(err)
	}
	removed := RemovedSite{TenantID: request.Materials[0].TenantID, SiteID: request.Materials[0].SiteID, BindingRevision: 3}
	removal := RemovalBuildRequest{
		EventID: request.EventID, DeploymentID: request.DeploymentID, Attempt: request.Attempt,
		ConfigVersionID: request.ConfigVersionID, ArtifactID: request.ArtifactID,
		RecipientKeyID: request.RecipientKeyID, RecipientPublicKey: request.RecipientPublicKey,
		TenantScopeID: request.Materials[0].TenantScopeID, RemovedSites: []RemovedSite{removed},
	}
	artifact, err := producer.BuildRemoval(t.Context(), removal)
	if err != nil {
		t.Fatal(err)
	}
	info, aad := frozenConsumerContext(t, metadataFromArtifact(removal.buildRequest(), artifact))
	plaintext := decryptFrozenArtifact(t, receiverPrivate, artifact.WireBytes, info, aad)
	defer clearBytes(plaintext)
	var document producedDocument
	if err := json.Unmarshal(plaintext, &document); err != nil {
		t.Fatal(err)
	}
	if len(document.Activation.RemovedSites) != 1 || len(document.Activation.Certificates) != 0 || len(document.Bundle.Bindings) != 0 {
		t.Fatalf("removal document = %+v", document)
	}
	got := document.Activation.RemovedSites[0]
	if got.TenantID != removed.TenantID.String() || got.TenantScopeID != removal.TenantScopeID.String() ||
		got.SiteID != removed.SiteID.String() || got.BindingRevision != 3 {
		t.Fatalf("removed site = %+v", got)
	}
	empty := removal
	empty.RemovedSites = nil
	if _, err := producer.BuildRemoval(t.Context(), empty); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("removal without sites: %v", err)
	}
}

// Snapshots bound only the publication's size, not its site count.
func TestPublicationSnapshotAcceptsMoreThan64Sites(t *testing.T) {
	scope := uuid.MustParse("018f47a2-5b9c-7d31-8a60-104c9c0b7101")
	materials := make([]certificateasset.PublicationMaterial, 0, 65)
	for index := 0; index < 65; index++ {
		materials = append(materials, publicationTestMaterial(scope, uuid.New(), "edge.example.test", 1))
	}
	encoded, err := buildPublicationSnapshot(scope, materials)
	if err != nil {
		t.Fatal(err)
	}
	sites, _, err := parsePublicationSnapshot(scope, encoded)
	if err != nil || len(sites) != 65 {
		t.Fatalf("parsed %d sites: %v", len(sites), err)
	}
}
