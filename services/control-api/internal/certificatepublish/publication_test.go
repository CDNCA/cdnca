package certificatepublish

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/certificateasset"
	"github.com/cdnca/cdnca/services/control-api/internal/edgedeployment"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type publicationTestMaterialStore struct{}

func (*publicationTestMaterialStore) UsePublicationMaterialsInTx(
	context.Context,
	pgx.Tx,
	certificateasset.PublicationRequest,
	certificateasset.PublicationConsumer,
) error {
	return nil
}

type publicationTestDeploymentStore struct{}

func (*publicationTestDeploymentStore) CreateCertificateSecretRolloutFromSourceTx(
	context.Context,
	pgx.Tx,
	edgedeployment.SecretRolloutRequest,
	edgedeployment.CertificateActorReference,
	[sha256.Size]byte,
	edgedeployment.CertificateSecretRolloutSource,
) (edgedeployment.CreateRolloutResult, error) {
	return edgedeployment.CreateRolloutResult{}, nil
}

func (*publicationTestDeploymentStore) CreateSecretRolloutFromSourceTx(
	context.Context,
	pgx.Tx,
	edgedeployment.SecretRolloutRequest,
	[sha256.Size]byte,
	[]string,
	edgedeployment.SecretRolloutSource,
) (edgedeployment.CreateRolloutResult, error) {
	return edgedeployment.CreateRolloutResult{}, nil
}

func (*publicationTestDeploymentStore) CreateSecretRolloutTx(
	context.Context,
	pgx.Tx,
	edgedeployment.SecretRolloutRequest,
	edgedeployment.SecretArtifactBuilder,
) (edgedeployment.CreateRolloutResult, error) {
	return edgedeployment.CreateRolloutResult{}, nil
}

func (*publicationTestDeploymentStore) ReplaceSecretRollout(
	context.Context,
	edgedeployment.SecretReplacementRequest,
	edgedeployment.SecretReplacementSource,
) (edgedeployment.SecretReplacementResult, error) {
	return edgedeployment.SecretReplacementResult{}, nil
}

func TestBuildPublicationSnapshotIsDeterministicAndRedacted(t *testing.T) {
	tenantScopeID := uuid.New()
	firstSite := uuid.MustParse("10000000-0000-0000-0000-000000000001")
	secondSite := uuid.MustParse("20000000-0000-0000-0000-000000000002")
	first := publicationTestMaterial(tenantScopeID, firstSite, "first.example.test", 7)
	second := publicationTestMaterial(tenantScopeID, secondSite, "second.example.test", 9)

	forward, err := buildPublicationSnapshot(tenantScopeID, []certificateasset.PublicationMaterial{first, second})
	if err != nil {
		t.Fatal(err)
	}
	reverse, err := buildPublicationSnapshot(tenantScopeID, []certificateasset.PublicationMaterial{second, first})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(forward, reverse) {
		t.Fatalf("snapshot depends on input order:\n%s\n%s", forward, reverse)
	}
	for _, forbidden := range [][]byte{
		first.CertificatePEM, first.PrivateKeyPEM, []byte("certificate_chain_pem"), []byte("private_key_pem"),
	} {
		if bytes.Contains(forward, forbidden) {
			t.Fatalf("snapshot contains private/publication material %q", forbidden)
		}
	}
	var decoded publicationSnapshot
	if err := json.Unmarshal(forward, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Schema != PublicationSnapshotSchema || decoded.TenantScopeID != tenantScopeID.String() ||
		len(decoded.Certificates) != 2 || decoded.Certificates[0].SiteID != firstSite.String() ||
		decoded.Certificates[0].CertificateVersion != first.CertificateVersion ||
		decoded.Certificates[0].BindingRevision != first.BindingRevision {
		t.Fatalf("snapshot identities=%+v", decoded)
	}
}

func TestBuildPublicationSnapshotRejectsInvalidIdentity(t *testing.T) {
	tenantScopeID := uuid.New()
	valid := publicationTestMaterial(tenantScopeID, uuid.New(), "valid.example.test", 1)
	tests := []struct {
		name   string
		values []certificateasset.PublicationMaterial
	}{
		{name: "empty"},
		{name: "cross scope", values: []certificateasset.PublicationMaterial{func() certificateasset.PublicationMaterial {
			value := valid
			value.TenantScopeID = uuid.New()
			return value
		}()}},
		{name: "duplicate site", values: []certificateasset.PublicationMaterial{valid, valid}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := buildPublicationSnapshot(tenantScopeID, test.values); err == nil {
				t.Fatal("invalid publication snapshot was accepted")
			}
		})
	}
}

func TestParsePublicationSnapshotIsCanonicalAndRejectsMutation(t *testing.T) {
	tenantScopeID := uuid.New()
	first := publicationTestMaterial(tenantScopeID,
		uuid.MustParse("10000000-0000-0000-0000-000000000001"), "first.example.test", 7)
	second := publicationTestMaterial(tenantScopeID,
		uuid.MustParse("20000000-0000-0000-0000-000000000002"), "second.example.test", 9)
	canonical, err := buildPublicationSnapshot(tenantScopeID, []certificateasset.PublicationMaterial{second, first})
	if err != nil {
		t.Fatal(err)
	}
	sites, removedNone, err := parsePublicationSnapshot(tenantScopeID, canonical)
	if err != nil || len(removedNone) != 0 {
		t.Fatal(err)
	}
	if len(sites) != 2 || sites[0] != first.SiteID || sites[1] != second.SiteID {
		t.Fatalf("sites=%v", sites)
	}
	removal, err := buildRemovalSnapshot(tenantScopeID)
	if err != nil {
		t.Fatal(err)
	}
	if string(removal) != `{"schema":"cdnca.edge.certificate-publication/v1","tenant_scope_id":"`+
		tenantScopeID.String()+`","certificates":[]}` {
		t.Fatalf("removal snapshot=%s", removal)
	}
	removedSites, _, err := parsePublicationSnapshot(tenantScopeID, removal)
	if err != nil || removedSites == nil || len(removedSites) != 0 {
		t.Fatalf("removal sites=%v error=%v", removedSites, err)
	}

	// An unpublication records its removal next to the sites that remain.
	tenantID := first.TenantID
	gone := RemovedSite{TenantID: tenantID, SiteID: uuid.MustParse("30000000-0000-0000-0000-000000000003"), BindingRevision: 12}
	alsoGone := RemovedSite{TenantID: tenantID, SiteID: uuid.MustParse("15000000-0000-0000-0000-000000000005"), BindingRevision: 4}
	withRemoval, err := withRemovedSites(canonical, []RemovedSite{gone, alsoGone})
	if err != nil {
		t.Fatal(err)
	}
	remaining, removed, err := parsePublicationSnapshot(tenantScopeID, withRemoval)
	if err != nil || len(remaining) != 2 || !reflect.DeepEqual(removed, []RemovedSite{alsoGone, gone}) {
		t.Fatalf("remaining=%v removed=%+v error=%v", remaining, removed, err)
	}
	emptyWithRemoval, err := withRemovedSites(removal, []RemovedSite{gone})
	if err != nil {
		t.Fatal(err)
	}
	if _, removed, err := parsePublicationSnapshot(tenantScopeID, emptyWithRemoval); err != nil || len(removed) != 1 {
		t.Fatalf("removal-only snapshot removed=%+v error=%v", removed, err)
	}
	overlapping, err := withRemovedSites(canonical, []RemovedSite{{TenantID: tenantID, SiteID: first.SiteID, BindingRevision: 8}})
	if err != nil {
		t.Fatal(err)
	}
	var unsorted publicationSnapshot
	if err := json.Unmarshal(withRemoval, &unsorted); err != nil {
		t.Fatal(err)
	}
	unsorted.RemovedSites[0], unsorted.RemovedSites[1] = unsorted.RemovedSites[1], unsorted.RemovedSites[0]
	unsortedBytes, err := json.Marshal(unsorted)
	if err != nil {
		t.Fatal(err)
	}
	otherTenant, err := withRemovedSites(canonical, []RemovedSite{{TenantID: uuid.New(), SiteID: gone.SiteID, BindingRevision: 12}})
	if err != nil {
		t.Fatal(err)
	}

	var decoded publicationSnapshot
	if err := json.Unmarshal(canonical, &decoded); err != nil {
		t.Fatal(err)
	}
	reversed := decoded
	reversed.Certificates = append([]publicationSnapshotCertificate(nil), decoded.Certificates...)
	reversed.Certificates[0], reversed.Certificates[1] = reversed.Certificates[1], reversed.Certificates[0]
	reversedBytes, err := json.Marshal(reversed)
	if err != nil {
		t.Fatal(err)
	}
	crossScope := bytes.Replace(canonical, []byte(tenantScopeID.String()), []byte(uuid.NewString()), 1)
	for name, invalid := range map[string][]byte{
		"trailing json":                append(append([]byte(nil), canonical...), []byte(`{}`)...),
		"unknown field":                append(append([]byte(nil), canonical[:len(canonical)-1]...), []byte(`,"extra":true}`)...),
		"noncanonical":                 append([]byte(" "), canonical...),
		"reversed sites":               reversedBytes,
		"cross scope":                  crossScope,
		"removed site still published": overlapping,
		"unsorted removal":             unsortedBytes,
		"removal of another tenant":    otherTenant,
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, err := parsePublicationSnapshot(tenantScopeID, invalid); !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("parsePublicationSnapshot() error=%v", err)
			}
		})
	}
}

func TestNewPublicationServiceRejectsNilDependencies(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	producer, err := NewProducer(&testArtifactSigner{id: "publication-test-signer", private: privateKey})
	if err != nil {
		t.Fatal(err)
	}
	pool := new(pgxpool.Pool)
	materials := &publicationTestMaterialStore{}
	deployments := &publicationTestDeploymentStore{}
	config := DefaultPublicationConfig()
	if _, err := NewPublicationService(pool, materials, deployments, producer, config); err != nil {
		t.Fatal(err)
	}
	var typedNilMaterials *publicationTestMaterialStore
	var typedNilDeployments *publicationTestDeploymentStore
	for name, build := range map[string]func() error{
		"pool": func() error {
			_, err := NewPublicationService(nil, materials, deployments, producer, config)
			return err
		},
		"materials": func() error {
			_, err := NewPublicationService(pool, typedNilMaterials, deployments, producer, config)
			return err
		},
		"deployments": func() error {
			_, err := NewPublicationService(pool, materials, typedNilDeployments, producer, config)
			return err
		},
		"producer": func() error {
			_, err := NewPublicationService(pool, materials, deployments, nil, config)
			return err
		},
	} {
		t.Run(name, func(t *testing.T) {
			if err := build(); err == nil {
				t.Fatal("nil dependency was accepted")
			}
		})
	}
}

func publicationTestMaterial(
	tenantScopeID, siteID uuid.UUID,
	domain string,
	version int64,
) certificateasset.PublicationMaterial {
	fingerprint := sha256.Sum256([]byte("fingerprint:" + domain))
	publicKey := sha256.Sum256([]byte("public-key:" + domain))
	return certificateasset.PublicationMaterial{
		TenantID: tenantScopeID, TenantScopeID: tenantScopeID, SiteID: siteID, SiteDomain: domain,
		AssetID: uuid.New(), AssetRevision: version + 10, CertificateVersionID: uuid.New(),
		CertificateVersion: version, BindingRevision: version + 20,
		CertificatePEM:    []byte("PUBLIC-CERTIFICATE-" + domain),
		PrivateKeyPEM:     []byte("PRIVATE-PKCS8-" + domain),
		FingerprintSHA256: fingerprint, PublicKeySHA256: publicKey,
		NotBefore: time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:  time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC),
	}
}
