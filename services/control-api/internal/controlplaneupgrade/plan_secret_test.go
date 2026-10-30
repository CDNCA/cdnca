package controlplaneupgrade

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/entitlementguard"
	"github.com/google/uuid"
)

func TestPlanPublisherVerifiesBindsAndReplaysSecretPublication(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	privateKey := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	signer := runnerTestSigner{privateKey: privateKey}
	encoded := signedRunnerTestBundle(t, now, signer)
	trust, err := entitlementguard.NewTrustStore([]entitlementguard.VerificationKey{{
		KeyID: signer.KeyID(), PublicKey: privateKey.Public().(ed25519.PublicKey),
	}})
	if err != nil {
		t.Fatal(err)
	}
	repository := newMemorySecretRepository()
	publisher, err := NewPlanPublisher(PlanPublisherConfig{
		InstallationID: "00000000-0000-4000-8000-000000000005", Component: "control-api",
		CurrentVersion: "1.4.0", CurrentDigest: digest52, ProtocolVersion: 2,
		Trust: trust, Now: func() time.Time { return now.Add(time.Minute) },
	}, repository)
	if err != nil {
		t.Fatal(err)
	}
	request := PublishRequest{Bundle: encoded, ExpectedRevision: 0, IdempotencyKey: "publish-plan-42",
		RequestID: "request-42", ActorUserID: uuid.MustParse("00000000-0000-4000-8000-000000000010"),
		ActorScopeID: uuid.MustParse("00000000-0000-4000-8000-000000000011")}
	receipt, err := publisher.Publish(t.Context(), request)
	if err != nil {
		t.Fatal(err)
	}
	if receipt.PlanID != "00000000-0000-4000-8000-000000000002" || receipt.PublicationRevision != 1 ||
		receipt.ChannelRevision != 7 || receipt.CurrentVersion != "1.4.0" || receipt.TargetVersion != "1.5.0" ||
		receipt.CurrentDigest != digest52 || receipt.TargetDigest != digest51 || receipt.Replayed {
		t.Fatalf("receipt = %#v", receipt)
	}
	document, _ := repository.Read(t.Context())
	if string(document.Bundle) != string(encoded) || document.Publication == nil || document.Publication.BundleSHA256 != receipt.BundleSHA256 {
		t.Fatalf("stored document = %#v", document)
	}
	replayed, err := publisher.Publish(t.Context(), request)
	if err != nil || !replayed.Replayed || replayed.ReceiptID != receipt.ReceiptID || repository.writes != 1 {
		t.Fatalf("replay = (%#v, %v), writes=%d", replayed, err, repository.writes)
	}
}

func TestPlanPublisherRejectsTamperStaleAndIdempotencyConflictBeforeWrite(t *testing.T) {
	fixture := newPublisherFixture(t)
	tampered := append([]byte(nil), fixture.encoded...)
	tampered[len(tampered)-2] ^= 1
	request := fixture.request
	request.Bundle = tampered
	if _, err := fixture.publisher.Publish(t.Context(), request); !errors.Is(err, ErrInvalidPlan) {
		t.Fatalf("tamper error = %v", err)
	}
	if fixture.repository.writes != 0 {
		t.Fatalf("tamper writes = %d", fixture.repository.writes)
	}
	if _, err := fixture.publisher.Publish(t.Context(), fixture.request); err != nil {
		t.Fatal(err)
	}
	stale := fixture.request
	stale.IdempotencyKey = "publish-stale"
	if _, err := fixture.publisher.Publish(t.Context(), stale); !errors.Is(err, ErrRevisionConflict) {
		t.Fatalf("stale error = %v", err)
	}
	conflict := fixture.request
	conflict.ExpectedRevision = 1
	if _, err := fixture.publisher.Publish(t.Context(), conflict); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("idempotency error = %v", err)
	}
}

func TestKubernetesSecretRepositoryUsesResourceVersionCASAndPreservesUnknownKeys(t *testing.T) {
	fixture := newPublisherFixture(t)
	receipt, err := fixture.publisher.Publish(t.Context(), fixture.request)
	if err != nil {
		t.Fatal(err)
	}
	publication, _ := json.Marshal(receipt)
	secret := kubernetesSecret{APIVersion: "v1", Kind: "Secret", Type: "Opaque", Data: map[string]string{
		defaultBundleKey: base64.StdEncoding.EncodeToString(fixture.encoded),
		publicationKey:   base64.StdEncoding.EncodeToString(publication),
		"internal-token": base64.StdEncoding.EncodeToString([]byte("internal-token-32-bytes-long-value")),
	}}
	secret.Metadata.Name, secret.Metadata.Namespace, secret.Metadata.ResourceVersion = "upgrade-plan", "cdnca", "7"
	tokenFile := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenFile, []byte("token-one"), 0o600); err != nil {
		t.Fatal(err)
	}
	expectedToken := "token-one"
	putCalls := 0
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "Bearer "+expectedToken {
			http.Error(writer, "token", http.StatusUnauthorized)
			return
		}
		writer.Header().Set("Content-Type", "application/json")
		switch request.Method {
		case http.MethodGet:
			_ = json.NewEncoder(writer).Encode(secret)
		case http.MethodPut:
			putCalls++
			if putCalls > 1 {
				http.Error(writer, "conflict", http.StatusConflict)
				return
			}
			var candidate kubernetesSecret
			if json.NewDecoder(request.Body).Decode(&candidate) != nil || candidate.Metadata.ResourceVersion != "7" ||
				candidate.Data["internal-token"] != secret.Data["internal-token"] {
				http.Error(writer, "invalid CAS", http.StatusBadRequest)
				return
			}
			candidate.Metadata.ResourceVersion = "8"
			secret = candidate
			_ = json.NewEncoder(writer).Encode(candidate)
		default:
			http.Error(writer, "method", http.StatusMethodNotAllowed)
		}
	}))
	defer server.Close()
	repository, err := NewKubernetesSecretRepository(KubernetesSecretConfig{APIServer: server.URL,
		Namespace: "cdnca", SecretName: "upgrade-plan", TokenFile: tokenFile, HTTPClient: server.Client()})
	if err != nil {
		t.Fatal(err)
	}
	document, err := repository.Read(t.Context())
	if err != nil || string(document.Data["internal-token"]) != "internal-token-32-bytes-long-value" {
		t.Fatalf("read document = (%#v, %v)", document, err)
	}
	if err := os.WriteFile(tokenFile, []byte("token-two"), 0o600); err != nil {
		t.Fatal(err)
	}
	expectedToken = "token-two"
	updated, err := repository.CompareAndSwap(t.Context(), "7", document)
	if err != nil || updated.ResourceVersion != "8" || string(updated.Data["internal-token"]) != "internal-token-32-bytes-long-value" {
		t.Fatalf("updated document = (%#v, %v)", updated, err)
	}
	updated.ResourceVersion = "8"
	if _, err := repository.CompareAndSwap(t.Context(), "8", updated); !errors.Is(err, ErrSecretConflict) {
		t.Fatalf("conflict error = %v", err)
	}
}

type publisherFixture struct {
	publisher  *PlanPublisher
	repository *memorySecretRepository
	encoded    []byte
	request    PublishRequest
}

func newPublisherFixture(t *testing.T) publisherFixture {
	t.Helper()
	now := time.Unix(1_800_000_000, 0).UTC()
	privateKey := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	signer := runnerTestSigner{privateKey: privateKey}
	trust, err := entitlementguard.NewTrustStore([]entitlementguard.VerificationKey{{KeyID: signer.KeyID(), PublicKey: privateKey.Public().(ed25519.PublicKey)}})
	if err != nil {
		t.Fatal(err)
	}
	repository := newMemorySecretRepository()
	publisher, err := NewPlanPublisher(PlanPublisherConfig{InstallationID: "00000000-0000-4000-8000-000000000005",
		Component: "control-api", CurrentVersion: "1.4.0", CurrentDigest: digest52, ProtocolVersion: 2,
		Trust: trust, Now: func() time.Time { return now.Add(time.Minute) }}, repository)
	if err != nil {
		t.Fatal(err)
	}
	encoded := signedRunnerTestBundle(t, now, signer)
	return publisherFixture{publisher: publisher, repository: repository, encoded: encoded,
		request: PublishRequest{Bundle: encoded, ExpectedRevision: 0, IdempotencyKey: "publish-plan-42",
			RequestID: "request-42", ActorUserID: uuid.New(), ActorScopeID: uuid.New()}}
}

type memorySecretRepository struct {
	mu       sync.Mutex
	document SecretDocument
	writes   int
}

func newMemorySecretRepository() *memorySecretRepository {
	return &memorySecretRepository{document: SecretDocument{ResourceVersion: "1"}}
}

func (repository *memorySecretRepository) Read(context.Context) (SecretDocument, error) {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	return cloneSecretDocument(repository.document), nil
}

func (repository *memorySecretRepository) CompareAndSwap(_ context.Context, expected string, document SecretDocument) (SecretDocument, error) {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	if expected != repository.document.ResourceVersion {
		return SecretDocument{}, ErrSecretConflict
	}
	repository.writes++
	document.ResourceVersion = string(rune('1' + repository.writes))
	repository.document = cloneSecretDocument(document)
	return cloneSecretDocument(repository.document), nil
}

const (
	digest51 = "5151515151515151515151515151515151515151515151515151515151515151"
	digest52 = "5252525252525252525252525252525252525252525252525252525252525252"
)
