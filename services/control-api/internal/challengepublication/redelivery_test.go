package challengepublication

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/edgedeployment"
	"github.com/cdnca/cdnca/services/control-api/internal/edgepublish"
	"github.com/cloudflare/circl/hpke"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type redeliverySourceStub struct {
	origin    []byte
	generator string
	snapshot  PublicationSnapshot
	err       error
}

func (stub *redeliverySourceStub) LoadRedeliveryFactsTx(_ context.Context, _ pgx.Tx, item edgepublish.ChallengeRedelivery,
) (RedeliveryFacts, error) {
	if stub.err != nil {
		return RedeliveryFacts{}, stub.err
	}
	snapshot := stub.snapshot
	snapshot.PolicyID, snapshot.TenantScopeID, snapshot.SiteID, snapshot.Revision =
		item.PolicyID, item.ScopeID, item.SiteID, item.PolicyVersion
	return RedeliveryFacts{OriginSnapshot: bytes.Clone(stub.origin), OriginGenerator: stub.generator, Policy: snapshot}, nil
}

type redeliveryStoreStub struct {
	t        *testing.T
	request  edgedeployment.SystemSecretRolloutRequest
	calls    int
	err      error
	rollout  uuid.UUID
	artifact edgedeployment.ArtifactInput
}

func (stub *redeliveryStoreStub) CreateSystemSecretRolloutTx(ctx context.Context, _ pgx.Tx,
	request edgedeployment.SystemSecretRolloutRequest, builder edgedeployment.SecretArtifactBuilder,
) (edgedeployment.CreateRolloutResult, error) {
	stub.calls++
	stub.request = request
	stub.request.CanonicalSnapshot = bytes.Clone(request.CanonicalSnapshot)
	if stub.err != nil {
		return edgedeployment.CreateRolloutResult{}, stub.err
	}
	public, _, err := hpke.KEM_X25519_HKDF_SHA256.Scheme().GenerateKeyPair()
	if err != nil {
		stub.t.Fatal(err)
	}
	publicBytes, err := public.MarshalBinary()
	if err != nil {
		stub.t.Fatal(err)
	}
	digest := sha256.Sum256(publicBytes)
	stub.artifact, err = builder(ctx, edgedeployment.SecretArtifactBinding{
		EventID: uuid.New(), DeploymentID: uuid.New(), RolloutID: stub.rollout, Attempt: 1, ConfigVersionID: uuid.New(),
		ArtifactID: uuid.New(), NodeID: request.NodeIDs[0], RecipientKeyID: "x25519:" + hex.EncodeToString(digest[:]),
		RecipientPublicKey: publicBytes,
	})
	if err != nil {
		return edgedeployment.CreateRolloutResult{}, err
	}
	return edgedeployment.CreateRolloutResult{Rollout: edgedeployment.Rollout{ID: stub.rollout}}, nil
}

func redeliveryFixture(t *testing.T) (*ChallengeSecretRedeliverer, *redeliverySourceStub, *redeliveryStoreStub,
	*runtimeKeyResolverStub, edgepublish.ChallengeRedelivery) {
	t.Helper()
	item := edgepublish.ChallengeRedelivery{ScopeID: uuid.New(), NodeID: uuid.New(), PolicyID: uuid.New(), SiteID: uuid.New(),
		PolicyVersion: 7, OriginConfigVersionID: uuid.New(), AccountableUserID: uuid.New(), Attempt: 1,
		Deadline: time.Now().Add(15 * time.Minute).UTC().Truncate(time.Microsecond), IdempotencyKey: "challenge-redelivery." + uuid.NewString()}
	snapshot := validRuntimePublishRequest(item.PolicyID, item.ScopeID, uuid.New(), item.SiteID).Policy
	snapshot.Revision = item.PolicyVersion
	keys := &runtimeKeyResolverStub{keys: ResolvedKeys{Current: ArtifactSecret{KeyID: "challenge-current",
		Secret: bytes.Repeat([]byte{7}, 32)}}}
	// The origin is what the publication stored: the same policy document.
	material := buildArtifactMaterial(snapshot, keys.keys)
	origin, err := json.Marshal(material.Policy)
	if err != nil {
		t.Fatal(err)
	}
	source := &redeliverySourceStub{origin: origin, generator: edgepublish.ChallengeSecretGeneratorName, snapshot: snapshot}
	store := &redeliveryStoreStub{t: t, rollout: uuid.New()}
	signer := artifactTestSigner{id: "challenge-signing-v1", private: ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x31}, ed25519.SeedSize))}
	producer, err := NewArtifactProducer(signer)
	if err != nil {
		t.Fatal(err)
	}
	redeliverer, err := NewChallengeSecretRedeliverer(source, keys, store, producer, RedeliveryPolicy{
		HealthCheck: edgedeployment.HealthCheckPolicy{ActivationTimeout: 30 * time.Second, ObservationWindow: 5 * time.Second,
			RequiredConsecutiveSuccesses: 2},
	})
	if err != nil {
		t.Fatal(err)
	}
	return redeliverer, source, store, keys, item
}

// The redelivered rollout carries the published policy document byte for
// byte, to the one node, as the accountable publisher's system rollout.
func TestChallengeSecretRedeliveryRebuildsThePublishedDocument(t *testing.T) {
	redeliverer, source, store, _, item := redeliveryFixture(t)
	rolloutID, err := redeliverer.RedeliverChallengeSecretTx(t.Context(), nil, item)
	if err != nil {
		t.Fatal(err)
	}
	request := store.request
	digest := sha256.Sum256(source.origin)
	if rolloutID != store.rollout || store.calls != 1 || request.ConfigurationScopeID != item.ScopeID ||
		request.AccountableUserID != item.AccountableUserID || len(request.NodeIDs) != 1 || request.NodeIDs[0] != item.NodeID ||
		!bytes.Equal(request.CanonicalSnapshot, source.origin) || request.PayloadDigest != digest ||
		request.GeneratorName != edgepublish.ChallengeSecretGeneratorName || request.IdempotencyKey != item.IdempotencyKey ||
		!request.Deadline.Equal(item.Deadline) || request.Reason != "challenge_redelivery" ||
		len(request.RequiredCapabilities) != 2 || request.HealthCheck.RequiredConsecutiveSuccesses != 2 {
		t.Fatalf("rollout %v request %+v", rolloutID, request)
	}
	if store.artifact.RecipientKeyID == nil || len(store.artifact.WireBytes) == 0 {
		t.Fatalf("artifact not built: %+v", store.artifact)
	}
}

// What cannot be rebuilt exactly is unrecoverable (no retry, no rollout):
// another document (the key facts changed), a foreign or missing origin.
func TestChallengeSecretRedeliveryRefusesWhatItCannotRebuild(t *testing.T) {
	for name, mutate := range map[string]func(*redeliverySourceStub, *runtimeKeyResolverStub){
		"document changed": func(source *redeliverySourceStub, _ *runtimeKeyResolverStub) {
			source.origin = bytes.Replace(source.origin, []byte(`"challenge-current"`), []byte(`"challenge-rotated"`), 1)
		},
		"foreign origin": func(source *redeliverySourceStub, _ *runtimeKeyResolverStub) {
			source.generator = "certificate-publication"
		},
		"origin gone": func(source *redeliverySourceStub, _ *runtimeKeyResolverStub) { source.err = ErrRedeliveryOriginMissing },
	} {
		t.Run(name, func(t *testing.T) {
			redeliverer, source, store, keys, item := redeliveryFixture(t)
			mutate(source, keys)
			if _, err := redeliverer.RedeliverChallengeSecretTx(t.Context(), nil, item); !errors.Is(err,
				edgepublish.ErrChallengeRedeliveryUnrecoverable) || store.calls != 0 {
				t.Fatalf("err=%v store calls=%d", err, store.calls)
			}
		})
	}
	// An unavailable key and a rollout store failure (another deployment in
	// flight) are retried.
	redeliverer, _, store, keys, item := redeliveryFixture(t)
	keys.err = ErrKeyUnavailable
	if _, err := redeliverer.RedeliverChallengeSecretTx(t.Context(), nil, item); !errors.Is(err, ErrKeyUnavailable) ||
		errors.Is(err, edgepublish.ErrChallengeRedeliveryUnrecoverable) || store.calls != 0 {
		t.Fatalf("key unavailable: %v (store calls %d)", err, store.calls)
	}
	keys.err = nil
	store.err = edgedeployment.ErrNodeDeploymentActive
	if _, err := redeliverer.RedeliverChallengeSecretTx(t.Context(), nil, item); err == nil ||
		errors.Is(err, edgepublish.ErrChallengeRedeliveryUnrecoverable) {
		t.Fatalf("store failure: %v", err)
	}
}
