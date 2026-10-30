//go:build integration

package acmehttp01

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"testing"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/cdnca/cdnca/services/control-api/internal/edgeartifact"
	"github.com/google/uuid"
)

// ADR-0003 purpose binding: a draining node that owes a cleanup and serves
// nothing (held while another node serves) gets a CLEANUP_ONLY command whose signed artifact says so; only that
// artifact is served to a session without deployments (cleanup_only fetch);
// an APPLY artifact is refused to it; the healthy receipt resolves the debt.
func TestNodeHTTP01CleanupOnlyPurposeBinding(t *testing.T) {
	f := newNodeFixture(t, true, true)
	n1 := f.nodes[1]
	a := f.challenge(t, "a.example.test")
	if err := f.store.PublishChallenge(t.Context(), a); err != nil {
		t.Fatal(err)
	}
	f.healthyAll(t)
	_, private, _ := ed25519.GenerateKey(nil)
	config := DefaultNodeArtifactConfig()
	config.Clock = f.clock.Now
	artifacts, err := NewNodeArtifactStore(f.store, testSigner{private}, config)
	if err != nil {
		t.Fatal(err)
	}
	// Draining alone still serves DNS; held while another node serves, it
	// is out of every published endpoint (globally non-serving).
	f.setAdmin(t, n1, "draining")
	f.hold(t, n1, true)
	f.reconcile(t)
	deliveries := f.deliver(t)
	cleanup := deliveries[n1]
	if cleanup.GenerationID == uuid.Nil {
		t.Fatalf("draining node got no delivery: %+v", deliveries)
	}
	command, err := artifacts.BuildCommand(t.Context(), cleanup)
	if err != nil {
		t.Fatal(err)
	}
	if command.Purpose != agentv1.AcmeHTTP01OverlayPurpose_ACME_HTTP01_OVERLAY_PURPOSE_CLEANUP_ONLY {
		t.Fatalf("draining node command purpose %v", command.Purpose)
	}
	request := fetchRequest(cleanup, command.Attempt)
	request.CleanupOnly = true
	chunk, err := artifacts.FetchChunk(t.Context(), request)
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		Purpose string            `json:"purpose"`
		Entries []json.RawMessage `json:"entries"`
	}
	if err := json.Unmarshal(chunk.Response.Chunk.Data, &document); err != nil ||
		document.Purpose != "cleanup_only" || len(document.Entries) != 0 {
		t.Fatalf("cleanup_only artifact %s %v", chunk.Response.Chunk.Data, err)
	}
	if !ed25519.Verify(private.Public().(ed25519.PublicKey), chunk.Response.Chunk.Data, command.Artifact.Signature) {
		t.Fatal("cleanup_only artifact signature does not cover the served bytes")
	}
	f.receipt(t, cleanup, "healthy", "")
	if got := f.debtEvents(t, "a.example.test", n1); !equalStrings(got, "opened:member_removed", "scheduled", "resolved_cleanup") {
		t.Fatalf("draining node debt %v", got)
	}
}

// An active node's generation is APPLY: its artifact names no purpose (the
// bytes stay what they were before purposes existed) and a session without
// deployments (cleanup_only fetch) is refused it.
func TestNodeHTTP01ApplyCommandCarriesPurpose(t *testing.T) {
	f := newNodeFixture(t, true)
	a := f.challenge(t, "a.example.test")
	if err := f.store.PublishChallenge(t.Context(), a); err != nil {
		t.Fatal(err)
	}
	_, private, _ := ed25519.GenerateKey(nil)
	config := DefaultNodeArtifactConfig()
	config.Clock = f.clock.Now
	artifacts, err := NewNodeArtifactStore(f.store, testSigner{private}, config)
	if err != nil {
		t.Fatal(err)
	}
	delivery := f.deliver(t)[f.nodes[0]]
	command, err := artifacts.BuildCommand(t.Context(), delivery)
	if err != nil {
		t.Fatal(err)
	}
	if command.Purpose != agentv1.AcmeHTTP01OverlayPurpose_ACME_HTTP01_OVERLAY_PURPOSE_APPLY {
		t.Fatalf("apply command purpose %v", command.Purpose)
	}
	chunk, err := artifacts.FetchChunk(t.Context(), fetchRequest(delivery, command.Attempt))
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]json.RawMessage
	if err := json.Unmarshal(chunk.Response.Chunk.Data, &document); err != nil {
		t.Fatal(err)
	}
	if _, found := document["purpose"]; found {
		t.Fatalf("apply artifact names a purpose: %s", chunk.Response.Chunk.Data)
	}
	restricted := fetchRequest(delivery, command.Attempt)
	restricted.CleanupOnly = true
	if _, err := artifacts.FetchChunk(t.Context(), restricted); !errors.Is(err, edgeartifact.ErrDeploymentIneligible) {
		t.Fatalf("apply artifact served to a cleanup_only session: %v", err)
	}
}
