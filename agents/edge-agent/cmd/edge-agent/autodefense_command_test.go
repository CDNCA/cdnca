package main

import (
	"crypto/ed25519"
	"errors"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/edgeconfig/autodefense"
	"github.com/google/uuid"
)

type autoDefenseLocalStub struct {
	applied  []autodefense.Snapshot
	revision uint64
	fail     error
	failures int // DeliveryFailed calls (ADR §10.2 item 5)
}

func (stub *autoDefenseLocalStub) DeliveryFailed() { stub.failures++ }

func (stub *autoDefenseLocalStub) Apply(snapshot autodefense.Snapshot) error {
	if stub.fail != nil {
		return stub.fail
	}
	stub.applied = append(stub.applied, snapshot)
	stub.revision = snapshot.Revision
	return nil
}
func (stub *autoDefenseLocalStub) AppliedRevision() uint64 { return stub.revision }
func (*autoDefenseLocalStub) Reports() <-chan []byte       { return nil }

type autoDefenseKeys struct {
	public  ed25519.PublicKey
	private ed25519.PrivateKey
}

func newAutoDefenseKeys(t *testing.T) autoDefenseKeys {
	t.Helper()
	public, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	return autoDefenseKeys{public: public, private: private}
}

func (keys autoDefenseKeys) trusted(keyID string) (ed25519.PublicKey, bool) {
	return keys.public, keyID == "edge-publish"
}

func testAutoDefensePart(t *testing.T, private ed25519.PrivateKey, nodeID string, revision uint64, part, parts uint32) []byte {
	t.Helper()
	encoded, err := autodefense.Sign(autodefense.Snapshot{Schema: autodefense.Schema, NodeID: nodeID, Revision: revision,
		Part: part, Parts: parts, IssuedAt: time.Now().Unix()}, "edge-publish", private)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func TestAutoDefenseReceiverVerifiesOrdersAndAssembles(t *testing.T) {
	keys := newAutoDefenseKeys(t)
	nodeID := uuid.NewString()
	local := &autoDefenseLocalStub{}
	receiver := newAutoDefenseReceiver(nodeID, keys.trusted, local, nil)
	if newAutoDefenseReceiver(nodeID, keys.trusted, nil, nil) != nil {
		t.Fatal("receiver without a local runtime must not exist (no AUTO_DEFENSE declared)")
	}

	// Untrusted signature, wrong node and garbage are refused with their contract codes.
	stranger := newAutoDefenseKeys(t)
	for name, want := range map[string]struct {
		encoded []byte
		code    string
	}{
		"untrusted": {testAutoDefensePart(t, stranger.private, nodeID, 5, 1, 1), autodefense.ErrorUntrusted},
		"node":      {testAutoDefensePart(t, keys.private, uuid.NewString(), 5, 1, 1), autodefense.ErrorWrongNode},
		"garbage":   {[]byte(`{"schema":"x"}`), autodefense.ErrorInvalid},
	} {
		if result := receiver.ApplyAutoDefense(want.encoded); result.Applied || result.ErrorCode != want.code {
			t.Fatalf("%s: %+v", name, result)
		}
	}
	if len(local.applied) != 0 {
		t.Fatal("refused part reached the runtime")
	}

	// Revision 5 applies; a redelivered revision 5 is applied again without touching the runtime; 4 is stale.
	if result := receiver.ApplyAutoDefense(testAutoDefensePart(t, keys.private, nodeID, 5, 1, 1)); !result.Applied || result.ErrorCode != "" {
		t.Fatalf("revision 5: %+v", result)
	}
	if result := receiver.ApplyAutoDefense(testAutoDefensePart(t, keys.private, nodeID, 5, 1, 1)); !result.Applied {
		t.Fatalf("redelivered 5: %+v", result)
	}
	if result := receiver.ApplyAutoDefense(testAutoDefensePart(t, keys.private, nodeID, 4, 1, 1)); result.Applied || result.ErrorCode != autodefense.ErrorStale {
		t.Fatalf("rollback to 4: %+v", result)
	}
	if len(local.applied) != 1 || local.applied[0].Revision != 5 {
		t.Fatalf("runtime got %d snapshots", len(local.applied))
	}

	// The runtime's persisted revision counts too (restart: the receiver is new, the runtime is not).
	restarted := newAutoDefenseReceiver(nodeID, keys.trusted, local, nil)
	if result := restarted.ApplyAutoDefense(testAutoDefensePart(t, keys.private, nodeID, 3, 1, 1)); result.ErrorCode != autodefense.ErrorStale {
		t.Fatalf("rollback after restart: %+v", result)
	}

	// Multi part revision 7: part 2 alone is incomplete, a newer revision 8 part supersedes it, both parts
	// of 8 apply it, a late part of 7 is stale.
	if result := receiver.ApplyAutoDefense(testAutoDefensePart(t, keys.private, nodeID, 7, 2, 2)); result.ErrorCode != autodefense.ErrorIncomplete {
		t.Fatalf("7/2: %+v", result)
	}
	if result := receiver.ApplyAutoDefense(testAutoDefensePart(t, keys.private, nodeID, 8, 2, 2)); result.ErrorCode != autodefense.ErrorIncomplete {
		t.Fatalf("8/2: %+v", result)
	}
	if result := receiver.ApplyAutoDefense(testAutoDefensePart(t, keys.private, nodeID, 7, 1, 2)); result.ErrorCode != autodefense.ErrorStale {
		t.Fatalf("late 7/1: %+v", result)
	}
	if result := receiver.ApplyAutoDefense(testAutoDefensePart(t, keys.private, nodeID, 8, 1, 2)); !result.Applied {
		t.Fatalf("8/1: %+v", result)
	}
	if len(local.applied) != 2 || local.applied[1].Revision != 8 || local.applied[1].Parts != 1 {
		t.Fatalf("assembled = %+v", local.applied)
	}

	// A runtime failure keeps the previous revision and reports runtime_unavailable.
	local.fail = errors.New("disk full")
	if result := receiver.ApplyAutoDefense(testAutoDefensePart(t, keys.private, nodeID, 9, 1, 1)); result.ErrorCode != autodefense.ErrorRuntime {
		t.Fatalf("runtime failure: %+v", result)
	}
	if local.revision != 8 {
		t.Fatalf("runtime revision = %d", local.revision)
	}
	local.fail = nil
	if result := receiver.ApplyAutoDefense(testAutoDefensePart(t, keys.private, nodeID, 9, 1, 1)); !result.Applied {
		t.Fatalf("retry after failure: %+v", result)
	}
}

// ad-fix7, ADR §10.2 item 5: an untrusted, invalid or unappliable snapshot counts as a delivery failure for the
// runtime breaker; a stale or wrong node part does not.
func TestAutoDefenseReceiverCountsDeliveryFailures(t *testing.T) {
	keys := newAutoDefenseKeys(t)
	nodeID := uuid.NewString()
	local := &autoDefenseLocalStub{}
	receiver := newAutoDefenseReceiver(nodeID, keys.trusted, local, nil)
	stranger := newAutoDefenseKeys(t)
	receiver.ApplyAutoDefense(testAutoDefensePart(t, stranger.private, nodeID, 5, 1, 1))
	receiver.ApplyAutoDefense(testAutoDefensePart(t, keys.private, uuid.NewString(), 5, 1, 1))
	if local.failures != 1 {
		t.Fatalf("failures %d after untrusted + wrong node, want 1", local.failures)
	}
	local.fail = errors.New("disk full")
	receiver.ApplyAutoDefense(testAutoDefensePart(t, keys.private, nodeID, 6, 1, 1))
	if local.failures != 2 {
		t.Fatalf("failures %d after a failed Apply, want 2", local.failures)
	}
	local.fail = nil
	receiver.ApplyAutoDefense(testAutoDefensePart(t, keys.private, nodeID, 7, 1, 1))
	receiver.ApplyAutoDefense(testAutoDefensePart(t, keys.private, nodeID, 6, 1, 1)) // stale
	if local.failures != 2 {
		t.Fatalf("failures %d after an applied and a stale part, want 2", local.failures)
	}
}
