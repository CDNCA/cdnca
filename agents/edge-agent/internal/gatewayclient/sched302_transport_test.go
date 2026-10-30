package gatewayclient

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/edgeconfig/sched302"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
)

type recordingSched302 struct{ tables []sched302.Table }

func (runtime *recordingSched302) Apply(table sched302.Table, _ []byte) error {
	runtime.tables = append(runtime.tables, table)
	return nil
}

func TestApplySched302Table(t *testing.T) {
	const nodeID = "00000000-0000-4000-8000-0000000000a0"
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	trust, err := NewTrustStore(map[string]crypto.PublicKey{"artifact-key": publicKey})
	if err != nil {
		t.Fatal(err)
	}
	carrier := func(nodeInBody string, key ed25519.PrivateKey) *agentv1.Sched302Table {
		encoded, err := sched302.Encode(sched302.Table{Schema: sched302.TableSchema, NodeID: nodeInBody, Revision: 3,
			GeneratedAt: time.Now().Unix(), Sites: []sched302.TableSite{{SiteID: "11111111-1111-4111-8111-111111111111",
				Hosts: []string{"dl.example.test"}, Key: base64.RawURLEncoding.EncodeToString(make([]byte, 32)),
				Candidates: []sched302.Candidate{}}}})
		if err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(encoded)
		return &agentv1.Sched302Table{Schema: agentv1.Sched302Schema_SCHED302_SCHEMA_V1, NodeId: nodeID, Revision: 3,
			TableJson: encoded, TableSha256: digest[:], SignatureAlgorithm: agentv1.ArtifactSignatureAlgorithm_ARTIFACT_SIGNATURE_ALGORITHM_ED25519,
			SigningKeyId: "artifact-key", Signature: ed25519.Sign(key, encoded)}
	}
	runtime := &recordingSched302{}
	if err := applySched302Table(carrier(nodeID, privateKey), nodeID, trust, runtime); err != nil || len(runtime.tables) != 1 {
		t.Fatalf("valid table: %v %d", err, len(runtime.tables))
	}
	_, otherKey, _ := ed25519.GenerateKey(rand.Reader)
	tampered := carrier(nodeID, privateKey)
	tampered.TableJson[len(tampered.TableJson)-3] ^= 1
	unknownKey := carrier(nodeID, privateKey)
	unknownKey.SigningKeyId = "other"
	for name, table := range map[string]*agentv1.Sched302Table{
		"forged signature": carrier(nodeID, otherKey),
		"tampered body":    tampered,
		"unknown key":      unknownKey,
		"body other node":  carrier("00000000-0000-4000-8000-0000000000b0", privateKey),
	} {
		if err := applySched302Table(table, nodeID, trust, runtime); !errors.Is(err, ErrInvalidMessage) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if len(runtime.tables) != 1 {
		t.Fatalf("refused tables were applied: %d", len(runtime.tables))
	}
	if enabled, err := negotiateSched302V1(&agentv1.GatewayHello{EnabledCapabilities: []*agentv1.Capability{
		{Name: agentv1.CapabilityName_CAPABILITY_NAME_SCHED302, ApiVersion: 1}}}, nil); enabled || err == nil {
		t.Fatal("gateway enabled schedule302 for an agent without the runtime")
	}
}
