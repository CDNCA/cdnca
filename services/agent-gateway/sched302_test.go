package gateway

import (
	"crypto/sha256"
	"encoding/base64"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/edgeconfig/sched302"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const sched302TestNode = "00000000-0000-4000-8000-0000000000a0"

func sched302TestTable(t *testing.T, nodeID string, revision uint64) *agentv1.Sched302Table {
	t.Helper()
	encoded, err := sched302.Encode(sched302.Table{Schema: sched302.TableSchema, NodeID: nodeID, Revision: revision,
		GeneratedAt: time.Now().Unix(), Sites: []sched302.TableSite{{SiteID: "11111111-1111-4111-8111-111111111111",
			Hosts: []string{"dl.example.test"}, Key: base64.RawURLEncoding.EncodeToString(make([]byte, 32)),
			Candidates: []sched302.Candidate{}}}})
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(encoded)
	return &agentv1.Sched302Table{
		Event:  &commonv1.EventMetadata{EventId: "018f47a2-5b9c-7d31-8a60-104c9c0b7101", RequestId: "018f47a2-5b9c-7d31-8a60-104c9c0b7102", OccurredTime: timestamppb.Now()},
		Schema: agentv1.Sched302Schema_SCHED302_SCHEMA_V1, NodeId: nodeID, Revision: revision, TableJson: encoded, TableSha256: digest[:],
		SignatureAlgorithm: agentv1.ArtifactSignatureAlgorithm_ARTIFACT_SIGNATURE_ALGORITHM_ED25519, SigningKeyId: "k1", Signature: []byte{1},
	}
}

func TestValidateSched302Table(t *testing.T) {
	if err := validateSched302Table(sched302TestTable(t, sched302TestNode, 4), sched302TestNode); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*agentv1.Sched302Table){
		"other node":   func(table *agentv1.Sched302Table) { table.NodeId = "00000000-0000-4000-8000-0000000000b0" },
		"revision":     func(table *agentv1.Sched302Table) { table.Revision = 5 },
		"digest":       func(table *agentv1.Sched302Table) { table.TableSha256[0] ^= 1 },
		"unsigned":     func(table *agentv1.Sched302Table) { table.Signature = nil },
		"schema":       func(table *agentv1.Sched302Table) { table.Schema = agentv1.Sched302Schema_SCHED302_SCHEMA_UNSPECIFIED },
		"body binding": func(table *agentv1.Sched302Table) { *table = *sched302TestTable(t, "00000000-0000-4000-8000-0000000000b0", 4); table.NodeId = sched302TestNode },
	} {
		table := proto.Clone(sched302TestTable(t, sched302TestNode, 4)).(*agentv1.Sched302Table)
		mutate(table)
		if err := validateSched302Table(table, sched302TestNode); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	if sched302CapabilityFromFeatures([]*agentv1.Capability{{Name: agentv1.CapabilityName_CAPABILITY_NAME_SCHED302, ApiVersion: 2}}) {
		t.Fatal("unknown sched302 version negotiated")
	}
}
