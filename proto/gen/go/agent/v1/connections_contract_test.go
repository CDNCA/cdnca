package agentv1_test

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestConnectionsV1ContractDeclaresFailClosedCarrier(t *testing.T) {
	_, testFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("could not locate contract test")
	}
	sourcePath := filepath.Join(filepath.Dir(testFile), "..", "..", "..", "..", "agent", "v1", "connections.proto")
	source, err := os.ReadFile(sourcePath)
	if err != nil {
		t.Fatalf("read connections.v1 source: %v", err)
	}
	body := string(source)
	for _, declaration := range []string{
		"syntax = \"proto3\";",
		"package agent.v1;",
		"import \"common/v1/common.proto\";",
		"import \"google/protobuf/timestamp.proto\";",
		"enum ConnectionsDependencyStateV1",
		"CONNECTIONS_DEPENDENCY_STATE_V1_READY = 1",
		"CONNECTIONS_DEPENDENCY_STATE_V1_UNKNOWN = 2",
		"CONNECTIONS_DEPENDENCY_STATE_V1_UNAVAILABLE = 3",
		"message ConnectionsMetricEnvelopeV1",
		"common.v1.EventMetadata event = 2;",
		"string tenant_id = 3;",
		"string installation_id = 4;",
		"uint64 connections = 7;",
		"bytes canonical_event_sha256 = 8;",
		"ConnectionsDependencyStateV1 dependency_state = 9;",
		"google.protobuf.Timestamp finalized_through = 10;",
		"bytes evidence_sha256 = 11;",
		"string node_id = 13;",
		"string domain = 14;",
		"uint32 listen_port = 15;",
	} {
		if !strings.Contains(body, declaration) {
			t.Errorf("connections.v1 contract missing %q", declaration)
		}
	}
}
