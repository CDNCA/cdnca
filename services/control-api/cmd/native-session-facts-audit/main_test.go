package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/url"
	"strings"
	"testing"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	controlv1 "github.com/cdnca/cdnca/proto/gen/go/controlinternal/v1"
	"github.com/cdnca/cdnca/services/control-api/internal/nodeidentity"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
)

func TestRunSessionFactsAudit(t *testing.T) {
	base := auditInputFixture(t)
	encoded, err := json.Marshal(base)
	if err != nil {
		t.Fatal(err)
	}
	t.Run("complete-bound-receipt", func(t *testing.T) {
		var output bytes.Buffer
		if err := runSessionFactsAudit(bytes.NewReader(encoded), &output); err != nil {
			t.Fatal(err)
		}
		var value map[string]any
		if err := json.Unmarshal(output.Bytes(), &value); err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(encoded)
		if len(value) != 8 || value["input_sha256"] != hex.EncodeToString(sum[:]) || value["schema"] != "cdnca.node-session-facts-audit-result/v1" || value["operation_id"] != base["operation_id"] || value["candidate_commit"] != base["candidate_commit"] || value["candidate_tree"] != base["candidate_tree"] || value["window_started_at"] != base["window_started_at"] || value["snapshot_at"] != base["snapshot_at"] {
			t.Fatal("receipt missing exact input/operation/candidate binding")
		}
		rows, ok := value["rows"].([]any)
		if !ok || len(rows) != 1 {
			t.Fatal("missing ordered receipt")
		}
		row := rows[0].(map[string]any)
		expected := base["rows"].([]any)[0].(map[string]any)["evidence"].(nodeidentity.SessionFactEvidence)
		if len(row) != 7 || row["node_id"] != expected.NodeID.String() || row["session_epoch"] != float64(expected.SessionEpoch) ||
			row["facts_sha256"] != hex.EncodeToString(expected.FactsSHA256) || row["capabilities_sha256"] != hex.EncodeToString(expected.CapabilitiesSHA256) ||
			row["agent_version"] != "1.0.22" || row["build_id"] != "build" || row["row_sha256"] != strings.Repeat("1", 64) {
			t.Fatal("wrong facts summary")
		}
	})
	for name, mutate := range map[string]func(map[string]any){
		"unknown-top":            func(v map[string]any) { v["unknown"] = true },
		"case-insensitive-key":   func(v map[string]any) { v["Schema"] = v["schema"]; delete(v, "schema") },
		"wrong-schema":           func(v map[string]any) { v["schema"] = "other" },
		"invalid-operation":      func(v map[string]any) { v["operation_id"] = "release" },
		"noncanonical-operation": func(v map[string]any) { v["operation_id"] = "AAAAAAAA-1111-4111-8111-111111111111" },
		"invalid-commit":         func(v map[string]any) { v["candidate_commit"] = "short" },
		"upper-tree":             func(v map[string]any) { v["candidate_tree"] = strings.Repeat("A", 40) },
		"non-UTC":                func(v map[string]any) { v["snapshot_at"] = "2025-01-01T00:00:00+00:00" },
		"reverse-window":         func(v map[string]any) { v["window_started_at"] = "2025-01-02T00:00:00Z" },
		"outside-window": func(v map[string]any) {
			v["window_started_at"] = "2025-01-01T00:00:01Z"
			v["snapshot_at"] = "2025-01-01T00:00:02Z"
		},
		"missing-rows":                         func(v map[string]any) { delete(v, "rows") },
		"null-rows":                            func(v map[string]any) { v["rows"] = nil },
		"duplicate-row":                        func(v map[string]any) { v["rows"] = append(v["rows"].([]any), v["rows"].([]any)[0]) },
		"invalid-second-row-no-partial-output": func(v map[string]any) { v["rows"] = append(v["rows"].([]any), map[string]any{"node_id": "invalid"}) },
		"too-many-rows":                        func(v map[string]any) { v["rows"] = make([]any, 1001) },
		"row-node-mismatch":                    func(v map[string]any) { v["rows"].([]any)[0].(map[string]any)["node_id"] = uuid.NewString() },
		"row-epoch-mismatch":                   func(v map[string]any) { v["rows"].([]any)[0].(map[string]any)["session_epoch"] = 2 },
		"bad-row-sha":                          func(v map[string]any) { v["rows"].([]any)[0].(map[string]any)["row_sha256"] = "bad" },
		"null-epoch":                           func(v map[string]any) { v["rows"].([]any)[0].(map[string]any)["session_epoch"] = nil },
		"overflow-epoch": func(v map[string]any) {
			v["rows"].([]any)[0].(map[string]any)["session_epoch"] = json.Number("18446744073709551616")
		},
		"negative-epoch":        func(v map[string]any) { v["rows"].([]any)[0].(map[string]any)["session_epoch"] = -1 },
		"fractional-epoch":      func(v map[string]any) { v["rows"].([]any)[0].(map[string]any)["session_epoch"] = 1.5 },
		"known-key-wrong-level": func(v map[string]any) { v["registered_at"] = "2025-01-01T00:00:00Z" },
		"unknown-evidence": func(v map[string]any) {
			v["rows"].([]any)[0].(map[string]any)["evidence"].(map[string]any)["unknown"] = true
		},
		"noncanonical-base64": func(v map[string]any) {
			e := v["rows"].([]any)[0].(map[string]any)["evidence"].(map[string]any)
			e["certificate_sha256"] = e["certificate_sha256"].(string) + "\n"
		},
		"unpadded-base64": func(v map[string]any) {
			e := v["rows"].([]any)[0].(map[string]any)["evidence"].(map[string]any)
			e["certificate_sha256"] = strings.TrimRight(e["certificate_sha256"].(string), "=")
		},
		"noncanonical-evidence-node": func(v map[string]any) {
			v["rows"].([]any)[0].(map[string]any)["evidence"].(map[string]any)["node_id"] = "AAAAAAAA-1111-4111-8111-111111111111"
		},
		"noncanonical-evidence-time": func(v map[string]any) {
			v["rows"].([]any)[0].(map[string]any)["evidence"].(map[string]any)["registered_at"] = "2025-01-01T00:00:00.000Z"
		},
		"missing-zero-valued-field": func(v map[string]any) {
			delete(v["rows"].([]any)[0].(map[string]any)["evidence"].(map[string]any), "selected_protocol_minor")
		},
		"invalid-certificate": func(v map[string]any) {
			v["rows"].([]any)[0].(map[string]any)["evidence"].(map[string]any)["leaf_certificate_pem"] = "bm90LWNlcnQ="
		},
	} {
		t.Run(name, func(t *testing.T) {
			var input map[string]any
			if err := json.Unmarshal(encoded, &input); err != nil {
				t.Fatal(err)
			}
			mutate(input)
			data, err := json.Marshal(input)
			if err != nil {
				t.Fatal(err)
			}
			var output bytes.Buffer
			if err := runSessionFactsAudit(bytes.NewReader(data), &output); err == nil || output.Len() != 0 {
				t.Fatal("unsafe input produced successful or partial receipt")
			}
		})
	}
	for _, field := range []string{"node_id", "session_epoch", "registered_at", "selected_protocol_major", "selected_protocol_minor", "artifact_key_id",
		"facts_snapshot", "facts_sha256", "capabilities_snapshot", "capabilities_sha256", "certificate_sha256", "certificate_serial_number",
		"leaf_certificate_pem", "ca_certificate_pem", "ca_certificate_sha256", "artifact_public_key", "artifact_public_key_sha256"} {
		for _, missing := range []bool{true, false} {
			t.Run("required-evidence/"+field+"/missing="+fmt.Sprint(missing), func(t *testing.T) {
				var input map[string]any
				if err := json.Unmarshal(encoded, &input); err != nil {
					t.Fatal(err)
				}
				evidence := input["rows"].([]any)[0].(map[string]any)["evidence"].(map[string]any)
				if missing {
					delete(evidence, field)
				} else {
					evidence[field] = nil
				}
				data, _ := json.Marshal(input)
				var output bytes.Buffer
				if err := runSessionFactsAudit(bytes.NewReader(data), &output); err == nil || output.Len() != 0 {
					t.Fatal("missing/null evidence accepted")
				}
			})
		}
	}
	for name, data := range map[string][]byte{
		"duplicate-top-key":    bytes.Replace(encoded, []byte(`"schema":`), []byte(`"schema":"shadow","schema":`), 1),
		"duplicate-nested-key": bytes.Replace(encoded, []byte(`"node_id":`), []byte(`"node_id":"shadow","node_id":`), 1),
		"trailing-value":       append(bytes.Clone(encoded), []byte(` {}`)...),
		"too-deep":             []byte(strings.Repeat("[", 18) + "0" + strings.Repeat("]", 18)),
		"oversized":            bytes.Repeat([]byte(" "), (16<<20)+1),
	} {
		t.Run(name, func(t *testing.T) {
			var output bytes.Buffer
			if err := runSessionFactsAudit(bytes.NewReader(data), &output); err == nil || output.Len() != 0 {
				t.Fatal("invalid framing accepted")
			}
		})
	}
	t.Run("ordered-rows-and-exact-input-bytes", func(t *testing.T) {
		input := auditInputFixture(t)
		second := auditInputFixture(t)["rows"].([]any)[0]
		input["rows"] = append(input["rows"].([]any), second)
		data, _ := json.Marshal(input)
		data = append([]byte(" \n"), data...)
		var output bytes.Buffer
		if err := runSessionFactsAudit(bytes.NewReader(data), &output); err != nil {
			t.Fatal(err)
		}
		var receipt struct {
			InputSHA256 string `json:"input_sha256"`
			Rows        []struct {
				NodeID string `json:"node_id"`
			} `json:"rows"`
		}
		if err := json.Unmarshal(output.Bytes(), &receipt); err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(data)
		if receipt.InputSHA256 != hex.EncodeToString(sum[:]) || len(receipt.Rows) != 2 {
			t.Fatal("not bound to exact bytes or row count")
		}
		for i, row := range input["rows"].([]any) {
			if receipt.Rows[i].NodeID != row.(map[string]any)["node_id"] {
				t.Fatal("row order changed")
			}
		}
	})
	t.Run("empty-does-not-prove-online", func(t *testing.T) {
		base["rows"] = []any{}
		data, _ := json.Marshal(base)
		var output bytes.Buffer
		if err := runSessionFactsAudit(bytes.NewReader(data), &output); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(output.String(), `"rows":[]`) || strings.Contains(output.String(), `"pass"`) {
			t.Fatal("empty receipt claimed online/authorization")
		}
	})
}

func auditInputFixture(t *testing.T) map[string]any {
	t.Helper()
	now := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	node := uuid.New()
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{2}, 32))
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "audit test CA"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	uri, _ := url.Parse(nodeidentity.NodeSPIFFEPrefix + node.String())
	leaf := &x509.Certificate{SerialNumber: big.NewInt(10), NotBefore: ca.NotBefore, NotAfter: ca.NotAfter, URIs: []*url.URL{uri}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	leafDER, err := x509.CreateCertificate(rand.Reader, leaf, ca, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	certHash, caHash := sha256.Sum256(leafDER), sha256.Sum256(caDER)
	public := bytes.Repeat([]byte{7}, 32)
	publicHash := sha256.Sum256(public)
	keyID := "x25519:" + hex.EncodeToString(publicHash[:])
	facts := &controlv1.GatewaySessionFactsV1{SchemaVersion: 1, NodeId: node.String(), SessionEpoch: 1, CertificateSha256: certHash[:], SelectedProtocolVersion: &commonv1.ProtocolVersion{Major: 1}, ArtifactEncryptionKeyId: keyID, Capabilities: &agentv1.AgentCapabilities{AgentVersion: "1.0.22", BuildId: "build", OperatingSystem: "linux", Architecture: "amd64", Features: []*agentv1.Capability{{Name: agentv1.CapabilityName_CAPABILITY_NAME_EDGE_UPGRADE, ApiVersion: 1}}}}
	factsBytes, _ := (proto.MarshalOptions{Deterministic: true}).Marshal(facts)
	caps, _ := (proto.MarshalOptions{Deterministic: true}).Marshal(facts.Capabilities)
	factsHash, capsHash := sha256.Sum256(factsBytes), sha256.Sum256(caps)
	evidence := nodeidentity.SessionFactEvidence{NodeID: node, SessionEpoch: 1, RegisteredAt: now, SelectedProtocolMajor: 1, ArtifactKeyID: keyID, FactsSnapshot: factsBytes, FactsSHA256: factsHash[:], CapabilitiesSnapshot: caps, CapabilitiesSHA256: capsHash[:], CertificateSHA256: certHash[:], CertificateSerialNumber: "a", LeafCertificatePEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}), CACertificatePEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), CACertificateSHA256: caHash[:], ArtifactPublicKey: public, ArtifactPublicKeySHA256: publicHash[:]}
	return map[string]any{"schema": "cdnca.node-session-facts-audit/v1", "operation_id": uuid.NewString(), "candidate_commit": strings.Repeat("a", 40), "candidate_tree": strings.Repeat("b", 40), "window_started_at": now.Add(-time.Minute).Format(time.RFC3339Nano), "snapshot_at": now.Format(time.RFC3339Nano), "rows": []any{map[string]any{"node_id": node.String(), "session_epoch": 1, "row_sha256": strings.Repeat("1", 64), "evidence": evidence}}}
}
