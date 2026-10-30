// Command native-session-facts-audit is a publisher-side stdin verifier. It is
// not a service, does not connect to a database and grants no upgrade authority.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/nodeidentity"
	"github.com/google/uuid"
)

func main() {
	if len(os.Args) != 1 || runSessionFactsAudit(os.Stdin, os.Stdout) != nil {
		fmt.Fprintln(os.Stderr, "session facts evidence rejected")
		os.Exit(1)
	}
}

func runSessionFactsAudit(input io.Reader, output io.Writer) error {
	const limit = 16 << 20
	data, err := io.ReadAll(io.LimitReader(input, limit+1))
	if err != nil || len(data) > limit {
		return nodeidentity.ErrInvalidInput
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := auditJSONValue(decoder, 0); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return nodeidentity.ErrInvalidInput
	}
	var request struct {
		Schema          string `json:"schema"`
		OperationID     string `json:"operation_id"`
		CandidateCommit string `json:"candidate_commit"`
		CandidateTree   string `json:"candidate_tree"`
		WindowStartedAt string `json:"window_started_at"`
		SnapshotAt      string `json:"snapshot_at"`
		Rows            []struct {
			NodeID       string          `json:"node_id"`
			SessionEpoch uint64          `json:"session_epoch"`
			RowSHA256    string          `json:"row_sha256"`
			Evidence     json.RawMessage `json:"evidence"`
		} `json:"rows"`
	}
	decoder = json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		return nodeidentity.ErrInvalidInput
	}
	operation, err := uuid.Parse(request.OperationID)
	start, startErr := canonicalAuditUTC(request.WindowStartedAt)
	snapshot, snapshotErr := canonicalAuditUTC(request.SnapshotAt)
	if request.Schema != "cdnca.node-session-facts-audit/v1" || err != nil || operation == uuid.Nil || operation.String() != request.OperationID ||
		!canonicalAuditHex(request.CandidateCommit, 40) || !canonicalAuditHex(request.CandidateTree, 40) ||
		startErr != nil || snapshotErr != nil || start.After(snapshot) || request.Rows == nil || len(request.Rows) > 1000 {
		return nodeidentity.ErrInvalidInput
	}
	type receiptRow struct {
		NodeID             string `json:"node_id"`
		SessionEpoch       uint64 `json:"session_epoch"`
		RowSHA256          string `json:"row_sha256"`
		FactsSHA256        string `json:"facts_sha256"`
		CapabilitiesSHA256 string `json:"capabilities_sha256"`
		AgentVersion       string `json:"agent_version"`
		BuildID            string `json:"build_id"`
	}
	rows := make([]receiptRow, 0, len(request.Rows))
	seen := make(map[struct {
		node  uuid.UUID
		epoch uint64
	}]bool, len(request.Rows))
	for _, row := range request.Rows {
		node, err := uuid.Parse(row.NodeID)
		if err != nil || node == uuid.Nil || node.String() != row.NodeID || row.SessionEpoch == 0 || !canonicalAuditHex(row.RowSHA256, 64) {
			return nodeidentity.ErrInvalidInput
		}
		key := struct {
			node  uuid.UUID
			epoch uint64
		}{node, row.SessionEpoch}
		if seen[key] {
			return nodeidentity.ErrInvalidInput
		}
		seen[key] = true
		evidence, err := decodeAuditEvidence(row.Evidence)
		if err != nil || evidence.NodeID != node || evidence.SessionEpoch != row.SessionEpoch || evidence.RegisteredAt.Before(start) || evidence.RegisteredAt.After(snapshot) {
			return nodeidentity.ErrInvalidInput
		}
		facts, err := nodeidentity.VerifySessionFactEvidence(evidence)
		if err != nil {
			return err
		}
		rows = append(rows, receiptRow{NodeID: row.NodeID, SessionEpoch: row.SessionEpoch, RowSHA256: row.RowSHA256,
			FactsSHA256: hex.EncodeToString(evidence.FactsSHA256), CapabilitiesSHA256: hex.EncodeToString(evidence.CapabilitiesSHA256),
			AgentVersion: facts.Capabilities.AgentVersion, BuildID: facts.Capabilities.BuildId})
	}
	digest := sha256.Sum256(data)
	receipt := struct {
		Schema          string       `json:"schema"`
		OperationID     string       `json:"operation_id"`
		CandidateCommit string       `json:"candidate_commit"`
		CandidateTree   string       `json:"candidate_tree"`
		WindowStartedAt string       `json:"window_started_at"`
		SnapshotAt      string       `json:"snapshot_at"`
		InputSHA256     string       `json:"input_sha256"`
		Rows            []receiptRow `json:"rows"`
	}{"cdnca.node-session-facts-audit-result/v1", request.OperationID, request.CandidateCommit, request.CandidateTree,
		request.WindowStartedAt, request.SnapshotAt, hex.EncodeToString(digest[:]), rows}
	encoded, err := json.Marshal(receipt)
	if err != nil {
		return err
	}
	_, err = output.Write(append(encoded, '\n'))
	return err
}

// Check the entire JSON before typed decoding: encoding/json otherwise accepts
// duplicate keys and case-insensitive field names. Typed decoding then rejects
// known names placed in the wrong object.
func auditJSONValue(decoder *json.Decoder, depth int) error {
	if depth > 16 {
		return nodeidentity.ErrInvalidInput
	}
	token, err := decoder.Token()
	if err != nil {
		return nodeidentity.ErrInvalidInput
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	if delim != '{' && delim != '[' {
		return nodeidentity.ErrInvalidInput
	}
	seen := make(map[string]bool)
	for decoder.More() {
		if delim == '{' {
			keyToken, err := decoder.Token()
			key, ok := keyToken.(string)
			if err != nil || !ok || seen[key] {
				return nodeidentity.ErrInvalidInput
			}
			switch key {
			case "schema", "operation_id", "candidate_commit", "candidate_tree", "window_started_at", "snapshot_at", "rows",
				"node_id", "session_epoch", "row_sha256", "evidence", "registered_at", "selected_protocol_major", "selected_protocol_minor",
				"artifact_key_id", "facts_snapshot", "facts_sha256", "capabilities_snapshot", "capabilities_sha256", "certificate_sha256",
				"certificate_serial_number", "leaf_certificate_pem", "ca_certificate_pem", "ca_certificate_sha256", "artifact_public_key", "artifact_public_key_sha256":
			default:
				return nodeidentity.ErrInvalidInput
			}
			seen[key] = true
		}
		if err := auditJSONValue(decoder, depth+1); err != nil {
			return err
		}
	}
	end, err := decoder.Token()
	if err != nil || (delim == '{' && end != json.Delim('}')) || (delim == '[' && end != json.Delim(']')) {
		return nodeidentity.ErrInvalidInput
	}
	return nil
}

func canonicalAuditUTC(value string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil || parsed.IsZero() || parsed.UTC().Format(time.RFC3339Nano) != value {
		return time.Time{}, nodeidentity.ErrInvalidInput
	}
	return parsed, nil
}

func canonicalAuditHex(value string, length int) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(value) == length && hex.EncodeToString(decoded) == value
}

func decodeAuditEvidence(raw json.RawMessage) (nodeidentity.SessionFactEvidence, error) {
	var fields map[string]json.RawMessage
	var evidence nodeidentity.SessionFactEvidence
	if err := json.Unmarshal(raw, &fields); err != nil || len(fields) != 17 {
		return evidence, nodeidentity.ErrInvalidInput
	}
	for _, key := range []string{"node_id", "session_epoch", "registered_at", "selected_protocol_major", "selected_protocol_minor", "artifact_key_id",
		"facts_snapshot", "facts_sha256", "capabilities_snapshot", "capabilities_sha256", "certificate_sha256", "certificate_serial_number",
		"leaf_certificate_pem", "ca_certificate_pem", "ca_certificate_sha256", "artifact_public_key", "artifact_public_key_sha256"} {
		value, ok := fields[key]
		if !ok || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return evidence, nodeidentity.ErrInvalidInput
		}
	}
	for _, key := range []string{"facts_snapshot", "facts_sha256", "capabilities_snapshot", "capabilities_sha256", "certificate_sha256",
		"leaf_certificate_pem", "ca_certificate_pem", "ca_certificate_sha256", "artifact_public_key", "artifact_public_key_sha256"} {
		var encoded string
		if err := json.Unmarshal(fields[key], &encoded); err != nil {
			return evidence, nodeidentity.ErrInvalidInput
		}
		decoded, err := base64.StdEncoding.Strict().DecodeString(encoded)
		if err != nil || base64.StdEncoding.EncodeToString(decoded) != encoded {
			return evidence, nodeidentity.ErrInvalidInput
		}
	}
	var registeredAt, nodeID string
	if err := json.Unmarshal(fields["registered_at"], &registeredAt); err != nil {
		return evidence, nodeidentity.ErrInvalidInput
	}
	if _, err := canonicalAuditUTC(registeredAt); err != nil {
		return evidence, err
	}
	if err := json.Unmarshal(fields["node_id"], &nodeID); err != nil {
		return evidence, nodeidentity.ErrInvalidInput
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&evidence); err != nil || evidence.NodeID.String() != nodeID {
		return evidence, nodeidentity.ErrInvalidInput
	}
	return evidence, nil
}
