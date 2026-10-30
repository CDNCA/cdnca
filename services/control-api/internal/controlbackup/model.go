package controlbackup

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"
)

const (
	ManifestSchema       = "cdnca.control-recovery/v1"
	SignedManifestSchema = "cdnca.control-recovery.signed/v1"
)

var (
	ErrInvalidManifest         = errors.New("invalid recovery manifest")
	ErrInvalidSecretReference  = errors.New("invalid secret reference")
	ErrManifestIntegrity       = errors.New("recovery manifest integrity check failed")
	ErrSchemaIncompatible      = errors.New("recovery schema is incompatible")
	ErrIdempotencyConflict     = errors.New("restore idempotency conflict")
	ErrRestorePreviouslyFailed = errors.New("restore operation previously failed")
)

var (
	identifierPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
	versionPattern    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$`)
	referencePattern  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/-]{0,255}$`)
)

type Component string

const (
	ComponentPostgreSQL Component = "postgresql"
	ComponentClickHouse Component = "clickhouse"
	ComponentJetStream  Component = "jetstream"
)

var requiredComponents = [...]Component{
	ComponentPostgreSQL,
	ComponentClickHouse,
	ComponentJetStream,
}

type SecretReference struct {
	Provider string `json:"provider"`
	Name     string `json:"name"`
	Version  string `json:"version"`
}

func (reference SecretReference) Validate() error {
	if !identifierPattern.MatchString(reference.Provider) ||
		!referencePattern.MatchString(reference.Name) ||
		!versionPattern.MatchString(reference.Version) {
		return ErrInvalidSecretReference
	}
	return nil
}

type ComponentCheckpoint struct {
	Component         Component         `json:"component"`
	BackupID          string            `json:"backup_id"`
	WriteFreezeID     string            `json:"write_freeze_id"`
	SnapshotID        string            `json:"snapshot_id"`
	Revision          uint64            `json:"revision"`
	CapturedAt        time.Time         `json:"captured_at"`
	SHA256            string            `json:"sha256"`
	SizeBytes         int64             `json:"size_bytes"`
	JetStreamTopology JetStreamTopology `json:"jetstream_topology,omitempty"`
}

type JetStreamConsumer struct {
	Stream string `json:"stream"`
	Name   string `json:"name"`
}

type JetStreamTopology struct {
	Streams   []string            `json:"streams,omitempty"`
	Consumers []JetStreamConsumer `json:"consumers,omitempty"`
}

var requiredJetStreamTopology = JetStreamTopology{
	Streams: []string{"AGENT_COMMANDS", "AGENT_DEPLOYMENT_STATUS", "AGENT_HEARTBEATS"},
	Consumers: []JetStreamConsumer{
		{Stream: "AGENT_DEPLOYMENT_STATUS", Name: "control_api_edge_status"},
		{Stream: "AGENT_HEARTBEATS", Name: "control_api_node_presence"},
		{Stream: "AGENT_DEPLOYMENT_STATUS", Name: "control_api_upgrade_status"},
		{Stream: "AGENT_COMMANDS", Name: "node_upgrade_${NODE_ID_UNDERSCORE}"},
	},
}

func RequiredJetStreamTopology() JetStreamTopology {
	return JetStreamTopology{
		Streams:   append([]string(nil), requiredJetStreamTopology.Streams...),
		Consumers: append([]JetStreamConsumer(nil), requiredJetStreamTopology.Consumers...),
	}
}

type RecoveryObjectives struct {
	ObservedRPOSeconds int64 `json:"observed_rpo_seconds"`
	TargetRPOSeconds   int64 `json:"target_rpo_seconds"`
	TargetRTOSeconds   int64 `json:"target_rto_seconds"`
}

type Manifest struct {
	Schema             string                `json:"schema"`
	BackupID           string                `json:"backup_id"`
	SourceClusterID    string                `json:"source_cluster_id"`
	AppVersion         string                `json:"app_version"`
	SchemaVersion      uint64                `json:"schema_version"`
	CreatedAt          time.Time             `json:"created_at"`
	RecoveryPointAt    time.Time             `json:"recovery_point_at"`
	WriteFreezeID      string                `json:"write_freeze_id"`
	CoreManifestSHA256 string                `json:"core_manifest_sha256"`
	EnvelopeKey        SecretReference       `json:"envelope_key"`
	Checkpoints        []ComponentCheckpoint `json:"checkpoints"`
	Objectives         RecoveryObjectives    `json:"objectives"`
}

func (manifest Manifest) Validate() error {
	if manifest.Schema != ManifestSchema ||
		!identifierPattern.MatchString(manifest.BackupID) ||
		!identifierPattern.MatchString(manifest.SourceClusterID) ||
		!versionPattern.MatchString(manifest.AppVersion) ||
		manifest.SchemaVersion == 0 || manifest.CreatedAt.IsZero() ||
		manifest.RecoveryPointAt.IsZero() || manifest.CreatedAt.Before(manifest.RecoveryPointAt) ||
		!identifierPattern.MatchString(manifest.WriteFreezeID) || !validSHA256(manifest.CoreManifestSHA256) ||
		manifest.Objectives.ObservedRPOSeconds < 0 || manifest.Objectives.TargetRPOSeconds <= 0 ||
		manifest.Objectives.TargetRTOSeconds <= 0 {
		return ErrInvalidManifest
	}
	if err := manifest.EnvelopeKey.Validate(); err != nil {
		return err
	}
	if len(manifest.Checkpoints) != len(requiredComponents) {
		return ErrInvalidManifest
	}
	seen := make(map[Component]bool, len(requiredComponents))
	earliest := manifest.Checkpoints[0].CapturedAt
	for _, checkpoint := range manifest.Checkpoints {
		if !isRequiredComponent(checkpoint.Component) || seen[checkpoint.Component] ||
			checkpoint.BackupID != manifest.BackupID || checkpoint.WriteFreezeID != manifest.WriteFreezeID ||
			!identifierPattern.MatchString(checkpoint.SnapshotID) || checkpoint.Revision == 0 ||
			checkpoint.CapturedAt.IsZero() || checkpoint.CapturedAt.After(manifest.CreatedAt) ||
			!validSHA256(checkpoint.SHA256) || checkpoint.SizeBytes <= 0 {
			return ErrInvalidManifest
		}
		if checkpoint.Component == ComponentJetStream {
			if !checkpoint.JetStreamTopology.equal(requiredJetStreamTopology) {
				return ErrInvalidManifest
			}
		} else if len(checkpoint.JetStreamTopology.Streams) != 0 || len(checkpoint.JetStreamTopology.Consumers) != 0 {
			return ErrInvalidManifest
		}
		seen[checkpoint.Component] = true
		if checkpoint.CapturedAt.Before(earliest) {
			earliest = checkpoint.CapturedAt
		}
	}
	if !manifest.RecoveryPointAt.Equal(earliest) || manifest.Objectives.ObservedRPOSeconds !=
		int64(manifest.CreatedAt.Sub(earliest)/time.Second) {
		return ErrInvalidManifest
	}
	return nil
}

func (topology JetStreamTopology) equal(expected JetStreamTopology) bool {
	if len(topology.Streams) != len(expected.Streams) || len(topology.Consumers) != len(expected.Consumers) {
		return false
	}
	for index := range expected.Streams {
		if topology.Streams[index] != expected.Streams[index] {
			return false
		}
	}
	for index := range expected.Consumers {
		if topology.Consumers[index] != expected.Consumers[index] {
			return false
		}
	}
	return true
}

type SignedManifest struct {
	Schema        string          `json:"schema"`
	Payload       json.RawMessage `json:"payload"`
	PayloadSHA256 string          `json:"payload_sha256"`
	SigningKeyID  string          `json:"signing_key_id"`
	Signature     string          `json:"signature"`
}

type ManifestExpectation struct {
	BackupID         string
	SourceClusterID  string
	AppVersion       string
	MaxSchemaVersion uint64
}

func SignManifest(manifest Manifest, signingKeyID string, privateKey ed25519.PrivateKey) (SignedManifest, error) {
	if err := manifest.Validate(); err != nil {
		return SignedManifest{}, err
	}
	if !identifierPattern.MatchString(signingKeyID) || len(privateKey) != ed25519.PrivateKeySize {
		return SignedManifest{}, ErrInvalidManifest
	}
	payload, err := json.Marshal(manifest)
	if err != nil {
		return SignedManifest{}, fmt.Errorf("marshal recovery manifest: %w", err)
	}
	digest := sha256.Sum256(payload)
	return SignedManifest{
		Schema:        SignedManifestSchema,
		Payload:       payload,
		PayloadSHA256: hex.EncodeToString(digest[:]),
		SigningKeyID:  signingKeyID,
		Signature:     base64.RawStdEncoding.EncodeToString(ed25519.Sign(privateKey, payload)),
	}, nil
}

func VerifyManifest(signed SignedManifest, publicKeys map[string]ed25519.PublicKey, expectation ManifestExpectation) (Manifest, error) {
	if signed.Schema != SignedManifestSchema || !validSHA256(signed.PayloadSHA256) ||
		!identifierPattern.MatchString(signed.SigningKeyID) || len(signed.Payload) == 0 {
		return Manifest{}, ErrManifestIntegrity
	}
	digest := sha256.Sum256(signed.Payload)
	if !strings.EqualFold(hex.EncodeToString(digest[:]), signed.PayloadSHA256) {
		return Manifest{}, ErrManifestIntegrity
	}
	publicKey := publicKeys[signed.SigningKeyID]
	signature, err := base64.RawStdEncoding.DecodeString(signed.Signature)
	if err != nil || len(publicKey) != ed25519.PublicKeySize || !ed25519.Verify(publicKey, signed.Payload, signature) {
		return Manifest{}, ErrManifestIntegrity
	}
	var manifest Manifest
	decoder := json.NewDecoder(bytes.NewReader(signed.Payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&manifest); err != nil {
		return Manifest{}, ErrManifestIntegrity
	}
	if err := ensureJSONEOF(decoder); err != nil {
		return Manifest{}, ErrManifestIntegrity
	}
	canonical, err := json.Marshal(manifest)
	if err != nil || !bytes.Equal(canonical, signed.Payload) {
		return Manifest{}, ErrManifestIntegrity
	}
	if err := manifest.Validate(); err != nil {
		return Manifest{}, err
	}
	if expectation.BackupID != "" && expectation.BackupID != manifest.BackupID ||
		expectation.SourceClusterID != "" && expectation.SourceClusterID != manifest.SourceClusterID ||
		expectation.AppVersion != "" && expectation.AppVersion != manifest.AppVersion {
		return Manifest{}, ErrManifestIntegrity
	}
	if expectation.MaxSchemaVersion != 0 && manifest.SchemaVersion > expectation.MaxSchemaVersion {
		return Manifest{}, ErrSchemaIncompatible
	}
	return manifest, nil
}

func ensureJSONEOF(decoder *json.Decoder) error {
	var extra any
	err := decoder.Decode(&extra)
	if errors.Is(err, io.EOF) {
		return nil
	}
	return ErrManifestIntegrity
}

func validSHA256(value string) bool {
	if len(value) != sha256.Size*2 || strings.ToLower(value) != value {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func isRequiredComponent(component Component) bool {
	for _, required := range requiredComponents {
		if component == required {
			return true
		}
	}
	return false
}
