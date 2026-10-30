package nativebackup

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"regexp"
	"time"
)

const (
	ManifestSchema       = "cdnca.control-native-backup/v1"
	SignedManifestSchema = "cdnca.control-native-backup.signed/v1"
)

// ComponentName identifies one encrypted artifact. Restore applies them in
// ComponentOrder; capture uses the same order.
type ComponentName string

const (
	ComponentConfig      ComponentName = "config"
	ComponentRuntime     ComponentName = "runtime"
	ComponentPostgreSQL  ComponentName = "postgresql"
	ComponentClickHouse  ComponentName = "clickhouse"
	ComponentJetStream   ComponentName = "jetstream"
	ComponentObjectStore ComponentName = "objectstore"
)

var ComponentOrder = []ComponentName{
	ComponentConfig, ComponentRuntime, ComponentPostgreSQL,
	ComponentClickHouse, ComponentJetStream, ComponentObjectStore,
}

var (
	ErrManifestInvalid   = errors.New("backup manifest is invalid")
	ErrSignatureMismatch = errors.New("backup signature or signer fingerprint does not match")
	backupIDPattern      = regexp.MustCompile(`^[0-9]{8}T[0-9]{6}Z-[a-z0-9]{8}$`)
	versionPattern       = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$`)
	shaPattern           = regexp.MustCompile(`^[0-9a-f]{64}$`)
	fingerprintPattern   = regexp.MustCompile(`^SHA256:[A-Za-z0-9+/]{43}$`)
)

// ControlFacts identify the backed-up installation. None of them is secret.
type ControlFacts struct {
	InstallationID   string `json:"installation_id"`
	InstallationName string `json:"installation_name"`
	Version          string `json:"version"`
	SourceCommit     string `json:"source_commit"`
	SchemaVersion    uint64 `json:"schema_version"`
	ControlDomain    string `json:"control_domain"`
	GatewayEndpoint  string `json:"gateway_endpoint"`
	Hostname         string `json:"hostname"`
}

type ComponentRecord struct {
	Name             ComponentName `json:"name"`
	File             string        `json:"file"`
	CiphertextSHA256 string        `json:"ciphertext_sha256"`
	CiphertextBytes  int64         `json:"ciphertext_bytes"`
	PlaintextSHA256  string        `json:"plaintext_sha256"`
	PlaintextBytes   int64         `json:"plaintext_bytes"`
	CapturedAt       time.Time     `json:"captured_at"`
	// Detail holds non-secret facts the restore preflight checks before any
	// mutation (server versions, database and role names, stream names).
	Detail map[string]string `json:"detail,omitempty"`
}

type Manifest struct {
	Schema        string            `json:"schema"`
	BackupID      string            `json:"backup_id"`
	Reason        string            `json:"reason"`
	CreatedAt     time.Time         `json:"created_at"`
	FreezeMode    FreezeMode        `json:"freeze_mode"`
	FrozenAt      time.Time         `json:"frozen_at"`
	Control       ControlFacts      `json:"control"`
	Recipients    []string          `json:"recipients"`
	Components    []ComponentRecord `json:"components"`
	ToolVersion   string            `json:"tool_version"`
	SignerKeyHint string            `json:"signer_fingerprint"`
}

func (manifest Manifest) Validate() error {
	if manifest.Schema != ManifestSchema || !backupIDPattern.MatchString(manifest.BackupID) ||
		manifest.CreatedAt.IsZero() || manifest.FrozenAt.IsZero() || manifest.CreatedAt.Before(manifest.FrozenAt) ||
		(manifest.FreezeMode != FreezeBackup && manifest.FreezeMode != FreezeHold) ||
		!versionPattern.MatchString(manifest.Control.Version) || manifest.Control.SchemaVersion == 0 ||
		manifest.Control.InstallationID == "" || len(manifest.Recipients) == 0 ||
		!fingerprintPattern.MatchString(manifest.SignerKeyHint) || len(manifest.Components) != len(ComponentOrder) {
		return ErrManifestInvalid
	}
	switch manifest.Reason {
	case "manual", "scheduled", "migration", "pre-restore":
	default:
		return ErrManifestInvalid
	}
	for index, component := range manifest.Components {
		if component.Name != ComponentOrder[index] || component.File != string(component.Name)+".tar.age" ||
			!shaPattern.MatchString(component.CiphertextSHA256) || !shaPattern.MatchString(component.PlaintextSHA256) ||
			component.CiphertextBytes <= 0 || component.PlaintextBytes <= 0 || component.CapturedAt.IsZero() ||
			component.CapturedAt.Before(manifest.FrozenAt) || component.CapturedAt.After(manifest.CreatedAt) {
			return ErrManifestInvalid
		}
	}
	return nil
}

func (manifest Manifest) Component(name ComponentName) (ComponentRecord, bool) {
	for _, component := range manifest.Components {
		if component.Name == name {
			return component, true
		}
	}
	return ComponentRecord{}, false
}

type SignedManifest struct {
	Schema string `json:"schema"`
	// Payload is the exact signed JSON, base64 so re-indenting the envelope
	// can never change the signed bytes.
	Payload   []byte `json:"payload"`
	PublicKey string `json:"public_key"`
	Signature string `json:"signature"`
}

// Fingerprint is the printable identity of a backup signer, in the same form
// as an SSH key fingerprint so operators can compare it by eye.
func Fingerprint(publicKey ed25519.PublicKey) string {
	digest := sha256.Sum256(publicKey)
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(digest[:])
}

func SignManifest(manifest Manifest, key ed25519.PrivateKey) (SignedManifest, error) {
	public := key.Public().(ed25519.PublicKey)
	manifest.SignerKeyHint = Fingerprint(public)
	if err := manifest.Validate(); err != nil {
		return SignedManifest{}, err
	}
	payload, err := json.Marshal(manifest)
	if err != nil {
		return SignedManifest{}, err
	}
	return SignedManifest{Schema: SignedManifestSchema, Payload: payload,
		PublicKey: base64.StdEncoding.EncodeToString(public),
		Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(key, payload))}, nil
}

// VerifyManifest checks the signature and that the signer is the pinned
// fingerprint. A bundle is never trusted only because it carries a key.
func VerifyManifest(signed SignedManifest, pinnedFingerprint string) (Manifest, error) {
	if signed.Schema != SignedManifestSchema || !fingerprintPattern.MatchString(pinnedFingerprint) {
		return Manifest{}, ErrSignatureMismatch
	}
	public, err := base64.StdEncoding.DecodeString(signed.PublicKey)
	if err != nil || len(public) != ed25519.PublicKeySize || Fingerprint(public) != pinnedFingerprint {
		return Manifest{}, ErrSignatureMismatch
	}
	signature, err := base64.StdEncoding.DecodeString(signed.Signature)
	if err != nil || !ed25519.Verify(public, signed.Payload, signature) {
		return Manifest{}, ErrSignatureMismatch
	}
	var manifest Manifest
	decoder := json.NewDecoder(bytes.NewReader(signed.Payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&manifest); err != nil {
		return Manifest{}, ErrManifestInvalid
	}
	if manifest.SignerKeyHint != pinnedFingerprint {
		return Manifest{}, ErrSignatureMismatch
	}
	return manifest, manifest.Validate()
}

// ReadUnverifiedManifest decodes a manifest only to show its facts (for the
// console list or before a fingerprint is pinned). Never restore from it.
func ReadUnverifiedManifest(signed SignedManifest) (Manifest, error) {
	var manifest Manifest
	if err := json.Unmarshal(signed.Payload, &manifest); err != nil {
		return Manifest{}, ErrManifestInvalid
	}
	return manifest, manifest.Validate()
}

func sha256Hex(value []byte) string {
	digest := sha256.Sum256(value)
	return hex.EncodeToString(digest[:])
}
