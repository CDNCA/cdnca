package helper

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/packaging/helper/protocol"
	"golang.org/x/sys/unix"
)

func cloneReceiptPublicKeys(keys map[string]ed25519.PublicKey) map[string]ed25519.PublicKey {
	if len(keys) == 0 {
		return nil
	}
	cloned := make(map[string]ed25519.PublicKey, len(keys))
	for keyID, publicKey := range keys {
		cloned[keyID] = append(ed25519.PublicKey(nil), publicKey...)
	}
	return cloned
}

const (
	legacyJournalSchemaVersion = 1
	journalSchemaVersion       = 2
	journalSchemaVersionV3     = 3
	maxJournalFileSize         = 64 << 10
)

var (
	ErrJournalPolicy       = errors.New("transaction journal policy violation")
	ErrJournalCorrupt      = errors.New("corrupt transaction journal")
	ErrJournalNotFound     = errors.New("transaction journal not found")
	ErrTransactionConflict = errors.New("transaction payload conflict")
)

type JournalPhase string

const (
	JournalPrepared    JournalPhase = "prepared"
	JournalAborted     JournalPhase = "aborted"
	JournalInstalling  JournalPhase = "installing"
	JournalActive      JournalPhase = "active"
	JournalRollbacking JournalPhase = "rollbacking"
	JournalRolledBack  JournalPhase = "rolled_back"
)

type JournalConfig struct {
	Directory string
	OwnerUID  uint32
	OwnerGID  uint32
	// TrustedReceiptKeys is the verification keyring for persisted receipts.
	TrustedReceiptKeys map[string]ed25519.PublicKey
}

type JournalRecord struct {
	SchemaVersion         int             `json:"schema_version"`
	TransactionID         string          `json:"transaction_id"`
	Phase                 JournalPhase    `json:"phase"`
	InstallPayloadSHA256  string          `json:"install_payload_sha256"`
	RollbackPayloadSHA256 string          `json:"rollback_payload_sha256,omitempty"`
	ExecutionSequence     uint64          `json:"execution_sequence,omitempty"`
	ReleaseSequence       uint64          `json:"release_sequence"`
	Action                protocol.Action `json:"action,omitempty"`
	OuterArtifactSHA256   string          `json:"outer_artifact_sha256"`
	ManifestSHA256        string          `json:"manifest_sha256"`
	ExecutableSHA256      string          `json:"executable_sha256"`
	SBOMSHA256            string          `json:"sbom_sha256"`
	// NativeSHA256 is the native section of a v2 bundle (empty for v1).
	NativeSHA256                    string            `json:"native_sha256,omitempty"`
	PreviousVersion                 string            `json:"previous_version"`
	TargetVersion                   string            `json:"target_version"`
	PreviousPhysicalReleaseSequence uint64            `json:"previous_physical_release_sequence,omitempty"`
	PreviousManifestSHA256          string            `json:"previous_manifest_sha256,omitempty"`
	PreviousReceipt                 *protocol.Receipt `json:"previous_receipt,omitempty"`
	ActiveReceipt                   *protocol.Receipt `json:"active_receipt,omitempty"`
	RollbackReceipt                 *protocol.Receipt `json:"rollback_receipt,omitempty"`
}

type JournalStore struct {
	config      JournalConfig
	mu          sync.Mutex
	beforeWrite func(existing, next JournalRecord)
}

func ProductionJournalConfig() (JournalConfig, error) {
	if os.Geteuid() != 0 {
		return JournalConfig{}, fmt.Errorf("%w: root journal initialization required", ErrJournalPolicy)
	}
	return JournalConfig{Directory: "/var/lib/cdnca-edge-agent-helper", OwnerUID: 0, OwnerGID: 0}, nil
}

func NewJournalStore(config JournalConfig) (*JournalStore, error) {
	if !validAbsoluteFilePath(config.Directory) {
		return nil, fmt.Errorf("%w: invalid state directory", ErrJournalPolicy)
	}
	if err := os.Mkdir(config.Directory, stateDirMode); err != nil && !errors.Is(err, os.ErrExist) {
		return nil, fmt.Errorf("create transaction state directory: %w", err)
	}
	if err := requireOwnedDirectory(config.Directory, stateDirMode, config.OwnerUID, config.OwnerGID, true); err != nil {
		return nil, fmt.Errorf("%w: state directory", ErrJournalPolicy)
	}
	config.TrustedReceiptKeys = cloneReceiptPublicKeys(config.TrustedReceiptKeys)
	return &JournalStore{config: config}, nil
}

func HashCanonicalPayload(packet []byte) string {
	digest := sha256.Sum256(packet)
	return hex.EncodeToString(digest[:])
}

func (record JournalRecord) MatchInstallPayload(packet []byte) error {
	if HashCanonicalPayload(packet) != record.InstallPayloadSHA256 {
		return ErrTransactionConflict
	}
	return nil
}

func (record JournalRecord) MatchRollbackPayload(packet []byte) error {
	if record.RollbackPayloadSHA256 == "" || HashCanonicalPayload(packet) != record.RollbackPayloadSHA256 {
		return ErrTransactionConflict
	}
	return nil
}

func (store *JournalStore) Save(record JournalRecord) error {
	if store == nil {
		return ErrJournalPolicy
	}
	if err := validateJournalRecordWithKeys(record, store.config.TrustedReceiptKeys); err != nil {
		return err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.withDirectoryLock(func() error {
		if err := store.verifyDirectory(); err != nil {
			return err
		}
		return store.saveLocked(record)
	})
}

func (store *JournalStore) saveLocked(record JournalRecord) error {
	existing, err := store.loadLocked(record.TransactionID)
	if err == nil {
		if reflect.DeepEqual(existing, record) {
			return nil
		}
		if err := validateJournalTransition(existing, record); err != nil {
			return err
		}
	} else if !errors.Is(err, ErrJournalNotFound) {
		return err
	} else if record.Phase == JournalAborted {
		return ErrJournalCorrupt
	}
	return store.writeLocked(existing, record)
}

func (store *JournalStore) migrateLegacyInFlightLocked(previous, next JournalRecord) error {
	if previous.SchemaVersion != legacyJournalSchemaVersion || next.SchemaVersion != journalSchemaVersion ||
		(previous.Phase != JournalPrepared && previous.Phase != JournalInstalling) || next.Phase != previous.Phase {
		return ErrTransactionConflict
	}
	if err := validateJournalRecordWithKeys(next, store.config.TrustedReceiptKeys); err != nil {
		return err
	}
	migrated := next
	migrated.SchemaVersion = legacyJournalSchemaVersion
	migrated.PreviousPhysicalReleaseSequence = 0
	migrated.PreviousManifestSHA256 = ""
	if !reflect.DeepEqual(previous, migrated) {
		return ErrTransactionConflict
	}
	existing, err := store.loadLocked(previous.TransactionID)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(existing, previous) {
		return ErrTransactionConflict
	}
	return store.writeLocked(existing, next)
}

func (store *JournalStore) writeLocked(existing, next JournalRecord) error {
	if store.beforeWrite != nil {
		store.beforeWrite(existing, next)
	}
	encoded, err := json.Marshal(next)
	if err != nil || len(encoded) > maxJournalFileSize {
		return ErrJournalCorrupt
	}
	path := store.path(next.TransactionID)
	return writeOwnedAtomic(path, journalMode, store.config.OwnerUID, store.config.OwnerGID, encoded, existing.TransactionID != "")
}

func (store *JournalStore) withStoreLock(fn func() error) error {
	if store == nil {
		return ErrJournalPolicy
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.withDirectoryLock(func() error {
		if err := store.verifyDirectory(); err != nil {
			return err
		}
		return fn()
	})
}

func (store *JournalStore) withDirectoryLock(fn func() error) error {
	directory, err := os.Open(store.config.Directory)
	if err != nil {
		return fmt.Errorf("%w: open state directory lock", ErrJournalPolicy)
	}
	defer directory.Close()
	if err := unix.Flock(int(directory.Fd()), unix.LOCK_EX); err != nil {
		return fmt.Errorf("%w: lock state directory", ErrJournalPolicy)
	}
	defer unix.Flock(int(directory.Fd()), unix.LOCK_UN)
	lockedInfo, err := directory.Stat()
	if err != nil {
		return fmt.Errorf("%w: stat state directory lock", ErrJournalPolicy)
	}
	pathInfo, err := os.Lstat(store.config.Directory)
	if err != nil || !os.SameFile(lockedInfo, pathInfo) {
		return fmt.Errorf("%w: state directory lock changed", ErrJournalPolicy)
	}
	return fn()
}

func (store *JournalStore) Load(transactionID string) (JournalRecord, error) {
	if store == nil || !validHelperIdentifier(transactionID) {
		return JournalRecord{}, ErrJournalPolicy
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	var record JournalRecord
	var loadErr error
	if err := store.withDirectoryLock(func() error {
		if err := store.verifyDirectory(); err != nil {
			return err
		}
		record, loadErr = store.loadLocked(transactionID)
		return nil
	}); err != nil {
		return JournalRecord{}, err
	}
	return record, loadErr
}

func (store *JournalStore) HighWaterMark() (uint64, error) {
	if store == nil {
		return 0, ErrJournalPolicy
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	var highWater uint64
	var highWaterErr error
	if err := store.withDirectoryLock(func() error {
		if err := store.verifyDirectory(); err != nil {
			return err
		}
		highWater, highWaterErr = store.highWaterMarkLocked()
		return nil
	}); err != nil {
		return 0, err
	}
	return highWater, highWaterErr
}

func (store *JournalStore) highWaterMarkLocked() (uint64, error) {
	return store.highWaterMarkLockedExcept("")
}

func (store *JournalStore) highWaterMarkLockedExcept(excludedTransactionID string) (uint64, error) {
	records, err := store.recordsLocked()
	if err != nil {
		return 0, err
	}
	hasV3 := false
	for _, record := range records {
		if record.SchemaVersion == journalSchemaVersionV3 {
			hasV3 = true
			break
		}
	}
	var highWater uint64
	for _, record := range records {
		if record.TransactionID == excludedTransactionID || hasV3 && record.SchemaVersion != journalSchemaVersionV3 {
			continue
		}
		sequence := journalSequence(record)
		if (record.Phase == JournalInstalling || record.Phase == JournalActive || record.Phase == JournalRollbacking || record.Phase == JournalRolledBack) && sequence > highWater {
			highWater = sequence
		}
	}
	return highWater, nil
}

func (store *JournalStore) activeReceiptForFactsLocked(facts InstalledFacts) (protocol.Receipt, bool, error) {
	records, err := store.recordsLocked()
	if err != nil {
		return protocol.Receipt{}, false, err
	}
	hasV3 := containsV3Journal(records)
	var matched *protocol.Receipt
	var matchedSequence uint64
	activeCount := 0
	for _, record := range records {
		if record.Phase != JournalActive || hasV3 && record.SchemaVersion != journalSchemaVersionV3 {
			continue
		}
		activeCount++
		if !installedTargetMatches(record, facts) {
			continue
		}
		sequence := journalSequence(record)
		if matched != nil && sequence == matchedSequence {
			return protocol.Receipt{}, true, ErrCurrentFacts
		}
		if matched != nil && sequence < matchedSequence {
			continue
		}
		matchedReceipt := *record.ActiveReceipt
		matched = &matchedReceipt
		matchedSequence = sequence
	}
	if activeCount != 0 && matched == nil {
		return protocol.Receipt{}, true, ErrCurrentFacts
	}
	if matched == nil {
		return protocol.Receipt{}, false, nil
	}
	return *matched, true, nil
}

func (store *JournalStore) recordsLocked() ([]JournalRecord, error) {
	entries, err := os.ReadDir(store.config.Directory)
	if err != nil {
		return nil, err
	}
	records := make([]JournalRecord, 0, len(entries))
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasPrefix(name, "journal-") || !strings.HasSuffix(name, ".json") {
			continue
		}
		transactionID := strings.TrimSuffix(strings.TrimPrefix(name, "journal-"), ".json")
		if !validHelperIdentifier(transactionID) {
			return nil, ErrJournalCorrupt
		}
		record, err := store.loadLocked(transactionID)
		if err != nil {
			return nil, err
		}
		records = append(records, record)
	}
	return records, nil
}

func (store *JournalStore) loadLocked(transactionID string) (JournalRecord, error) {
	content, err := readOwnedCanonicalFile(store.path(transactionID), journalMode, store.config.OwnerUID, store.config.OwnerGID, maxJournalFileSize)
	if errors.Is(err, os.ErrNotExist) {
		return JournalRecord{}, ErrJournalNotFound
	}
	if err != nil {
		return JournalRecord{}, fmt.Errorf("%w: read", ErrJournalPolicy)
	}
	var record JournalRecord
	if err := decodeCanonicalJSON(content, &record); err != nil || validateJournalRecordWithKeys(record, store.config.TrustedReceiptKeys) != nil || record.TransactionID != transactionID {
		return JournalRecord{}, ErrJournalCorrupt
	}
	return record, nil
}

func (store *JournalStore) verifyDirectory() error {
	if err := requireOwnedDirectory(store.config.Directory, stateDirMode, store.config.OwnerUID, store.config.OwnerGID, true); err != nil {
		return fmt.Errorf("%w: state directory", ErrJournalPolicy)
	}
	return nil
}

func (store *JournalStore) path(transactionID string) string {
	return filepath.Join(store.config.Directory, "journal-"+transactionID+".json")
}

func validateJournalRecord(record JournalRecord) error {
	return validateJournalRecordWithKeys(record, nil)
}

func validateJournalRecordWithKeys(record JournalRecord, trustedKeys map[string]ed25519.PublicKey) error {
	if !validHelperIdentifier(record.TransactionID) || record.ReleaseSequence == 0 ||
		!validHelperDigest(record.InstallPayloadSHA256) || !validHelperDigest(record.OuterArtifactSHA256) ||
		!validHelperDigest(record.ManifestSHA256) || !validHelperDigest(record.ExecutableSHA256) || !validHelperDigest(record.SBOMSHA256) ||
		(record.NativeSHA256 != "" && !validHelperDigest(record.NativeSHA256)) ||
		!validHelperVersion(record.PreviousVersion) || !validHelperVersion(record.TargetVersion) ||
		record.PreviousVersion == record.TargetVersion {
		return ErrJournalCorrupt
	}
	switch record.SchemaVersion {
	case legacyJournalSchemaVersion:
		if record.ExecutionSequence != 0 || record.Action != "" ||
			record.PreviousPhysicalReleaseSequence != 0 || record.PreviousManifestSHA256 != "" {
			return ErrJournalCorrupt
		}
	case journalSchemaVersion:
		if record.ExecutionSequence != 0 || record.Action != "" || record.PreviousPhysicalReleaseSequence == 0 ||
			record.PreviousPhysicalReleaseSequence >= record.ReleaseSequence ||
			!validHelperDigest(record.PreviousManifestSHA256) {
			return ErrJournalCorrupt
		}
	case journalSchemaVersionV3:
		if record.ExecutionSequence == 0 ||
			(record.Action != protocol.ActionUpgrade && record.Action != protocol.ActionRollback) ||
			record.PreviousPhysicalReleaseSequence == 0 ||
			!validHelperDigest(record.PreviousManifestSHA256) {
			return ErrJournalCorrupt
		}
	default:
		return ErrJournalCorrupt
	}
	if record.PreviousReceipt != nil && !previousReceiptMatches(record, trustedKeys) {
		return ErrJournalCorrupt
	}
	if (record.Phase == JournalActive || record.Phase == JournalRollbacking || record.Phase == JournalRolledBack) && record.PreviousReceipt == nil {
		return ErrJournalCorrupt
	}
	switch record.Phase {
	case JournalPrepared, JournalAborted, JournalInstalling:
		if record.RollbackPayloadSHA256 != "" || record.ActiveReceipt != nil || record.RollbackReceipt != nil {
			return ErrJournalCorrupt
		}
	case JournalActive:
		if record.RollbackPayloadSHA256 != "" || record.RollbackReceipt != nil || !activeReceiptMatches(record, trustedKeys) {
			return ErrJournalCorrupt
		}
	case JournalRollbacking:
		if !validHelperDigest(record.RollbackPayloadSHA256) || record.RollbackReceipt != nil || !activeReceiptMatches(record, trustedKeys) {
			return ErrJournalCorrupt
		}
	case JournalRolledBack:
		manual := validHelperDigest(record.RollbackPayloadSHA256) && activeReceiptMatches(record, trustedKeys)
		automatic := record.RollbackPayloadSHA256 == "" && record.ActiveReceipt == nil
		if (!manual && !automatic) || !rollbackReceiptMatches(record, trustedKeys) {
			return ErrJournalCorrupt
		}
	default:
		return ErrJournalCorrupt
	}
	return nil
}

func validateJournalTransition(previous, next JournalRecord) error {
	if previous.TransactionID != next.TransactionID || previous.SchemaVersion != next.SchemaVersion ||
		previous.InstallPayloadSHA256 != next.InstallPayloadSHA256 || previous.ExecutionSequence != next.ExecutionSequence ||
		previous.ReleaseSequence != next.ReleaseSequence || previous.Action != next.Action ||
		previous.OuterArtifactSHA256 != next.OuterArtifactSHA256 || previous.ManifestSHA256 != next.ManifestSHA256 ||
		previous.ExecutableSHA256 != next.ExecutableSHA256 || previous.SBOMSHA256 != next.SBOMSHA256 || previous.NativeSHA256 != next.NativeSHA256 ||
		previous.PreviousVersion != next.PreviousVersion || previous.TargetVersion != next.TargetVersion ||
		previous.PreviousPhysicalReleaseSequence != next.PreviousPhysicalReleaseSequence ||
		previous.PreviousManifestSHA256 != next.PreviousManifestSHA256 ||
		!reflect.DeepEqual(previous.PreviousReceipt, next.PreviousReceipt) {
		return ErrTransactionConflict
	}
	if previous.RollbackPayloadSHA256 != "" && previous.RollbackPayloadSHA256 != next.RollbackPayloadSHA256 {
		return ErrTransactionConflict
	}
	valid := previous.Phase == JournalPrepared && next.Phase == JournalAborted ||
		previous.Phase == JournalPrepared && next.Phase == JournalInstalling ||
		previous.Phase == JournalInstalling && next.Phase == JournalActive ||
		previous.Phase == JournalInstalling && next.Phase == JournalRolledBack && next.RollbackPayloadSHA256 == "" ||
		previous.Phase == JournalActive && next.Phase == JournalRollbacking ||
		previous.Phase == JournalRollbacking && next.Phase == JournalRolledBack
	if !valid {
		return ErrJournalCorrupt
	}
	return nil
}

func previousReceiptMatches(record JournalRecord, trustedKeys map[string]ed25519.PublicKey) bool {
	receipt := record.PreviousReceipt
	if receipt == nil || receipt.Status != "active" || receipt.CurrentVersion != record.PreviousVersion ||
		!validStoredReceipt(*receipt, trustedKeys) {
		return false
	}
	if record.SchemaVersion == journalSchemaVersionV3 {
		return receipt.SchemaVersion == 1 || receipt.SchemaVersion == 2 && receipt.ExecutionSequence < record.ExecutionSequence
	}
	return receipt.SchemaVersion == 1 && receipt.ReleaseSequence < record.ReleaseSequence
}

func activeReceiptMatches(record JournalRecord, trustedKeys map[string]ed25519.PublicKey) bool {
	receipt := record.ActiveReceipt
	wantSchema := 1
	if record.SchemaVersion == journalSchemaVersionV3 {
		wantSchema = 2
	}
	return receipt != nil && receipt.SchemaVersion == wantSchema &&
		receipt.ExecutionSequence == record.ExecutionSequence && receipt.InstallerTransactionID == record.TransactionID &&
		receipt.ReleaseSequence == record.ReleaseSequence && receipt.ArtifactSHA256 == record.OuterArtifactSHA256 &&
		receipt.CurrentVersion == record.TargetVersion && receipt.PreviousVersion == record.PreviousVersion &&
		receipt.Status == "active" && validStoredReceipt(*receipt, trustedKeys)
}

func rollbackReceiptMatches(record JournalRecord, trustedKeys map[string]ed25519.PublicKey) bool {
	receipt := record.RollbackReceipt
	wantSchema := 1
	if record.SchemaVersion == journalSchemaVersionV3 {
		wantSchema = 2
	}
	return receipt != nil && receipt.SchemaVersion == wantSchema &&
		receipt.ExecutionSequence == record.ExecutionSequence && receipt.InstallerTransactionID == record.TransactionID &&
		receipt.ReleaseSequence == record.ReleaseSequence && receipt.ArtifactSHA256 == record.OuterArtifactSHA256 &&
		receipt.CurrentVersion == record.PreviousVersion && receipt.PreviousVersion == record.TargetVersion &&
		receipt.Status == "rolled_back" && validStoredReceipt(*receipt, trustedKeys)
}

func validStoredReceipt(receipt protocol.Receipt, trustedKeys map[string]ed25519.PublicKey) bool {
	if receipt.IssuedAt.IsZero() || receipt.IssuedAt.Location() != time.UTC || protocol.ValidateResponse(protocol.Success(receipt)) != nil {
		return false
	}
	if len(trustedKeys) == 0 {
		return false
	}
	publicKey, ok := trustedKeys[receipt.Signature.KeyID]
	if !ok || len(publicKey) != ed25519.PublicKeySize {
		return false
	}
	payload, err := ReceiptSigningBytes(receipt)
	if err != nil {
		return false
	}
	signature, err := base64.RawStdEncoding.DecodeString(receipt.Signature.Value)
	return err == nil && len(signature) == ed25519.SignatureSize && ed25519.Verify(publicKey, payload, signature)
}

func journalSequence(record JournalRecord) uint64 {
	if record.SchemaVersion == journalSchemaVersionV3 {
		return record.ExecutionSequence
	}
	return record.ReleaseSequence
}
