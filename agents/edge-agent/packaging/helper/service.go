package helper

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/packaging/helper/protocol"
	"golang.org/x/sys/unix"
)

type PackageOperator interface {
	Upgrade(context.Context, StagedBundle) error
	Rollback(context.Context, string) error
}

type ServiceConfig struct {
	Paths      RuntimePaths
	OwnerUID   uint32
	OwnerGID   uint32
	ReceiptKey KeyMaterial
	// ReceiptPublicKeys contains explicitly trusted historical receipt keys.
	ReceiptPublicKeys map[string]ed25519.PublicKey
	ReleasePublicKey  ed25519.PublicKey
	Runner            PackageOperator
	Now               func() time.Time
}

type Service struct {
	config               ServiceConfig
	journals             *JournalStore
	current              *CurrentStore
	transactions         string
	receiptKeys          map[string]ed25519.PublicKey
	syncJournalDirectory func() error
	syncTransactions     func() error
	mu                   sync.Mutex
}

func NewService(config ServiceConfig) (*Service, error) {
	if config.Runner == nil || len(config.ReceiptKey.PrivateKey) != ed25519.PrivateKeySize ||
		len(config.ReleasePublicKey) != ed25519.PublicKeySize || !validAbsoluteFilePath(config.Paths.StateDirectory) {
		return nil, ErrCurrentFacts
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	receiptKeys := cloneReceiptPublicKeys(config.ReceiptPublicKeys)
	if receiptKeys == nil {
		receiptKeys = make(map[string]ed25519.PublicKey)
	}
	receiptKeys[config.ReceiptKey.KeyID] = append(ed25519.PublicKey(nil), config.ReceiptKey.PrivateKey.Public().(ed25519.PublicKey)...)
	journals, err := NewJournalStore(JournalConfig{
		Directory: config.Paths.StateDirectory, OwnerUID: config.OwnerUID, OwnerGID: config.OwnerGID,
		TrustedReceiptKeys: receiptKeys,
	})
	if err != nil {
		return nil, err
	}
	current, err := NewCurrentStore(config.Paths.StateDirectory, config.OwnerUID, config.OwnerGID)
	if err != nil {
		return nil, err
	}
	transactions := filepath.Join(config.Paths.StateDirectory, "transactions")
	if err := os.Mkdir(transactions, stateDirMode); err != nil && !errors.Is(err, os.ErrExist) {
		return nil, err
	}
	if err := requireOwnedDirectory(transactions, stateDirMode, config.OwnerUID, config.OwnerGID, true); err != nil {
		return nil, err
	}
	service := &Service{config: config, journals: journals, current: current, transactions: transactions, receiptKeys: receiptKeys}
	service.syncJournalDirectory = func() error { return syncHelperDirectory(config.Paths.StateDirectory) }
	service.syncTransactions = func() error { return syncHelperDirectory(transactions) }
	return service, nil
}

func (service *Service) Handle(ctx context.Context, packet []byte, request protocol.Request, artifact *os.File) protocol.Response {
	service.mu.Lock()
	defer service.mu.Unlock()
	if request.ProtocolVersion == protocol.JournalVersion {
		hasV3, err := service.hasV3State()
		if err != nil {
			return protocol.FailureForVersion(protocol.JournalVersion, protocol.ErrorStateUncertain)
		}
		if hasV3 {
			return protocol.FailureForVersion(protocol.JournalVersion, protocol.ErrorProtocol)
		}
	}
	if request.ProtocolVersion == protocol.JournalVersion || request.ProtocolVersion == protocol.JournalV3Version ||
		request.ProtocolVersion == protocol.JournalV4Version {
		version := request.ProtocolVersion
		switch request.Operation {
		case protocol.OperationPrepareInstall:
			record, code := service.prepareInstall(packet, request, artifact)
			if code != "" {
				return protocol.FailureForVersion(version, code)
			}
			return protocol.Prepared(version, preparedAck(record))
		case protocol.OperationInspectTransaction:
			status, code := service.inspectTransaction(request.TransactionID)
			if code != "" {
				return protocol.FailureForVersion(version, code)
			}
			return protocol.Inspected(version, status)
		case protocol.OperationMarkInstalling:
			status, code := service.markInstalling(request)
			if code != "" {
				return protocol.FailureForVersion(version, code)
			}
			return protocol.Inspected(version, status)
		case protocol.OperationActivateInstall:
			receipt, code := service.activateInstall(ctx, request)
			if code != "" {
				return protocol.FailureForVersion(version, code)
			}
			return protocol.SuccessForVersion(version, receipt)
		case protocol.OperationAbortPrepared:
			status, code := service.abortPrepared(request)
			if code != "" {
				return protocol.FailureForVersion(version, code)
			}
			return protocol.Inspected(version, status)
		default:
			return protocol.FailureForVersion(version, protocol.ErrorProtocol)
		}
	}
	receipt, code := service.handle(ctx, packet, request, artifact)
	if code != "" {
		return protocol.Failure(code)
	}
	// Answer in the request's protocol version: v1 carries schema 1 and 2
	// receipts, and a client rejects any response whose version differs.
	return protocol.SuccessForVersion(request.ProtocolVersion, receipt)
}

func (service *Service) hasV3State() (bool, error) {
	var hasV3 bool
	err := service.journals.withStoreLock(func() error {
		records, err := service.journals.recordsLocked()
		if err != nil {
			return err
		}
		hasV3 = containsV3Journal(records)
		return nil
	})
	return hasV3, err
}

func (service *Service) handle(ctx context.Context, packet []byte, request protocol.Request, artifact *os.File) (protocol.Receipt, protocol.ErrorCode) {
	switch request.Operation {
	case protocol.OperationCurrent:
		return service.ensureCurrent()
	case protocol.OperationQuery:
		return service.query(ctx, request.TransactionID)
	case protocol.OperationInstall:
		return service.install(ctx, packet, request, artifact)
	case protocol.OperationRollback:
		return service.rollback(ctx, packet, request)
	default:
		return protocol.Receipt{}, protocol.ErrorProtocol
	}
}

func (service *Service) ensureCurrent() (protocol.Receipt, protocol.ErrorCode) {
	var receipt protocol.Receipt
	var code protocol.ErrorCode
	if err := service.journals.withStoreLock(func() error {
		receipt, code = service.ensureCurrentLocked(true)
		return nil
	}); err != nil {
		return protocol.Receipt{}, protocol.ErrorStateUncertain
	}
	return receipt, code
}

func (service *Service) ensureCurrentForPrepare() (protocol.Receipt, protocol.ErrorCode) {
	var receipt protocol.Receipt
	var code protocol.ErrorCode
	if err := service.journals.withStoreLock(func() error {
		receipt, code = service.ensureCurrentLocked(false)
		return nil
	}); err != nil {
		return protocol.Receipt{}, protocol.ErrorStateUncertain
	}
	return receipt, code
}

func (service *Service) ensureCurrentLocked(blockUnresolved bool) (protocol.Receipt, protocol.ErrorCode) {
	facts, err := InspectInstalled(service.config.Paths, service.config.ReleasePublicKey, service.config.OwnerUID, service.config.OwnerGID)
	if err != nil {
		return protocol.Receipt{}, protocol.ErrorCurrentUnavailable
	}
	records, err := service.journals.recordsLocked()
	if err != nil || blockUnresolved && unresolvedInstallBlocksCurrent(records, facts) {
		return protocol.Receipt{}, protocol.ErrorStateUncertain
	}
	hasV3 := containsV3Journal(records)
	highWater, err := service.journals.highWaterMarkLocked()
	if err != nil {
		return protocol.Receipt{}, protocol.ErrorStateUncertain
	}
	if !hasV3 {
		if facts.AcceptedSequence > highWater {
			highWater = facts.AcceptedSequence
		}
		if facts.ReleaseSequence > highWater {
			highWater = facts.ReleaseSequence
		}
	}
	stored, manifestDigest, loadErr := service.current.Load()
	storedUsable := loadErr == nil && service.persistedReceiptUsable(stored)
	var restored *JournalRecord
	for index := range records {
		record := &records[index]
		if record.Phase != JournalRolledBack || journalSequence(*record) != highWater {
			continue
		}
		if restored == nil {
			restored = record
		}
	}
	if restored != nil {
		recovered, ok := service.recoverRolledBackCurrentLocked(*restored, facts)
		if !ok {
			return protocol.Receipt{}, protocol.ErrorStateUncertain
		}
		return recovered, ""
	}
	trustedActive, hasActive, err := service.journals.activeReceiptForFactsLocked(facts)
	if err != nil {
		return protocol.Receipt{}, protocol.ErrorStateUncertain
	}
	if hasActive {
		if receiptSequence(trustedActive) < highWater || !hasV3 && facts.AcceptedSequence > trustedActive.ReleaseSequence {
			return protocol.Receipt{}, protocol.ErrorStateUncertain
		}
		current, ok := service.ensureActiveCurrentLocked(trustedActive, facts)
		if !ok {
			return protocol.Receipt{}, protocol.ErrorStateUncertain
		}
		return current, ""
	}
	if storedUsable && stored.Status == "active" && stored.ArtifactSHA256 == facts.OuterArtifactSHA256 &&
		manifestDigest == facts.ManifestSHA256 && stored.CurrentVersion == facts.Version && receiptSequence(stored) >= highWater {
		if service.receiptSignedByCurrentKey(stored) {
			return stored, ""
		}
		rotated := stored
		if SignReceipt(&rotated, service.config.ReceiptKey) != nil || service.current.Save(rotated, facts.ManifestSHA256) != nil {
			return protocol.Receipt{}, protocol.ErrorStateUncertain
		}
		return rotated, ""
	}
	if loadErr == nil && !storedUsable {
		loadErr = ErrCurrentFacts
	}
	if hasV3 {
		return protocol.Receipt{}, protocol.ErrorStateUncertain
	}
	artifactDigest := facts.OuterArtifactSHA256
	previousVersion := ""
	if loadErr == nil {
		if manifestDigest == facts.ManifestSHA256 && stored.CurrentVersion == facts.Version {
			artifactDigest = stored.ArtifactSHA256
			previousVersion = stored.PreviousVersion
		} else {
			previousVersion = stored.CurrentVersion
		}
	}
	receipt := protocol.Receipt{
		SchemaVersion: 1, InstallerTransactionID: currentTransactionID(facts, highWater),
		ReleaseSequence: highWater, ArtifactSHA256: artifactDigest, CurrentVersion: facts.Version,
		PreviousVersion: previousVersion, Status: "active", IssuedAt: service.config.Now().UTC(),
	}
	if SignReceipt(&receipt, service.config.ReceiptKey) != nil || service.current.Save(receipt, facts.ManifestSHA256) != nil {
		return protocol.Receipt{}, protocol.ErrorStateUncertain
	}
	return receipt, ""
}

func (service *Service) install(ctx context.Context, packet []byte, request protocol.Request, artifact *os.File) (protocol.Receipt, protocol.ErrorCode) {
	record, code := service.prepareInstall(packet, request, artifact)
	if code != "" {
		return protocol.Receipt{}, code
	}
	return service.completeInstall(ctx, record)
}

func (service *Service) prepareInstall(packet []byte, request protocol.Request, artifact *os.File) (JournalRecord, protocol.ErrorCode) {
	existing, err := service.journals.Load(request.TransactionID)
	if err == nil {
		if existing.MatchInstallPayload(packet) != nil {
			return JournalRecord{}, protocol.ErrorTransactionConflict
		}
		if existing.Phase == JournalAborted {
			return JournalRecord{}, protocol.ErrorTransactionConflict
		}
		return existing, ""
	}
	if !errors.Is(err, ErrJournalNotFound) {
		return JournalRecord{}, protocol.ErrorStateUncertain
	}
	var records []JournalRecord
	if err := service.journals.withStoreLock(func() error {
		var loadErr error
		records, loadErr = service.journals.recordsLocked()
		return loadErr
	}); err != nil {
		return JournalRecord{}, protocol.ErrorStateUncertain
	}
	if request.ProtocolVersion != protocol.JournalV3Version && containsV3Journal(records) {
		return JournalRecord{}, protocol.ErrorProtocol
	}
	if request.ProtocolVersion == protocol.JournalV3Version && request.ExecutionSequence <= highestV3Execution(records) {
		return JournalRecord{}, protocol.ErrorTransactionConflict
	}
	current, code := service.ensureCurrentForPrepare()
	if code != "" {
		return JournalRecord{}, code
	}
	if request.CurrentReceipt == nil || !sameReceipt(*request.CurrentReceipt, current) || request.CurrentVersion != current.CurrentVersion ||
		request.TargetVersion == current.CurrentVersion ||
		request.ProtocolVersion != protocol.JournalV3Version && request.ReleaseSequence <= current.ReleaseSequence ||
		request.ProtocolVersion == protocol.JournalV3Version && request.ExecutionSequence <= receiptSequence(current) {
		return JournalRecord{}, protocol.ErrorTransactionConflict
	}
	temporary, err := os.MkdirTemp(service.transactions, ".staging-"+request.TransactionID+"-")
	if err != nil {
		return JournalRecord{}, protocol.ErrorStateUncertain
	}
	defer os.RemoveAll(temporary)
	if err := os.Chmod(temporary, stateDirMode); err != nil {
		return JournalRecord{}, protocol.ErrorStateUncertain
	}
	staged, err := StageReleaseBundle(artifact, temporary, request.ArtifactSize, request.ArtifactSHA256)
	if err != nil {
		return JournalRecord{}, bundleErrorCode(err)
	}
	manifest, err := VerifyReleaseManifest(staged, service.config.ReleasePublicKey, ManifestExpectation{
		ReleaseSequence: request.ReleaseSequence, TargetVersion: request.TargetVersion,
		Platform: request.Platform, Architecture: request.Architecture,
	})
	if err != nil {
		return JournalRecord{}, protocol.ErrorArtifactMismatch
	}
	previous := *request.CurrentReceipt
	recordSchema := journalSchemaVersion
	if request.ProtocolVersion == protocol.JournalV3Version {
		recordSchema = journalSchemaVersionV3
	}
	record := JournalRecord{
		SchemaVersion: recordSchema, TransactionID: request.TransactionID, Phase: JournalPrepared,
		InstallPayloadSHA256: HashCanonicalPayload(packet), ExecutionSequence: request.ExecutionSequence,
		ReleaseSequence: request.ReleaseSequence, Action: request.Action,
		OuterArtifactSHA256: request.ArtifactSHA256, ManifestSHA256: manifest.ManifestSHA256,
		ExecutableSHA256: manifest.ArtifactSHA256, SBOMSHA256: manifest.SBOMSHA256, NativeSHA256: staged.NativeSHA256,
		PreviousVersion: current.CurrentVersion, TargetVersion: request.TargetVersion, PreviousReceipt: &previous,
	}
	directory := filepath.Join(service.transactions, request.TransactionID)
	var lockErr error
	lockErr = service.journals.withStoreLock(func() error {
		existing, loadErr := service.journals.loadLocked(request.TransactionID)
		if loadErr == nil {
			if existing.MatchInstallPayload(packet) != nil {
				return ErrTransactionConflict
			}
			if existing.Phase == JournalAborted {
				return ErrTransactionConflict
			}
			record = existing
			return nil
		}
		if !errors.Is(loadErr, ErrJournalNotFound) {
			return loadErr
		}
		records, recordsErr := service.journals.recordsLocked()
		if recordsErr != nil {
			return recordsErr
		}
		if request.ProtocolVersion != protocol.JournalV3Version && containsV3Journal(records) ||
			request.ProtocolVersion == protocol.JournalV3Version && request.ExecutionSequence <= highestV3Execution(records) {
			return ErrTransactionConflict
		}
		facts, inspectErr := InspectInstalled(service.config.Paths, service.config.ReleasePublicKey, service.config.OwnerUID, service.config.OwnerGID)
		stored, previousManifestSHA256, currentErr := service.current.Load()
		if inspectErr != nil || currentErr != nil || !service.persistedReceiptUsable(stored) {
			return ErrCurrentFacts
		}
		if !sameReceipt(stored, current) {
			return ErrTransactionConflict
		}
		if previousManifestSHA256 != facts.ManifestSHA256 || current.CurrentVersion != facts.Version ||
			current.ArtifactSHA256 != facts.OuterArtifactSHA256 ||
			request.ProtocolVersion != protocol.JournalV3Version && facts.ReleaseSequence >= request.ReleaseSequence {
			return ErrCurrentFacts
		}
		record.PreviousPhysicalReleaseSequence = facts.ReleaseSequence
		record.PreviousManifestSHA256 = facts.ManifestSHA256
		if info, statErr := os.Lstat(directory); statErr == nil {
			if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
				return ErrCurrentFacts
			}
			matches, matchErr := service.transactionDirectoryMatches(directory, staged)
			if matchErr != nil {
				return matchErr
			}
			if !matches {
				return ErrCurrentFacts
			}
		} else if !errors.Is(statErr, os.ErrNotExist) {
			return statErr
		} else {
			if err := os.Rename(temporary, directory); err != nil {
				return err
			}
			if err := syncHelperDirectory(service.transactions); err != nil {
				return err
			}
		}
		return service.journals.saveLocked(record)
	})
	if errors.Is(lockErr, ErrTransactionConflict) {
		return JournalRecord{}, protocol.ErrorTransactionConflict
	}
	if lockErr != nil {
		return JournalRecord{}, protocol.ErrorStateUncertain
	}
	return record, ""
}

func (service *Service) completeInstall(ctx context.Context, record JournalRecord) (protocol.Receipt, protocol.ErrorCode) {
	var receipt protocol.Receipt
	var code protocol.ErrorCode
	err := service.journals.withStoreLock(func() error {
		latest, err := service.journals.loadLocked(record.TransactionID)
		if err != nil {
			code = protocol.ErrorStateUncertain
			if errors.Is(err, ErrJournalNotFound) {
				code = protocol.ErrorTransactionUnknown
			}
			return nil
		}
		receipt, code = service.completeInstallLocked(ctx, latest)
		return nil
	})
	if err != nil {
		return protocol.Receipt{}, protocol.ErrorStateUncertain
	}
	return receipt, code
}

func (service *Service) completeInstallLocked(ctx context.Context, record JournalRecord) (protocol.Receipt, protocol.ErrorCode) {
	switch record.Phase {
	case JournalActive:
		facts, err := InspectInstalled(service.config.Paths, service.config.ReleasePublicKey, service.config.OwnerUID, service.config.OwnerGID)
		if err != nil || record.ActiveReceipt == nil {
			return protocol.Receipt{}, protocol.ErrorStateUncertain
		}
		if _, ok := service.ensureActiveCurrentLocked(*record.ActiveReceipt, facts); !ok {
			return protocol.Receipt{}, protocol.ErrorStateUncertain
		}
		return *record.ActiveReceipt, ""
	case JournalRolledBack:
		if record.RollbackReceipt == nil || !service.persistedReceiptUsable(*record.RollbackReceipt) {
			return protocol.Receipt{}, protocol.ErrorStateUncertain
		}
		facts, err := InspectInstalled(service.config.Paths, service.config.ReleasePublicKey, service.config.OwnerUID, service.config.OwnerGID)
		if err != nil {
			return protocol.Receipt{}, protocol.ErrorStateUncertain
		}
		if _, ok := service.recoverRolledBackCurrentLocked(record, facts); !ok {
			return protocol.Receipt{}, protocol.ErrorStateUncertain
		}
		return *record.RollbackReceipt, ""
	case JournalPrepared, JournalInstalling:
		facts, err := InspectInstalled(service.config.Paths, service.config.ReleasePublicKey, service.config.OwnerUID, service.config.OwnerGID)
		if err != nil {
			return protocol.Receipt{}, protocol.ErrorStateUncertain
		}
		stored, previousManifestSHA256, err := service.current.Load()
		if err != nil || !service.persistedReceiptUsable(stored) {
			return protocol.Receipt{}, protocol.ErrorStateUncertain
		}
		if record.PreviousReceipt == nil || !sameReceipt(stored, *record.PreviousReceipt) {
			return protocol.Receipt{}, protocol.ErrorTransactionConflict
		}
		highWater, err := service.journals.highWaterMarkLockedExcept(record.TransactionID)
		if err != nil {
			return protocol.Receipt{}, protocol.ErrorStateUncertain
		}
		targetInstalled := service.installedTargetMatches(record, facts)
		previousInstalled := installedPreviousMatches(record, facts)
		if !targetInstalled && !previousInstalled {
			return protocol.Receipt{}, protocol.ErrorStateUncertain
		}
		if record.SchemaVersion == journalSchemaVersionV3 {
			if highWater >= record.ExecutionSequence || receiptSequence(stored) >= record.ExecutionSequence {
				return protocol.Receipt{}, protocol.ErrorTransactionConflict
			}
		} else if facts.AcceptedSequence > record.ReleaseSequence || facts.ReleaseSequence > record.ReleaseSequence ||
			highWater >= record.ReleaseSequence || stored.ReleaseSequence >= record.ReleaseSequence {
			return protocol.Receipt{}, protocol.ErrorTransactionConflict
		}
		if record.SchemaVersion == legacyJournalSchemaVersion {
			if record, err = service.migrateLegacyInFlightLocked(record, facts, stored, previousManifestSHA256); err != nil {
				return protocol.Receipt{}, protocol.ErrorStateUncertain
			}
		}
		if targetInstalled {
			return service.persistActive(record, facts)
		}
		if record.Phase == JournalPrepared {
			record.Phase = JournalInstalling
			if service.journals.saveLocked(record) != nil {
				return protocol.Receipt{}, protocol.ErrorStateUncertain
			}
		}
	default:
		return protocol.Receipt{}, protocol.ErrorTransactionConflict
	}
	staged, err := service.stagedFromJournal(record)
	if err != nil {
		return protocol.Receipt{}, protocol.ErrorStateUncertain
	}
	runErr := service.config.Runner.Upgrade(ctx, staged)
	if ctx.Err() != nil {
		return protocol.Receipt{}, protocol.ErrorDeadline
	}
	if runErr != nil {
		if service.config.Runner.Rollback(ctx, record.PreviousVersion) != nil {
			if ctx.Err() != nil {
				return protocol.Receipt{}, protocol.ErrorDeadline
			}
			return protocol.Receipt{}, protocol.ErrorRollbackFailed
		}
	}
	facts, inspectErr := InspectInstalled(service.config.Paths, service.config.ReleasePublicKey, service.config.OwnerUID, service.config.OwnerGID)
	if inspectErr != nil {
		return protocol.Receipt{}, protocol.ErrorStateUncertain
	}
	if runErr == nil && service.installedTargetMatches(record, facts) {
		return service.persistActive(record, facts)
	}
	if runErr != nil && installedPreviousMatches(record, facts) {
		receipt := service.newReceiptForRecord(record, record.PreviousVersion, record.TargetVersion, "rolled_back")
		if SignReceipt(&receipt, service.config.ReceiptKey) != nil {
			return protocol.Receipt{}, protocol.ErrorInternal
		}
		record.Phase = JournalRolledBack
		record.RollbackReceipt = &receipt
		if service.journals.saveLocked(record) != nil || service.saveRestoredCurrent(record, facts) != nil {
			return protocol.Receipt{}, protocol.ErrorStateUncertain
		}
		return receipt, ""
	}
	return protocol.Receipt{}, protocol.ErrorStateUncertain
}

func (service *Service) activateInstall(ctx context.Context, request protocol.Request) (protocol.Receipt, protocol.ErrorCode) {
	var receipt protocol.Receipt
	var code protocol.ErrorCode
	err := service.journals.withStoreLock(func() error {
		record, err := service.journals.loadLocked(request.TransactionID)
		if errors.Is(err, ErrJournalNotFound) {
			code = protocol.ErrorTransactionUnknown
			return nil
		}
		if err != nil {
			code = protocol.ErrorStateUncertain
			return nil
		}
		ack := preparedAck(record)
		if request.PreparedAck == nil || request.InstallPayloadSHA256 != record.InstallPayloadSHA256 || *request.PreparedAck != ack {
			code = protocol.ErrorTransactionConflict
			return nil
		}
		receipt, code = service.completeInstallLocked(ctx, record)
		return nil
	})
	if err != nil {
		return protocol.Receipt{}, protocol.ErrorStateUncertain
	}
	return receipt, code
}

func (service *Service) markInstalling(request protocol.Request) (protocol.TransactionStatus, protocol.ErrorCode) {
	var status protocol.TransactionStatus
	var code protocol.ErrorCode
	err := service.journals.withStoreLock(func() error {
		record, err := service.journals.loadLocked(request.TransactionID)
		if errors.Is(err, ErrJournalNotFound) {
			code = protocol.ErrorTransactionUnknown
			return nil
		}
		if err != nil {
			code = protocol.ErrorStateUncertain
			return nil
		}
		ack := preparedAck(record)
		if request.PreparedAck == nil || request.InstallPayloadSHA256 != record.InstallPayloadSHA256 || *request.PreparedAck != ack {
			code = protocol.ErrorTransactionConflict
			return nil
		}
		switch record.Phase {
		case JournalPrepared:
			record.Phase = JournalInstalling
			if service.journals.saveLocked(record) != nil {
				code = protocol.ErrorStateUncertain
				return nil
			}
			if service.syncJournalDirectory == nil || service.syncJournalDirectory() != nil {
				code = protocol.ErrorStateUncertain
				return nil
			}
		case JournalInstalling:
			if service.syncJournalDirectory == nil || service.syncJournalDirectory() != nil {
				code = protocol.ErrorStateUncertain
				return nil
			}
		default:
			code = protocol.ErrorTransactionConflict
			return nil
		}
		status = protocol.TransactionStatus{TransactionID: record.TransactionID, Phase: protocol.TransactionInstalling, PreparedAck: &ack}
		return nil
	})
	if err != nil {
		return protocol.TransactionStatus{}, protocol.ErrorStateUncertain
	}
	return status, code
}

func (service *Service) abortPrepared(request protocol.Request) (protocol.TransactionStatus, protocol.ErrorCode) {
	var status protocol.TransactionStatus
	var code protocol.ErrorCode
	err := service.journals.withStoreLock(func() error {
		record, err := service.journals.loadLocked(request.TransactionID)
		if errors.Is(err, ErrJournalNotFound) {
			code = protocol.ErrorTransactionUnknown
			return nil
		}
		if err != nil {
			code = protocol.ErrorStateUncertain
			return nil
		}
		ack := preparedAck(record)
		if request.PreparedAck == nil || request.InstallPayloadSHA256 != record.InstallPayloadSHA256 || *request.PreparedAck != ack {
			code = protocol.ErrorTransactionConflict
			return nil
		}
		if record.Phase == JournalPrepared {
			record.Phase = JournalAborted
			if service.journals.saveLocked(record) != nil {
				code = protocol.ErrorStateUncertain
				return nil
			}
		} else if record.Phase != JournalAborted {
			code = protocol.ErrorTransactionConflict
			return nil
		}
		if service.cleanupTransactionDirectoryLocked(record.TransactionID) != nil {
			code = protocol.ErrorStateUncertain
			return nil
		}
		status = protocol.TransactionStatus{TransactionID: record.TransactionID, Phase: protocol.TransactionAborted, PreparedAck: &ack}
		return nil
	})
	if err != nil {
		return protocol.TransactionStatus{}, protocol.ErrorStateUncertain
	}
	return status, code
}

func (service *Service) cleanupTransactionDirectoryLocked(transactionID string) error {
	directory := filepath.Join(service.transactions, transactionID)
	info, err := os.Lstat(directory)
	if errors.Is(err, os.ErrNotExist) {
		return service.syncTransactions()
	}
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 ||
		requireOwnedDirectory(directory, stateDirMode, service.config.OwnerUID, service.config.OwnerGID, true) != nil {
		return ErrCurrentFacts
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		return err
	}
	allowed := map[string]os.FileMode{
		"manifest": 0o400, "manifest.sig": 0o400,
		"edge-agent.spdx.json": 0o400, "edge-agent": 0o500,
	}
	for _, entry := range entries {
		mode, ok := allowed[entry.Name()]
		if !ok {
			return ErrCurrentFacts
		}
		path := filepath.Join(directory, entry.Name())
		fileInfo, err := os.Lstat(path)
		stat, statOK := infoSysStat(fileInfo)
		if err != nil || !statOK || !fileInfo.Mode().IsRegular() || fileInfo.Mode().Perm() != mode ||
			stat.Uid != service.config.OwnerUID || stat.Gid != service.config.OwnerGID || stat.Nlink != 1 {
			return ErrCurrentFacts
		}
	}
	for _, entry := range entries {
		if err := os.Remove(filepath.Join(directory, entry.Name())); err != nil {
			return err
		}
	}
	if err := syncHelperDirectory(directory); err != nil {
		return err
	}
	if err := os.Remove(directory); err != nil {
		return err
	}
	return service.syncTransactions()
}

func (service *Service) inspectTransaction(transactionID string) (protocol.TransactionStatus, protocol.ErrorCode) {
	var status protocol.TransactionStatus
	var code protocol.ErrorCode
	err := service.journals.withStoreLock(func() error {
		record, err := service.journals.loadLocked(transactionID)
		if errors.Is(err, ErrJournalNotFound) {
			status = protocol.TransactionStatus{TransactionID: transactionID, Phase: protocol.TransactionUnknown}
			return nil
		}
		if err != nil {
			code = protocol.ErrorStateUncertain
			return nil
		}
		ack := preparedAck(record)
		status = protocol.TransactionStatus{TransactionID: transactionID, PreparedAck: &ack}
		switch record.Phase {
		case JournalPrepared:
			status.Phase = protocol.TransactionPrepared
		case JournalAborted:
			if requireOwnedDirectory(service.transactions, stateDirMode, service.config.OwnerUID, service.config.OwnerGID, true) != nil {
				code = protocol.ErrorStateUncertain
				return nil
			}
			if _, err := os.Lstat(filepath.Join(service.transactions, transactionID)); !errors.Is(err, os.ErrNotExist) {
				code = protocol.ErrorStateUncertain
				return nil
			}
			if service.syncTransactions() != nil {
				code = protocol.ErrorStateUncertain
				return nil
			}
			status.Phase = protocol.TransactionAborted
		case JournalInstalling:
			status.Phase = protocol.TransactionInstalling
		case JournalActive:
			if record.ActiveReceipt == nil {
				code = protocol.ErrorStateUncertain
				return nil
			}
			facts, err := InspectInstalled(service.config.Paths, service.config.ReleasePublicKey, service.config.OwnerUID, service.config.OwnerGID)
			if err != nil {
				code = protocol.ErrorStateUncertain
				return nil
			}
			if _, ok := service.ensureActiveCurrentLocked(*record.ActiveReceipt, facts); !ok {
				code = protocol.ErrorStateUncertain
				return nil
			}
			status.Phase = protocol.TransactionActive
			status.Receipt = record.ActiveReceipt
		case JournalRolledBack:
			if record.RollbackReceipt == nil || !service.persistedReceiptUsable(*record.RollbackReceipt) {
				code = protocol.ErrorStateUncertain
				return nil
			}
			facts, err := InspectInstalled(service.config.Paths, service.config.ReleasePublicKey, service.config.OwnerUID, service.config.OwnerGID)
			if err != nil {
				code = protocol.ErrorStateUncertain
				return nil
			}
			if _, ok := service.recoverRolledBackCurrentLocked(record, facts); !ok {
				code = protocol.ErrorStateUncertain
				return nil
			}
			status.Phase = protocol.TransactionRolledBack
			status.Receipt = record.RollbackReceipt
		default:
			code = protocol.ErrorStateUncertain
		}
		return nil
	})
	if err != nil {
		return protocol.TransactionStatus{}, protocol.ErrorStateUncertain
	}
	return status, code
}

func preparedAck(record JournalRecord) protocol.PreparedAck {
	schemaVersion := 1
	if record.SchemaVersion == journalSchemaVersionV3 {
		schemaVersion = 2
	}
	return protocol.PreparedAck{
		SchemaVersion: schemaVersion, TransactionID: record.TransactionID, InstallPayloadSHA256: record.InstallPayloadSHA256,
		ExecutionSequence: record.ExecutionSequence,
		ReleaseSequence:   record.ReleaseSequence, ArtifactSHA256: record.OuterArtifactSHA256,
		ManifestSHA256: record.ManifestSHA256, ExecutableSHA256: record.ExecutableSHA256, SBOMSHA256: record.SBOMSHA256,
		PreviousVersion: record.PreviousVersion, TargetVersion: record.TargetVersion,
	}
}

func installedTargetMatches(record JournalRecord, facts InstalledFacts) bool {
	return facts.Version == record.TargetVersion && facts.ReleaseSequence == record.ReleaseSequence && facts.AcceptedSequence == record.ReleaseSequence &&
		facts.ManifestSHA256 == record.ManifestSHA256 && facts.ExecutableSHA256 == record.ExecutableSHA256 &&
		facts.OuterArtifactSHA256 == record.OuterArtifactSHA256
}

func unresolvedInstallBlocksCurrent(records []JournalRecord, facts InstalledFacts) bool {
	var highestUnresolved uint64
	for _, record := range records {
		sequence := journalSequence(record)
		if (record.Phase == JournalPrepared || record.Phase == JournalInstalling) && sequence > highestUnresolved {
			highestUnresolved = sequence
		}
	}
	if highestUnresolved == 0 {
		return false
	}
	for _, record := range records {
		if journalSequence(record) < highestUnresolved {
			continue
		}
		if record.Phase == JournalActive && installedTargetMatches(record, facts) {
			return false
		}
		if record.Phase == JournalRolledBack && (record.SchemaVersion == journalSchemaVersionV3 || facts.AcceptedSequence == record.ReleaseSequence) && installedPreviousMatches(record, facts) {
			return false
		}
	}
	return true
}

func (service *Service) installedTargetMatches(record JournalRecord, facts InstalledFacts) bool {
	if !installedTargetMatches(record, facts) {
		return false
	}
	accepted, err := readInstalledFile(service.config.Paths.AcceptedManifest, 0o600, service.config.OwnerUID, service.config.OwnerGID, MaxManifestBytes)
	if err != nil {
		return false
	}
	manifest, err := parseReleaseManifest(accepted)
	return err == nil && manifest.ReleaseSequence == record.ReleaseSequence
}

func installedPreviousMatches(record JournalRecord, facts InstalledFacts) bool {
	if record.PreviousReceipt == nil || facts.Version != record.PreviousVersion || facts.OuterArtifactSHA256 != record.PreviousReceipt.ArtifactSHA256 {
		return false
	}
	if record.SchemaVersion == legacyJournalSchemaVersion {
		return facts.ReleaseSequence == record.PreviousReceipt.ReleaseSequence
	}
	return (record.SchemaVersion == journalSchemaVersion || record.SchemaVersion == journalSchemaVersionV3) &&
		facts.ReleaseSequence == record.PreviousPhysicalReleaseSequence &&
		facts.ManifestSHA256 == record.PreviousManifestSHA256
}

func (service *Service) migrateLegacyInFlightLocked(record JournalRecord, facts InstalledFacts, stored protocol.Receipt, manifestSHA256 string) (JournalRecord, error) {
	if record.SchemaVersion != legacyJournalSchemaVersion ||
		(record.Phase != JournalPrepared && record.Phase != JournalInstalling) || record.PreviousReceipt == nil ||
		!sameReceipt(stored, *record.PreviousReceipt) || manifestSHA256 != facts.ManifestSHA256 ||
		facts.Version != record.PreviousVersion || facts.ReleaseSequence != record.PreviousReceipt.ReleaseSequence ||
		facts.AcceptedSequence != record.PreviousReceipt.ReleaseSequence || facts.OuterArtifactSHA256 != record.PreviousReceipt.ArtifactSHA256 ||
		facts.ReleaseSequence >= record.ReleaseSequence {
		return JournalRecord{}, ErrCurrentFacts
	}
	migrated := record
	migrated.SchemaVersion = journalSchemaVersion
	migrated.PreviousPhysicalReleaseSequence = facts.ReleaseSequence
	migrated.PreviousManifestSHA256 = facts.ManifestSHA256
	if err := service.journals.migrateLegacyInFlightLocked(record, migrated); err != nil {
		return JournalRecord{}, err
	}
	return migrated, nil
}

func (service *Service) currentReceiptMatches(receipt protocol.Receipt, facts InstalledFacts) bool {
	stored, manifestDigest, err := service.current.Load()
	return err == nil && manifestDigest == facts.ManifestSHA256 && receiptFactsMatch(stored, receipt) && service.persistedReceiptUsable(stored)
}

func (service *Service) ensureActiveCurrentLocked(receipt protocol.Receipt, facts InstalledFacts) (protocol.Receipt, bool) {
	if !service.persistedReceiptUsable(receipt) {
		return protocol.Receipt{}, false
	}
	trusted, hasActive, err := service.journals.activeReceiptForFactsLocked(facts)
	if err != nil || !hasActive || !sameReceipt(trusted, receipt) {
		return protocol.Receipt{}, false
	}
	record, err := service.journals.loadLocked(receipt.InstallerTransactionID)
	if err != nil || record.Phase != JournalActive || !service.installedTargetMatches(record, facts) {
		return protocol.Receipt{}, false
	}
	highWater, err := service.journals.highWaterMarkLocked()
	if err != nil || highWater != receiptSequence(receipt) {
		return protocol.Receipt{}, false
	}
	stored, manifestDigest, loadErr := service.current.Load()
	switch {
	case errors.Is(loadErr, os.ErrNotExist):
	case loadErr != nil || !service.persistedReceiptUsable(stored):
		return protocol.Receipt{}, false
	case manifestDigest == facts.ManifestSHA256 && receiptFactsMatch(stored, receipt):
		if service.receiptSignedByCurrentKey(stored) {
			return stored, true
		}
	case record.PreviousReceipt != nil && sameReceipt(stored, *record.PreviousReceipt):
	default:
		return protocol.Receipt{}, false
	}
	repaired := receipt
	if SignReceipt(&repaired, service.config.ReceiptKey) != nil || service.current.Save(repaired, facts.ManifestSHA256) != nil {
		return protocol.Receipt{}, false
	}
	return repaired, true
}

func receiptFactsMatch(left, right protocol.Receipt) bool {
	left.Signature = protocol.Signature{}
	right.Signature = protocol.Signature{}
	return sameReceipt(left, right)
}

func (service *Service) recoverRolledBackCurrentLocked(record JournalRecord, facts InstalledFacts) (protocol.Receipt, bool) {
	// An explicit rollback follows an accepted target, so packaging's accepted
	// manifest is the target's. An automatic rollback (the target never became
	// active) never published it: the accepted sequence stays below the target.
	acceptedConsistent := facts.AcceptedSequence == record.ReleaseSequence ||
		record.ActiveReceipt == nil && facts.AcceptedSequence < record.ReleaseSequence
	if record.Phase != JournalRolledBack || record.PreviousReceipt == nil || record.RollbackReceipt == nil ||
		!service.persistedReceiptUsable(*record.RollbackReceipt) || !acceptedConsistent ||
		!installedPreviousMatches(record, facts) {
		return protocol.Receipt{}, false
	}
	records, err := service.journals.recordsLocked()
	if err != nil {
		return protocol.Receipt{}, false
	}
	var highest uint64
	for _, candidate := range records {
		sequence := journalSequence(candidate)
		if candidate.Phase != JournalAborted && sequence > highest {
			highest = sequence
		}
	}
	rolledBackAtHighest := 0
	for _, candidate := range records {
		if candidate.Phase == JournalRolledBack && journalSequence(candidate) == highest {
			rolledBackAtHighest++
		}
	}
	if journalSequence(record) != highest || rolledBackAtHighest != 1 {
		return protocol.Receipt{}, false
	}

	stored, manifestSHA256, loadErr := service.current.Load()
	switch {
	case errors.Is(loadErr, os.ErrNotExist):
	case loadErr != nil || !service.persistedReceiptUsable(stored):
		return protocol.Receipt{}, false
	case record.ActiveReceipt != nil && manifestSHA256 == record.ManifestSHA256 && receiptFactsMatch(stored, *record.ActiveReceipt):
	case manifestSHA256 == facts.ManifestSHA256 && receiptFactsMatch(stored, *record.PreviousReceipt):
	case service.restoredCurrentReceiptMatches(record, facts, stored, manifestSHA256):
		if service.receiptSignedByCurrentKey(stored) {
			return stored, true
		}
		rotated := stored
		if SignReceipt(&rotated, service.config.ReceiptKey) != nil || service.current.Save(rotated, facts.ManifestSHA256) != nil {
			return protocol.Receipt{}, false
		}
		return rotated, true
	default:
		return protocol.Receipt{}, false
	}
	if service.saveRestoredCurrent(record, facts) != nil {
		return protocol.Receipt{}, false
	}
	restored, restoredManifestSHA256, err := service.current.Load()
	if err != nil || !service.restoredCurrentReceiptMatches(record, facts, restored, restoredManifestSHA256) {
		return protocol.Receipt{}, false
	}
	return restored, true
}

func (service *Service) restoredCurrentReceiptMatches(record JournalRecord, facts InstalledFacts, stored protocol.Receipt, manifestSHA256 string) bool {
	sequenceMatches := stored.SchemaVersion == 1 && stored.ExecutionSequence == 0
	if record.SchemaVersion == journalSchemaVersionV3 {
		sequenceMatches = stored.SchemaVersion == 2 && stored.ExecutionSequence == record.ExecutionSequence
	}
	return record.PreviousReceipt != nil && manifestSHA256 == facts.ManifestSHA256 && service.persistedReceiptUsable(stored) &&
		sequenceMatches &&
		stored.InstallerTransactionID == currentTransactionID(facts, record.ReleaseSequence) && stored.Status == "active" &&
		stored.ReleaseSequence == record.ReleaseSequence && stored.CurrentVersion == record.PreviousVersion &&
		stored.PreviousVersion == record.TargetVersion && stored.ArtifactSHA256 == record.PreviousReceipt.ArtifactSHA256
}

func (service *Service) persistActive(record JournalRecord, facts InstalledFacts) (protocol.Receipt, protocol.ErrorCode) {
	receipt := service.newReceiptForRecord(record, record.TargetVersion, record.PreviousVersion, "active")
	if SignReceipt(&receipt, service.config.ReceiptKey) != nil {
		return protocol.Receipt{}, protocol.ErrorInternal
	}
	record.Phase = JournalActive
	record.ActiveReceipt = &receipt
	if service.journals.saveLocked(record) != nil || service.current.Save(receipt, facts.ManifestSHA256) != nil {
		return protocol.Receipt{}, protocol.ErrorStateUncertain
	}
	return receipt, ""
}

func (service *Service) query(ctx context.Context, transactionID string) (protocol.Receipt, protocol.ErrorCode) {
	var receipt protocol.Receipt
	var code protocol.ErrorCode
	err := service.journals.withStoreLock(func() error {
		record, err := service.journals.loadLocked(transactionID)
		if errors.Is(err, ErrJournalNotFound) {
			code = protocol.ErrorTransactionUnknown
			return nil
		}
		if err != nil {
			code = protocol.ErrorStateUncertain
			return nil
		}
		switch record.Phase {
		case JournalPrepared, JournalInstalling, JournalActive:
			receipt, code = service.completeInstallLocked(ctx, record)
		case JournalRollbacking:
			receipt, code = service.completeRollbackLocked(ctx, record)
		case JournalRolledBack:
			if record.RollbackReceipt == nil || !service.persistedReceiptUsable(*record.RollbackReceipt) {
				code = protocol.ErrorStateUncertain
				return nil
			}
			facts, err := InspectInstalled(service.config.Paths, service.config.ReleasePublicKey, service.config.OwnerUID, service.config.OwnerGID)
			if err != nil {
				code = protocol.ErrorStateUncertain
				return nil
			}
			if _, ok := service.recoverRolledBackCurrentLocked(record, facts); !ok {
				code = protocol.ErrorStateUncertain
				return nil
			}
			receipt = *record.RollbackReceipt
		default:
			code = protocol.ErrorStateUncertain
		}
		return nil
	})
	if err != nil {
		return protocol.Receipt{}, protocol.ErrorStateUncertain
	}
	return receipt, code
}

func (service *Service) rollback(ctx context.Context, packet []byte, request protocol.Request) (protocol.Receipt, protocol.ErrorCode) {
	var receipt protocol.Receipt
	var code protocol.ErrorCode
	err := service.journals.withStoreLock(func() error {
		record, err := service.journals.loadLocked(request.TransactionID)
		if errors.Is(err, ErrJournalNotFound) {
			code = protocol.ErrorTransactionUnknown
			return nil
		}
		if err != nil {
			code = protocol.ErrorStateUncertain
			return nil
		}
		receipt, code = service.rollbackLocked(ctx, packet, request, record)
		return nil
	})
	if err != nil {
		return protocol.Receipt{}, protocol.ErrorStateUncertain
	}
	return receipt, code
}

func (service *Service) rollbackLocked(ctx context.Context, packet []byte, request protocol.Request, record JournalRecord) (protocol.Receipt, protocol.ErrorCode) {
	if record.Phase == JournalRolledBack {
		if record.MatchRollbackPayload(packet) != nil {
			return protocol.Receipt{}, protocol.ErrorTransactionConflict
		}
		if record.RollbackReceipt == nil || !service.persistedReceiptUsable(*record.RollbackReceipt) {
			return protocol.Receipt{}, protocol.ErrorStateUncertain
		}
		facts, err := InspectInstalled(service.config.Paths, service.config.ReleasePublicKey, service.config.OwnerUID, service.config.OwnerGID)
		if err != nil {
			return protocol.Receipt{}, protocol.ErrorStateUncertain
		}
		if _, ok := service.recoverRolledBackCurrentLocked(record, facts); !ok {
			return protocol.Receipt{}, protocol.ErrorStateUncertain
		}
		return *record.RollbackReceipt, ""
	}
	if record.Phase == JournalRollbacking {
		if record.MatchRollbackPayload(packet) != nil {
			return protocol.Receipt{}, protocol.ErrorTransactionConflict
		}
		return service.completeRollbackLocked(ctx, record)
	}
	if record.ActiveReceipt != nil && !service.persistedReceiptUsable(*record.ActiveReceipt) ||
		record.PreviousReceipt != nil && !service.persistedReceiptUsable(*record.PreviousReceipt) {
		return protocol.Receipt{}, protocol.ErrorStateUncertain
	}
	if record.Phase != JournalActive || request.ActiveReceipt == nil || request.PreviousReceipt == nil ||
		!sameReceipt(*request.ActiveReceipt, *record.ActiveReceipt) || record.PreviousReceipt == nil ||
		!sameReceipt(*request.PreviousReceipt, *record.PreviousReceipt) || request.ReleaseSequence != record.ReleaseSequence ||
		request.ArtifactSHA256 != record.OuterArtifactSHA256 || request.ExpectedCurrentVersion != record.TargetVersion ||
		request.RollbackVersion != record.PreviousVersion {
		return protocol.Receipt{}, protocol.ErrorTransactionConflict
	}
	facts, err := InspectInstalled(service.config.Paths, service.config.ReleasePublicKey, service.config.OwnerUID, service.config.OwnerGID)
	if err != nil || !service.installedTargetMatches(record, facts) {
		return protocol.Receipt{}, protocol.ErrorStateUncertain
	}
	if code := service.rollbackFenceLocked(record, facts); code != "" {
		return protocol.Receipt{}, code
	}
	if _, ok := service.ensureActiveCurrentLocked(*record.ActiveReceipt, facts); !ok {
		return protocol.Receipt{}, protocol.ErrorStateUncertain
	}
	record.Phase = JournalRollbacking
	record.RollbackPayloadSHA256 = HashCanonicalPayload(packet)
	if service.journals.saveLocked(record) != nil {
		return protocol.Receipt{}, protocol.ErrorStateUncertain
	}
	return service.completeRollbackLocked(ctx, record)
}

func (service *Service) completeRollback(ctx context.Context, record JournalRecord) (protocol.Receipt, protocol.ErrorCode) {
	var receipt protocol.Receipt
	var code protocol.ErrorCode
	err := service.journals.withStoreLock(func() error {
		latest, err := service.journals.loadLocked(record.TransactionID)
		if err != nil {
			code = protocol.ErrorStateUncertain
			if errors.Is(err, ErrJournalNotFound) {
				code = protocol.ErrorTransactionUnknown
			}
			return nil
		}
		receipt, code = service.completeRollbackLocked(ctx, latest)
		return nil
	})
	if err != nil {
		return protocol.Receipt{}, protocol.ErrorStateUncertain
	}
	return receipt, code
}

func (service *Service) completeRollbackLocked(ctx context.Context, record JournalRecord) (protocol.Receipt, protocol.ErrorCode) {
	facts, inspectErr := InspectInstalled(service.config.Paths, service.config.ReleasePublicKey, service.config.OwnerUID, service.config.OwnerGID)
	if inspectErr != nil {
		return protocol.Receipt{}, protocol.ErrorStateUncertain
	}
	if code := service.rollbackFenceLocked(record, facts); code != "" {
		return protocol.Receipt{}, code
	}
	if installedPreviousMatches(record, facts) {
		return service.persistRollback(record, facts)
	}
	if !service.installedTargetMatches(record, facts) || record.ActiveReceipt == nil || !service.currentReceiptMatches(*record.ActiveReceipt, facts) {
		return protocol.Receipt{}, protocol.ErrorStateUncertain
	}
	runErr := service.config.Runner.Rollback(ctx, record.PreviousVersion)
	facts, inspectErr = InspectInstalled(service.config.Paths, service.config.ReleasePublicKey, service.config.OwnerUID, service.config.OwnerGID)
	if inspectErr != nil {
		if runErr != nil {
			return protocol.Receipt{}, protocol.ErrorRollbackFailed
		}
		return protocol.Receipt{}, protocol.ErrorStateUncertain
	}
	if code := service.rollbackFenceLocked(record, facts); code != "" {
		return protocol.Receipt{}, code
	}
	if installedPreviousMatches(record, facts) {
		return service.persistRollback(record, facts)
	}
	if service.installedTargetMatches(record, facts) && runErr != nil {
		return protocol.Receipt{}, protocol.ErrorRollbackFailed
	}
	return protocol.Receipt{}, protocol.ErrorStateUncertain
}

func (service *Service) rollbackFenceLocked(record JournalRecord, facts InstalledFacts) protocol.ErrorCode {
	if facts.AcceptedSequence != record.ReleaseSequence {
		return protocol.ErrorTransactionConflict
	}
	highWater, err := service.journals.highWaterMarkLockedExcept(record.TransactionID)
	if err != nil {
		return protocol.ErrorStateUncertain
	}
	attemptSequence := record.ReleaseSequence
	if record.SchemaVersion == journalSchemaVersionV3 {
		attemptSequence = record.ExecutionSequence
	}
	if highWater >= attemptSequence {
		return protocol.ErrorTransactionConflict
	}
	return ""
}

func (service *Service) persistRollback(record JournalRecord, facts InstalledFacts) (protocol.Receipt, protocol.ErrorCode) {
	if !installedPreviousMatches(record, facts) {
		return protocol.Receipt{}, protocol.ErrorStateUncertain
	}
	receipt := service.newReceiptForRecord(record, record.PreviousVersion, record.TargetVersion, "rolled_back")
	if SignReceipt(&receipt, service.config.ReceiptKey) != nil {
		return protocol.Receipt{}, protocol.ErrorInternal
	}
	record.Phase = JournalRolledBack
	record.RollbackReceipt = &receipt
	if service.journals.saveLocked(record) != nil || service.saveRestoredCurrent(record, facts) != nil {
		return protocol.Receipt{}, protocol.ErrorStateUncertain
	}
	return receipt, ""
}

func (service *Service) saveRestoredCurrent(record JournalRecord, facts InstalledFacts) error {
	artifactDigest := facts.OuterArtifactSHA256
	if record.PreviousReceipt != nil {
		artifactDigest = record.PreviousReceipt.ArtifactSHA256
	}
	receipt := service.newReceipt(currentTransactionID(facts, record.ReleaseSequence), record.ReleaseSequence, artifactDigest, record.PreviousVersion, record.TargetVersion, "active")
	if record.SchemaVersion == journalSchemaVersionV3 {
		receipt.SchemaVersion = 2
		receipt.ExecutionSequence = record.ExecutionSequence
	}
	if err := SignReceipt(&receipt, service.config.ReceiptKey); err != nil {
		return err
	}
	return service.current.Save(receipt, facts.ManifestSHA256)
}

func (service *Service) prepareTransactionDirectory(directory string) error {
	if info, err := os.Lstat(directory); err == nil {
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || requireOwnedDirectory(directory, stateDirMode, service.config.OwnerUID, service.config.OwnerGID, true) != nil {
			return ErrCurrentFacts
		}
		entries, err := os.ReadDir(directory)
		if err != nil {
			return err
		}
		allowed := map[string]os.FileMode{
			"manifest": 0o400, "manifest.sig": 0o400,
			"edge-agent.spdx.json": 0o400, "edge-agent": 0o500, NativeSectionName: 0o400,
		}
		for _, entry := range entries {
			mode, ok := allowed[entry.Name()]
			if !ok {
				return ErrCurrentFacts
			}
			path := filepath.Join(directory, entry.Name())
			fileInfo, err := os.Lstat(path)
			stat, statOK := infoSysStat(fileInfo)
			if err != nil || !statOK || !fileInfo.Mode().IsRegular() || fileInfo.Mode().Perm() != mode ||
				stat.Uid != service.config.OwnerUID || stat.Gid != service.config.OwnerGID || stat.Nlink != 1 {
				return ErrCurrentFacts
			}
		}
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.Mkdir(directory, stateDirMode); err != nil {
		return err
	}
	return syncHelperDirectory(service.transactions)
}

func (service *Service) transactionDirectoryMatches(directory string, staged StagedBundle) (bool, error) {
	if err := service.prepareTransactionDirectory(directory); err != nil {
		return false, err
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		return false, err
	}
	sections := 4
	if staged.NativePath != "" {
		sections = 5
	}
	if len(entries) != sections {
		return false, nil
	}
	allowed := map[string]struct{}{"manifest": {}, "manifest.sig": {}, "edge-agent.spdx.json": {}, "edge-agent": {}}
	if staged.NativePath != "" {
		allowed[NativeSectionName] = struct{}{}
	}
	for _, entry := range entries {
		if _, ok := allowed[entry.Name()]; !ok {
			return false, nil
		}
	}
	checks := []struct {
		name   string
		path   string
		size   int64
		digest string
		mode   os.FileMode
	}{
		{name: "manifest", path: filepath.Join(directory, "manifest"), size: staged.ManifestSize, digest: staged.ManifestSHA256, mode: 0400},
		{name: "manifest.sig", path: filepath.Join(directory, "manifest.sig"), size: SignatureBytes, digest: staged.SignatureSHA256, mode: 0400},
		{name: "edge-agent.spdx.json", path: filepath.Join(directory, "edge-agent.spdx.json"), size: staged.SBOMSize, digest: staged.SBOMSHA256, mode: 0400},
		{name: "edge-agent", path: filepath.Join(directory, "edge-agent"), size: staged.ExecutableSize, digest: staged.ExecutableSHA256, mode: 0500},
	}
	if staged.NativePath != "" {
		checks = append(checks, struct {
			name   string
			path   string
			size   int64
			digest string
			mode   os.FileMode
		}{name: NativeSectionName, path: filepath.Join(directory, NativeSectionName), size: staged.NativeSize, digest: staged.NativeSHA256, mode: 0400})
	}
	for _, check := range checks {
		if _, err := readVerifiedStagedFile(check.path, check.size, check.digest, check.mode, false); err != nil {
			return false, nil
		}
	}
	return true, nil
}

func (service *Service) newReceipt(transactionID string, sequence uint64, artifactDigest, currentVersion, previousVersion, status string) protocol.Receipt {
	return protocol.Receipt{
		SchemaVersion: 1, InstallerTransactionID: transactionID, ReleaseSequence: sequence,
		ArtifactSHA256: artifactDigest, CurrentVersion: currentVersion, PreviousVersion: previousVersion,
		Status: status, IssuedAt: service.config.Now().UTC(),
	}
}

func (service *Service) newReceiptForRecord(record JournalRecord, currentVersion, previousVersion, status string) protocol.Receipt {
	receipt := service.newReceipt(record.TransactionID, record.ReleaseSequence, record.OuterArtifactSHA256, currentVersion, previousVersion, status)
	if record.SchemaVersion == journalSchemaVersionV3 {
		receipt.SchemaVersion = 2
		receipt.ExecutionSequence = record.ExecutionSequence
	}
	return receipt
}

func (service *Service) persistedReceiptUsable(receipt protocol.Receipt) bool {
	if protocol.ValidateResponse(protocol.Success(receipt)) != nil {
		return false
	}
	publicKey, ok := service.receiptKeys[receipt.Signature.KeyID]
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

func (service *Service) receiptSignedByCurrentKey(receipt protocol.Receipt) bool {
	if receipt.Signature.KeyID != service.config.ReceiptKey.KeyID {
		return false
	}
	return service.persistedReceiptUsable(receipt)
}

func receiptSequence(receipt protocol.Receipt) uint64 {
	if receipt.SchemaVersion == 2 {
		return receipt.ExecutionSequence
	}
	return receipt.ReleaseSequence
}

func containsV3Journal(records []JournalRecord) bool {
	for _, record := range records {
		if record.SchemaVersion == journalSchemaVersionV3 {
			return true
		}
	}
	return false
}

func highestV3Execution(records []JournalRecord) uint64 {
	var highest uint64
	for _, record := range records {
		if record.SchemaVersion == journalSchemaVersionV3 && record.ExecutionSequence > highest {
			highest = record.ExecutionSequence
		}
	}
	return highest
}

func (service *Service) stagedFromJournal(record JournalRecord) (StagedBundle, error) {
	directory := filepath.Join(service.transactions, record.TransactionID)
	if err := requireOwnedDirectory(directory, stateDirMode, service.config.OwnerUID, service.config.OwnerGID, true); err != nil {
		return StagedBundle{}, err
	}
	manifestSize, manifestDigest, err := protectedFileFacts(filepath.Join(directory, "manifest"), 0o400, service.config.OwnerUID, service.config.OwnerGID, MaxManifestBytes)
	if err != nil || manifestDigest != record.ManifestSHA256 {
		return StagedBundle{}, ErrInvalidBundle
	}
	_, signatureDigest, err := protectedFileFacts(filepath.Join(directory, "manifest.sig"), 0o400, service.config.OwnerUID, service.config.OwnerGID, SignatureBytes)
	if err != nil {
		return StagedBundle{}, ErrInvalidBundle
	}
	sbomSize, sbomDigest, err := protectedFileFacts(filepath.Join(directory, "edge-agent.spdx.json"), 0o400, service.config.OwnerUID, service.config.OwnerGID, MaxSBOMBytes)
	if err != nil || sbomDigest != record.SBOMSHA256 {
		return StagedBundle{}, ErrInvalidBundle
	}
	executableSize, executableDigest, err := protectedFileFacts(filepath.Join(directory, "edge-agent"), 0o500, service.config.OwnerUID, service.config.OwnerGID, MaxExecutableBytes)
	if err != nil || executableDigest != record.ExecutableSHA256 {
		return StagedBundle{}, ErrInvalidBundle
	}
	var nativePath, nativeDigest string
	var nativeSize int64
	if record.NativeSHA256 != "" {
		nativePath = filepath.Join(directory, NativeSectionName)
		nativeSize, nativeDigest, err = protectedFileFacts(nativePath, 0o400, service.config.OwnerUID, service.config.OwnerGID, MaxNativeBytes)
		if err != nil || nativeDigest != record.NativeSHA256 {
			return StagedBundle{}, ErrInvalidBundle
		}
	}
	return StagedBundle{
		NativePath: nativePath, NativeSHA256: nativeDigest, NativeSize: nativeSize,
		Directory: directory, ManifestPath: filepath.Join(directory, "manifest"),
		SignaturePath: filepath.Join(directory, "manifest.sig"), SBOMPath: filepath.Join(directory, "edge-agent.spdx.json"),
		ExecutablePath: filepath.Join(directory, "edge-agent"), OuterSHA256: record.OuterArtifactSHA256,
		ManifestSHA256: manifestDigest, ManifestSize: manifestSize, SignatureSHA256: signatureDigest,
		SBOMSHA256: sbomDigest, SBOMSize: sbomSize, ExecutableSHA256: executableDigest, ExecutableSize: executableSize,
	}, nil
}

func protectedFileFacts(path string, mode os.FileMode, uid, gid uint32, maximum int64) (int64, string, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return 0, "", err
	}
	file := os.NewFile(uintptr(fd), filepath.Base(path))
	if file == nil {
		_ = unix.Close(fd)
		return 0, "", ErrInvalidBundle
	}
	defer file.Close()
	var stat unix.Stat_t
	if unix.Fstat(fd, &stat) != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Nlink != 1 || stat.Size <= 0 || stat.Size > maximum ||
		uint32(stat.Uid) != uid || uint32(stat.Gid) != gid || os.FileMode(stat.Mode).Perm() != mode {
		return 0, "", ErrInvalidBundle
	}
	hash := sha256.New()
	written, err := io.Copy(hash, file)
	if err != nil || written != stat.Size {
		return 0, "", ErrInvalidBundle
	}
	return stat.Size, hex.EncodeToString(hash.Sum(nil)), nil
}

func bundleErrorCode(err error) protocol.ErrorCode {
	switch {
	case errors.Is(err, ErrUnsafeArtifactFD):
		return protocol.ErrorFDUnsafe
	case errors.Is(err, ErrArtifactMismatch), errors.Is(err, ErrInvalidBundle):
		return protocol.ErrorArtifactMismatch
	default:
		return protocol.ErrorInternal
	}
}

func Serve(ctx context.Context, listener *Listener, service *Service) error {
	if listener == nil || service == nil {
		return fmt.Errorf("helper service is unavailable")
	}
	for {
		exchange, err := listener.Accept(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if _, ok := ErrorCode(err); ok {
				continue
			}
			return err
		}
		response := service.Handle(exchange.Context, exchange.Packet, exchange.Request, exchange.Artifact)
		respondErr := exchange.Respond(exchange.Context, response)
		closeErr := exchange.Close()
		if respondErr != nil && !errors.Is(respondErr, context.Canceled) && !errors.Is(respondErr, context.DeadlineExceeded) {
			continue
		}
		if closeErr != nil {
			continue
		}
	}
}
