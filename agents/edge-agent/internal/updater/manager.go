package updater

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"sync"
	"time"
)

type Manager struct {
	mu          sync.Mutex
	store       *diskStore
	fs          *anchoredUpgradeFS
	config      Config
	downloader  Downloader
	installer   Installer
	installerV2 InstallerV2
	probe       Probe
	clock       Clock
}

var ErrInstallerLegacyActivated = errors.New("installer activated through legacy protocol")

type preparedUpgrade struct {
	InstallerTransactionID string
	Complete               bool
	Result                 Result
}

func NewManager(config Config) (*Manager, error) {
	if config.Platform == "" || config.Architecture == "" || config.AgentVersion == "" || !safeIDPattern.MatchString(config.NodeID) ||
		config.Downloader == nil || config.Installer == nil || config.Probe == nil ||
		config.MaxArtifactBytes <= 0 || config.DiskReserveBytes < 0 {
		return nil, fmt.Errorf("%w: updater configuration", ErrInvalidPlan)
	}
	installerV2, transactional := config.Installer.(InstallerV2)
	if transactional && installerV2.ProtocolVersion() != InstallerProtocolV2 {
		return nil, fmt.Errorf("%w: installer protocol", ErrIncompatible)
	}
	if _, err := parseVersion(config.AgentVersion); err != nil {
		return nil, fmt.Errorf("%w: configured agent version", ErrInvalidPlan)
	}
	var err error
	config.Keys, err = copyKeyRing(config.Keys)
	if err != nil {
		return nil, err
	}
	config.ReceiptKeys, err = copyKeyRing(config.ReceiptKeys)
	if err != nil {
		return nil, err
	}
	if config.Clock == nil {
		config.Clock = realClock{}
	}
	store, err := newDiskStore(config.Root)
	if err != nil {
		return nil, err
	}
	fs, err := newAnchoredUpgradeFS(store, false)
	if err != nil {
		return nil, err
	}
	manager := &Manager{
		store: store, fs: fs, config: config, downloader: config.Downloader,
		installer: config.Installer, probe: config.Probe, clock: config.Clock,
	}
	if transactional {
		manager.installerV2 = installerV2
	}
	return manager, nil
}

func copyKeyRing(source map[string]ed25519.PublicKey) (map[string]ed25519.PublicKey, error) {
	if len(source) == 0 {
		return nil, fmt.Errorf("%w: empty keyring", ErrInvalidPlan)
	}
	keys := make(map[string]ed25519.PublicKey, len(source))
	for keyID, key := range source {
		if !safeIDPattern.MatchString(keyID) || len(key) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("%w: keyring", ErrInvalidPlan)
		}
		keys[keyID] = append(ed25519.PublicKey(nil), key...)
	}
	return keys, nil
}

func (m *Manager) Process(ctx context.Context, plan Plan) (Result, error) {
	unlock, err := m.lockState(ctx)
	if err != nil {
		return Result{}, err
	}
	defer unlock()
	prepared, value, err := m.prepareLocked(ctx, plan)
	if err != nil {
		return Result{}, err
	}
	if prepared.Complete {
		return prepared.Result, nil
	}
	if err := m.prepareInstallerV2(ctx, value); err != nil {
		return Result{}, err
	}
	if value.Phase == phaseDone {
		return value.Result, errorForCode(value.Result.ErrorCode)
	}
	return m.run(ctx, value)
}

func (m *Manager) prepare(ctx context.Context, plan Plan) (preparedUpgrade, error) {
	unlock, err := m.lockState(ctx)
	if err != nil {
		return preparedUpgrade{}, err
	}
	defer unlock()
	prepared, value, err := m.prepareLocked(ctx, plan)
	if err == nil && !prepared.Complete {
		if err = m.prepareInstallerV2(ctx, value); err == nil && value != nil && value.Phase == phaseDone {
			prepared.Complete = true
			prepared.Result = value.Result
		}
	}
	return prepared, err
}

func (m *Manager) prepareLocked(ctx context.Context, plan Plan) (preparedUpgrade, *transaction, error) {
	existing, err := m.fs.loadTransaction()
	if err != nil {
		return preparedUpgrade{}, nil, err
	}
	digest, err := planDigest(plan)
	if err != nil {
		return preparedUpgrade{}, nil, ErrInvalidPlan
	}
	resume := existing != nil && existing.Plan.PlanID == plan.PlanID && existing.Plan.Revision == plan.Revision && existing.Digest == digest
	if err := validatePlan(plan, m.config, m.clock.Now().UTC(), resume); err != nil {
		return preparedUpgrade{}, nil, err
	}
	if existing != nil {
		if resume {
			prepared := preparedUpgrade{InstallerTransactionID: existing.InstallerTransactionID}
			if existing.Phase == phaseDone {
				result := existing.Result
				result.Duplicate = true
				prepared.Complete = true
				prepared.Result = result
			}
			return prepared, existing, nil
		}
		if existing.Phase != phaseDone {
			return preparedUpgrade{}, nil, ErrReplay
		}
		if existing.Plan.SchemaVersion == planSchemaVersionV3 {
			if plan.SchemaVersion != planSchemaVersionV3 || plan.ExecutionSequence <= existing.Plan.ExecutionSequence {
				return preparedUpgrade{}, nil, ErrReplay
			}
		} else if plan.SchemaVersion != planSchemaVersionV3 &&
			(plan.Revision <= existing.Plan.Revision || plan.ReleaseSequence <= existing.Plan.ReleaseSequence) {
			return preparedUpgrade{}, nil, ErrReplay
		}
	}
	current, err := m.installer.Current(ctx)
	if err != nil {
		return preparedUpgrade{}, nil, ErrInstaller
	}
	if err := validateReceipt(current, m.config.ReceiptKeys, m.clock.Now().UTC()); err != nil || current.Status != ReceiptStatusActive {
		return preparedUpgrade{}, nil, ErrInvalidReceipt
	}
	if current.CurrentVersion != plan.CurrentVersion {
		return preparedUpgrade{}, nil, ErrReplay
	}
	if plan.SchemaVersion == planSchemaVersionV3 {
		if current.SchemaVersion == receiptSchemaVersionV2 && plan.ExecutionSequence <= current.ExecutionSequence {
			return preparedUpgrade{}, nil, ErrReplay
		}
	} else if current.SchemaVersion == receiptSchemaVersionV2 || plan.ReleaseSequence <= current.ReleaseSequence {
		return preparedUpgrade{}, nil, ErrReplay
	}
	value := &transaction{
		Version: stateVersion, Plan: plan, Digest: digest, Phase: phaseDownload,
		InstallerTransactionID: "txn-" + randomSuffix(), Before: current,
	}
	if err := m.fs.saveTransaction(value); err != nil {
		return preparedUpgrade{}, nil, err
	}
	return preparedUpgrade{InstallerTransactionID: value.InstallerTransactionID}, value, nil
}

func (m *Manager) processPrepared(ctx context.Context, plan Plan, installerTransactionID string) (Result, error) {
	unlock, err := m.lockState(ctx)
	if err != nil {
		return Result{}, err
	}
	defer unlock()
	value, err := m.fs.loadTransaction()
	if err != nil {
		return Result{}, err
	}
	digest, digestErr := planDigest(plan)
	if digestErr != nil || value == nil || installerTransactionID == "" ||
		value.InstallerTransactionID != installerTransactionID || value.Plan.PlanID != plan.PlanID ||
		value.Plan.Revision != plan.Revision || value.Digest != digest {
		return Result{}, ErrReplay
	}
	if err := validatePlan(plan, m.config, m.clock.Now().UTC(), true); err != nil {
		return Result{}, err
	}
	if err := validateReceipt(value.Before, m.config.ReceiptKeys, m.clock.Now().UTC()); err != nil {
		return Result{}, err
	}
	if value.Phase == phaseDone {
		result := value.Result
		result.Duplicate = true
		return result, nil
	}
	if err := m.prepareInstallerV2(ctx, value); err != nil {
		return Result{}, err
	}
	return m.run(ctx, value)
}

func (m *Manager) beginInstall(ctx context.Context, installerTransactionID string) (bool, error) {
	if m.installerV2 == nil {
		// Legacy installers have no separate helper transaction boundary. Keep
		// their established status progression; the production v2 path below
		// requires a durable helper readback before returning.
		return true, nil
	}
	unlock, err := m.lockState(ctx)
	if err != nil {
		return false, err
	}
	defer unlock()
	value, err := m.fs.loadTransaction()
	if err != nil || value == nil || value.InstallerTransactionID != installerTransactionID ||
		value.PreparedInstall == nil || !preparedInstallMatchesTransaction(*value.PreparedInstall, value) {
		return false, ErrInstallerUncertain
	}
	status, err := m.installerV2.Inspect(ctx, installerTransactionID)
	if err != nil || status.Phase == InstallerTransactionUnknown || status.Phase == InstallerTransactionAborted {
		return false, ErrInstallerUncertain
	}
	if err := m.consumeInstallerTransaction(value, status); err != nil {
		return false, err
	}
	if status.Phase == InstallerTransactionActive || status.Phase == InstallerTransactionRolledBack {
		return true, nil
	}
	if status.Phase == InstallerTransactionInstalling {
		status, err = m.installerV2.MarkInstalling(ctx, *value.PreparedInstall)
		if err != nil || status.Prepared != *value.PreparedInstall {
			return false, ErrInstallerUncertain
		}
		if status.Phase == InstallerTransactionActive {
			if status.Receipt == (ActivationReceipt{}) {
				return false, ErrInstallerUncertain
			}
			if err := m.consumeInstallerTransaction(value, status); err != nil {
				return false, err
			}
			return false, ErrInstallerLegacyActivated
		}
		if status.Phase != InstallerTransactionInstalling || status.Receipt != (ActivationReceipt{}) {
			return false, ErrInstallerUncertain
		}
		confirmed, inspectErr := m.installerV2.Inspect(ctx, installerTransactionID)
		if inspectErr != nil || confirmed.Phase != InstallerTransactionInstalling ||
			confirmed.Prepared != *value.PreparedInstall || confirmed.Receipt != (ActivationReceipt{}) {
			return false, ErrInstallerUncertain
		}
		if err := m.consumeInstallerTransaction(value, confirmed); err != nil {
			return false, err
		}
		return true, nil
	}
	if status.Phase != InstallerTransactionPrepared {
		return false, ErrInstallerUncertain
	}
	status, err = m.installerV2.MarkInstalling(ctx, *value.PreparedInstall)
	if err != nil || status.Prepared != *value.PreparedInstall {
		return false, ErrInstallerUncertain
	}
	if status.Phase == InstallerTransactionActive {
		if status.Receipt == (ActivationReceipt{}) {
			return false, ErrInstallerUncertain
		}
		if err := m.consumeInstallerTransaction(value, status); err != nil {
			return false, err
		}
		return false, ErrInstallerLegacyActivated
	}
	if status.Phase != InstallerTransactionInstalling || status.Receipt != (ActivationReceipt{}) {
		return false, ErrInstallerUncertain
	}
	confirmed, inspectErr := m.installerV2.Inspect(ctx, installerTransactionID)
	if inspectErr != nil || confirmed.Phase != InstallerTransactionInstalling ||
		confirmed.Prepared != *value.PreparedInstall || confirmed.Receipt != (ActivationReceipt{}) {
		return false, ErrInstallerUncertain
	}
	if err := m.consumeInstallerTransaction(value, confirmed); err != nil {
		return false, err
	}
	return true, nil
}

func (m *Manager) lockState(ctx context.Context) (func(), error) {
	m.mu.Lock()
	unlock, err := m.fs.lock(ctx)
	if err != nil {
		m.mu.Unlock()
		return nil, err
	}
	return func() {
		unlock()
		m.mu.Unlock()
	}, nil
}

func (m *Manager) Recover(ctx context.Context) (Result, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	unlock, err := m.fs.lock(ctx)
	if err != nil {
		return Result{}, false, err
	}
	defer unlock()
	value, err := m.fs.loadTransaction()
	if err != nil || value == nil || value.Phase == phaseDone {
		return Result{}, false, err
	}
	if err := validatePlan(value.Plan, m.config, m.clock.Now().UTC(), true); err != nil {
		return Result{}, true, err
	}
	if err := validateReceipt(value.Before, m.config.ReceiptKeys, m.clock.Now().UTC()); err != nil {
		return Result{}, true, err
	}
	if err := m.prepareInstallerV2(ctx, value); err != nil {
		return Result{}, true, err
	}
	result, err := m.run(ctx, value)
	return result, true, err
}

func (m *Manager) installerProtocolVersion() int {
	if m != nil && m.installerV2 != nil {
		return m.installerV2.ProtocolVersion()
	}
	return 0
}

func (m *Manager) Current(ctx context.Context) (Result, error) {
	receipt, err := m.installer.Current(ctx)
	if err != nil {
		return Result{}, ErrInstaller
	}
	if err := validateReceipt(receipt, m.config.ReceiptKeys, m.clock.Now().UTC()); err != nil {
		return Result{}, err
	}
	if receipt.Status != ReceiptStatusActive {
		return Result{}, ErrInvalidReceipt
	}
	return Result{
		ExecutionSequence: receipt.ExecutionSequence, ReleaseSequence: receipt.ReleaseSequence,
		CurrentVersion:  receipt.CurrentVersion,
		PreviousVersion: receipt.PreviousVersion, InstallerTransactionID: receipt.InstallerTransactionID,
	}, nil
}

func (m *Manager) pendingTransaction(ctx context.Context) (Plan, string, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	unlock, err := m.fs.lock(ctx)
	if err != nil {
		return Plan{}, "", false, err
	}
	defer unlock()
	value, err := m.fs.loadTransaction()
	if err != nil || value == nil || value.Phase == phaseDone {
		return Plan{}, "", false, err
	}
	return value.Plan, value.InstallerTransactionID, true, nil
}

func (m *Manager) run(ctx context.Context, value *transaction) (Result, error) {
	for {
		expired := !m.clock.Now().UTC().Before(value.Plan.ExpiresAt)
		if expired {
			switch value.Phase {
			case phaseDownload:
				return m.fail(value, "PLAN_EXPIRED", ErrExpired)
			case phaseInstall:
				if closed, err := m.abortExpiredPrepared(ctx, value); err != nil {
					return Result{}, err
				} else if closed {
					return m.fail(value, "PLAN_EXPIRED", ErrExpired)
				} else if value.Phase != phaseInstall {
					continue
				}
				active, err := m.queryActive(ctx, value)
				if err == nil && active {
					value.ErrorCode = "PLAN_EXPIRED"
					value.Phase = phaseRollback
					if err := m.fs.saveTransaction(value); err != nil {
						return Result{}, err
					}
				} else if errors.Is(err, ErrInstallerUnknown) {
					return m.fail(value, "PLAN_EXPIRED", ErrExpired)
				} else if err != nil {
					return Result{}, err
				}
			case phaseObserve:
				value.ErrorCode = "PLAN_EXPIRED"
				value.Phase = phaseRollback
				if err := m.fs.saveTransaction(value); err != nil {
					return Result{}, err
				}
			}
		}

		switch value.Phase {
		case phaseDownload:
			if err := m.download(ctx, value.Plan); err != nil {
				if ctx.Err() != nil {
					return Result{}, ctx.Err()
				}
				code := "DOWNLOAD_FAILED"
				if errors.Is(err, ErrArtifactTooLarge) {
					code = "ARTIFACT_TOO_LARGE"
				} else if errors.Is(err, ErrArtifactIntegrity) {
					code = "ARTIFACT_INTEGRITY_FAILED"
				} else if errors.Is(err, ErrInsufficientDisk) {
					code = "INSUFFICIENT_DISK"
				}
				return m.fail(value, code, err)
			}
			value.Phase = phaseInstall
			if err := m.fs.saveTransaction(value); err != nil {
				return Result{}, err
			}
		case phaseInstall:
			if err := m.install(ctx, value); err != nil {
				if value.Phase == phaseDone {
					return value.Result, err
				}
				return Result{}, err
			}
		case phaseObserve:
			if err := validateActiveReceipt(value.ActiveReceipt, value, m.config.ReceiptKeys, m.clock.Now().UTC()); err != nil {
				return Result{}, err
			}
			evidence, err := m.healthGate(ctx, value.ActiveReceipt, value, value.Before.ArtifactSHA256)
			if err != nil {
				if ctx.Err() != nil {
					return Result{}, ctx.Err()
				}
				value.ErrorCode = healthFailureCode(err)
				value.Phase = phaseRollback
				if err := m.fs.saveTransaction(value); err != nil {
					return Result{}, err
				}
				continue
			}
			value.Result.ActiveEvidence = evidence
			return m.succeed(value)
		case phaseRollback:
			return m.rollback(ctx, value)
		case phaseDone:
			return value.Result, nil
		default:
			return Result{}, ErrCorruptState
		}
	}
}

func (m *Manager) abortExpiredPrepared(ctx context.Context, value *transaction) (bool, error) {
	if m.installerV2 == nil || value == nil || value.PreparedInstall == nil {
		return false, nil
	}
	status, err := m.installerV2.Inspect(ctx, value.InstallerTransactionID)
	if err != nil {
		return false, ErrInstallerUncertain
	}
	if err := m.consumeInstallerTransaction(value, status); err != nil {
		return false, err
	}
	switch status.Phase {
	case InstallerTransactionAborted:
		return true, nil
	case InstallerTransactionPrepared:
	case InstallerTransactionInstalling, InstallerTransactionActive, InstallerTransactionRolledBack:
		return false, nil
	default:
		return false, ErrInstallerUncertain
	}
	abortCtx, cancelAbort := context.WithTimeout(ctx, value.Plan.Health.ActivationTimeout)
	aborted, abortErr := m.installerV2.Abort(abortCtx, *value.PreparedInstall)
	cancelAbort()
	if abortErr == nil {
		if err := m.consumeInstallerTransaction(value, aborted); err != nil {
			return false, err
		}
		return aborted.Phase == InstallerTransactionAborted, nil
	}
	status, err = m.installerV2.Inspect(ctx, value.InstallerTransactionID)
	if err != nil {
		return false, ErrInstallerUncertain
	}
	if err := m.consumeInstallerTransaction(value, status); err != nil {
		return false, err
	}
	if status.Phase == InstallerTransactionAborted {
		return true, nil
	}
	return false, ErrInstallerUncertain
}

func (m *Manager) prepareInstallerV2(ctx context.Context, value *transaction) error {
	if m.installerV2 == nil || value == nil || value.Phase == phaseDone {
		return nil
	}
	if value.Phase == phaseDownload {
		if err := m.download(ctx, value.Plan); err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			code := "DOWNLOAD_FAILED"
			if errors.Is(err, ErrArtifactTooLarge) {
				code = "ARTIFACT_TOO_LARGE"
			} else if errors.Is(err, ErrArtifactIntegrity) {
				code = "ARTIFACT_INTEGRITY_FAILED"
			} else if errors.Is(err, ErrInsufficientDisk) {
				code = "INSUFFICIENT_DISK"
			}
			_, _ = m.fail(value, code, err)
			return nil
		}
		value.Phase = phaseInstall
		if err := m.fs.saveTransaction(value); err != nil {
			return err
		}
	}
	if value.Phase != phaseInstall {
		return nil
	}
	if value.PreparedInstall != nil || value.InstallStarted {
		status, err := m.installerV2.Inspect(ctx, value.InstallerTransactionID)
		if err != nil {
			return ErrInstallerUncertain
		}
		if status.Phase != InstallerTransactionUnknown {
			return m.consumeInstallerTransaction(value, status)
		}
		return ErrInstallerUncertain
	}
	if err := m.beforeActivating(ctx, value.Plan.TargetVersion); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		_, _ = m.fail(value, stateIncompatibleCode, err)
		return nil
	}
	file, path, err := m.fs.openVerified(value.Plan.Artifact.SHA256, value.Plan.Artifact.Size)
	if err != nil {
		return err
	}
	request := installRequestForTransaction(value, file, path)
	prepareCtx, cancelPrepare := context.WithTimeout(ctx, value.Plan.Health.ActivationTimeout)
	prepared, prepareErr := m.installerV2.Prepare(prepareCtx, request)
	cancelPrepare()
	closeErr := file.Close()
	if closeErr != nil {
		return ErrInstallerUncertain
	}
	if prepareErr == nil {
		status, inspectErr := m.installerV2.Inspect(ctx, value.InstallerTransactionID)
		if inspectErr != nil || status.Phase != InstallerTransactionPrepared || status.Prepared != prepared {
			return ErrInstallerUncertain
		}
		return m.consumeInstallerTransaction(value, status)
	}
	status, inspectErr := m.installerV2.Inspect(ctx, value.InstallerTransactionID)
	if inspectErr != nil || status.Phase == InstallerTransactionUnknown {
		return ErrInstallerUncertain
	}
	return m.consumeInstallerTransaction(value, status)
}

func installRequestForTransaction(value *transaction, file *os.File, path string) InstallRequest {
	return InstallRequest{
		InstallerTransactionID: value.InstallerTransactionID, ExecutionSequence: value.Plan.ExecutionSequence,
		ReleaseSequence: value.Plan.ReleaseSequence, Action: value.Plan.Action,
		CurrentVersion: value.Plan.CurrentVersion, TargetVersion: value.Plan.TargetVersion,
		Platform: value.Plan.Platform, Architecture: value.Plan.Architecture,
		ArtifactSHA256: value.Plan.Artifact.SHA256, ArtifactSize: value.Plan.Artifact.Size,
		StagedPath: path, Artifact: file, CurrentReceipt: value.Before,
	}
}

func (m *Manager) persistPreparedInstall(value *transaction, prepared PreparedInstall) error {
	if !preparedInstallMatchesTransaction(prepared, value) {
		return ErrInstallerUncertain
	}
	if value.PreparedInstall != nil && *value.PreparedInstall != prepared {
		return ErrInstallerUncertain
	}
	copy := prepared
	value.PreparedInstall = &copy
	return m.fs.saveTransaction(value)
}

func (m *Manager) consumeInstallerTransaction(value *transaction, status InstallerTransaction) error {
	if status.InstallerTransactionID != value.InstallerTransactionID ||
		status.Phase != InstallerTransactionUnknown && !preparedInstallMatchesTransaction(status.Prepared, value) {
		return ErrInstallerUncertain
	}
	if status.Phase != InstallerTransactionUnknown {
		if err := m.persistPreparedInstall(value, status.Prepared); err != nil {
			return err
		}
		if status.Phase == InstallerTransactionInstalling && !value.InstallStarted {
			value.InstallStarted = true
			if err := m.fs.saveTransaction(value); err != nil {
				return err
			}
		}
	}
	switch status.Phase {
	case InstallerTransactionPrepared, InstallerTransactionInstalling, InstallerTransactionAborted:
		if status.Receipt != (ActivationReceipt{}) {
			return ErrInstallerUncertain
		}
		return nil
	case InstallerTransactionActive, InstallerTransactionRolledBack:
		return m.consumeInstallReceipt(value, status.Receipt)
	default:
		return ErrInstallerUnknown
	}
}

func validPreparedInstall(prepared PreparedInstall, transactionID string) bool {
	return (prepared.SchemaVersion == 1 && prepared.ExecutionSequence == 0 ||
		prepared.SchemaVersion == 2 && prepared.ExecutionSequence > 0) && prepared.InstallerTransactionID == transactionID &&
		safeIDPattern.MatchString(prepared.InstallerTransactionID) && validDigest(prepared.InstallPayloadSHA256) &&
		prepared.ReleaseSequence > 0 && validDigest(prepared.ArtifactSHA256) && validDigest(prepared.ManifestSHA256) &&
		validDigest(prepared.ExecutableSHA256) && validDigest(prepared.SBOMSHA256) &&
		safeIDPattern.MatchString(prepared.PreviousVersion) && safeIDPattern.MatchString(prepared.TargetVersion) &&
		prepared.PreviousVersion != prepared.TargetVersion
}

func preparedInstallMatchesTransaction(prepared PreparedInstall, value *transaction) bool {
	if value == nil || !validPreparedInstall(prepared, value.InstallerTransactionID) {
		return false
	}
	expectedDigest, err := prepareInstallerRequestDigest(installRequestForTransaction(value, nil, "artifact"))
	return err == nil && prepared.InstallPayloadSHA256 == expectedDigest &&
		prepared.ExecutionSequence == value.Plan.ExecutionSequence &&
		prepared.ReleaseSequence == value.Plan.ReleaseSequence && prepared.ArtifactSHA256 == value.Plan.Artifact.SHA256 &&
		prepared.PreviousVersion == value.Plan.CurrentVersion && prepared.TargetVersion == value.Plan.TargetVersion
}

func (m *Manager) install(ctx context.Context, value *transaction) error {
	if m.installerV2 != nil {
		return m.activateInstallerV2(ctx, value)
	}
	if value.InstallStarted {
		receipt, err := m.installer.Query(ctx, value.InstallerTransactionID)
		if err == nil {
			return m.consumeInstallReceipt(value, receipt)
		}
		if !errors.Is(err, ErrInstallerUnknown) {
			return ErrInstallerUncertain
		}
		current, currentErr := m.installer.Current(ctx)
		if currentErr != nil {
			return ErrInstallerUncertain
		}
		if err := validateReceipt(current, m.config.ReceiptKeys, m.clock.Now().UTC()); err != nil {
			return err
		}
		if validateActiveReceipt(current, value, m.config.ReceiptKeys, m.clock.Now().UTC()) == nil {
			return m.acceptActive(value, current)
		}
		if !sameInstalledRelease(current, value.Before) {
			return ErrInstallerUncertain
		}
	}
	if err := m.beforeActivating(ctx, value.Plan.TargetVersion); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		_, failErr := m.fail(value, stateIncompatibleCode, err)
		return failErr
	}
	value.InstallStarted = true
	if err := m.fs.saveTransaction(value); err != nil {
		return err
	}
	file, path, err := m.fs.openVerified(value.Plan.Artifact.SHA256, value.Plan.Artifact.Size)
	if err != nil {
		return err
	}
	request := InstallRequest{
		InstallerTransactionID: value.InstallerTransactionID, ReleaseSequence: value.Plan.ReleaseSequence,
		CurrentVersion: value.Plan.CurrentVersion, TargetVersion: value.Plan.TargetVersion,
		Platform: value.Plan.Platform, Architecture: value.Plan.Architecture,
		ArtifactSHA256: value.Plan.Artifact.SHA256, ArtifactSize: value.Plan.Artifact.Size,
		StagedPath: path, Artifact: file,
		CurrentReceipt: value.Before,
	}
	installCtx, cancelInstall := context.WithTimeout(ctx, value.Plan.Health.ActivationTimeout)
	receipt, installErr := m.installer.Install(installCtx, request)
	cancelInstall()
	closeErr := file.Close()
	if closeErr != nil {
		return ErrInstallerUncertain
	}
	if receipt.SchemaVersion != 0 {
		if err := m.consumeInstallReceipt(value, receipt); err != nil {
			return err
		}
		return nil
	}
	if installErr == nil {
		return ErrInvalidReceipt
	}
	queried, queryErr := m.installer.Query(ctx, value.InstallerTransactionID)
	if queryErr == nil {
		return m.consumeInstallReceipt(value, queried)
	}
	if !errors.Is(queryErr, ErrInstallerUnknown) {
		return ErrInstallerUncertain
	}
	current, currentErr := m.installer.Current(ctx)
	if currentErr != nil {
		return ErrInstallerUncertain
	}
	if err := validateReceipt(current, m.config.ReceiptKeys, m.clock.Now().UTC()); err != nil {
		return err
	}
	if validateActiveReceipt(current, value, m.config.ReceiptKeys, m.clock.Now().UTC()) == nil {
		return m.acceptActive(value, current)
	}
	return ErrInstallerUncertain
}

func (m *Manager) activateInstallerV2(ctx context.Context, value *transaction) error {
	if value.PreparedInstall == nil || !preparedInstallMatchesTransaction(*value.PreparedInstall, value) {
		return ErrInstallerUncertain
	}
	activate := func() (ActivationReceipt, error) {
		if value.ActivationAttempts >= maxInstallerActivationAttempts {
			return ActivationReceipt{}, ErrInstallerUncertain
		}
		value.ActivationAttempts++
		if err := m.fs.saveTransaction(value); err != nil {
			return ActivationReceipt{}, err
		}
		activateCtx, cancelActivate := context.WithTimeout(ctx, value.Plan.Health.ActivationTimeout)
		defer cancelActivate()
		return m.installerV2.Activate(activateCtx, *value.PreparedInstall)
	}
	for {
		status, err := m.installerV2.Inspect(ctx, value.InstallerTransactionID)
		if err != nil || status.Phase == InstallerTransactionUnknown || status.Phase == InstallerTransactionAborted {
			return ErrInstallerUncertain
		}
		if err := m.consumeInstallerTransaction(value, status); err != nil {
			return err
		}
		if status.Phase == InstallerTransactionActive || status.Phase == InstallerTransactionRolledBack {
			return nil
		}
		if status.Phase != InstallerTransactionPrepared &&
			(status.Phase != InstallerTransactionInstalling || value.ActivationAttempts != 0) {
			return ErrInstallerUncertain
		}
		if value.ActivationAttempts >= maxInstallerActivationAttempts {
			return ErrInstallerUncertain
		}
		if status.Phase == InstallerTransactionPrepared {
			// Local state may have changed since Prepare (a deployment applied
			// in between); prepare it again right before the switch.
			if err := m.beforeActivating(ctx, value.Plan.TargetVersion); err != nil {
				if ctx.Err() != nil {
					return ctx.Err()
				}
				closed, abortErr := m.abortExpiredPrepared(ctx, value)
				if abortErr != nil || !closed {
					return ErrInstallerUncertain
				}
				_, failErr := m.fail(value, stateIncompatibleCode, err)
				return failErr
			}
		}
		receipt, activateErr := activate()
		if receipt.SchemaVersion != 0 {
			return m.consumeInstallReceipt(value, receipt)
		}
		if activateErr == nil {
			return ErrInvalidReceipt
		}
	}
}

func (m *Manager) consumeInstallReceipt(value *transaction, receipt ActivationReceipt) error {
	switch receipt.Status {
	case ReceiptStatusActive:
		if err := validateActiveReceipt(receipt, value, m.config.ReceiptKeys, m.clock.Now().UTC()); err != nil {
			return err
		}
		return m.acceptActive(value, receipt)
	case ReceiptStatusRolledBack:
		if err := validateRollbackReceipt(receipt, value, m.config.ReceiptKeys, m.clock.Now().UTC()); err != nil {
			return err
		}
		value.ErrorCode = "INSTALLER_ROLLED_BACK"
		value.RollbackStarted = true
		value.Phase = phaseRollback
		return m.fs.saveTransaction(value)
	default:
		return ErrInvalidReceipt
	}
}

func (m *Manager) acceptActive(value *transaction, receipt ActivationReceipt) error {
	value.ActiveReceipt = receipt
	value.Phase = phaseObserve
	return m.fs.saveTransaction(value)
}

func (m *Manager) queryActive(ctx context.Context, value *transaction) (bool, error) {
	receipt, err := m.inspectReceipt(ctx, value.InstallerTransactionID)
	if err != nil {
		return false, err
	}
	if err := validateActiveReceipt(receipt, value, m.config.ReceiptKeys, m.clock.Now().UTC()); err != nil {
		return false, err
	}
	value.ActiveReceipt = receipt
	return true, nil
}

func (m *Manager) inspectReceipt(ctx context.Context, transactionID string) (ActivationReceipt, error) {
	if m.installerV2 == nil {
		return m.installer.Query(ctx, transactionID)
	}
	status, err := m.installerV2.Inspect(ctx, transactionID)
	if err != nil {
		return ActivationReceipt{}, ErrInstallerUncertain
	}
	switch status.Phase {
	case InstallerTransactionUnknown:
		return ActivationReceipt{}, ErrInstallerUnknown
	case InstallerTransactionActive, InstallerTransactionRolledBack:
		return status.Receipt, nil
	default:
		return ActivationReceipt{}, ErrInstallerUncertain
	}
}

func (m *Manager) download(ctx context.Context, plan Plan) error {
	if err := m.requireDisk(plan.Artifact.Size); err != nil {
		return err
	}
	file, path, err := m.fs.prepareStaging(plan.PlanID)
	if err != nil {
		return err
	}
	hash := sha256.New()
	writer := &boundedWriter{destination: io.MultiWriter(file, hash), remaining: plan.Artifact.Size}
	downloadErr := m.downloader.Download(ctx, DownloadRequest{URL: plan.Artifact.URL, MaxBytes: plan.Artifact.Size}, writer)
	syncErr := file.Sync()
	closeErr := file.Close()
	if downloadErr != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if errors.Is(downloadErr, ErrArtifactTooLarge) {
			return ErrArtifactTooLarge
		}
		return ErrDownload
	}
	if syncErr != nil || closeErr != nil {
		return ErrDownload
	}
	if writer.written != plan.Artifact.Size || hex.EncodeToString(hash.Sum(nil)) != plan.Artifact.SHA256 {
		return ErrArtifactIntegrity
	}
	_, err = m.fs.commitStaging(plan.PlanID, path, plan.Artifact.SHA256, plan.Artifact.Size)
	return err
}

func (m *Manager) requireDisk(artifactSize int64) error {
	available, err := m.fs.availableDiskBytes()
	if err != nil {
		return err
	}
	required := uint64(artifactSize) + uint64(m.config.DiskReserveBytes)
	if uint64(artifactSize) > ^uint64(0)-uint64(m.config.DiskReserveBytes) || available < required {
		return ErrInsufficientDisk
	}
	return nil
}

func (m *Manager) healthGate(ctx context.Context, receipt ActivationReceipt, value *transaction,
	lastKnownGoodArtifactSHA256 string) (*ActiveProbeEvidence, error) {
	plan := value.Plan
	evidence := cloneActiveProbeEvidence(value.Result.ActiveEvidence)
	if evidence == nil || evidence.ProbeDeadline.IsZero() {
		evidence = &ActiveProbeEvidence{Schema: ActiveProbeEvidenceSchema,
			ProbeDeadline: m.clock.Now().UTC().Add(plan.Health.ActivationTimeout)}
		value.Result.ActiveEvidence = cloneActiveProbeEvidence(evidence)
		if err := m.fs.saveTransaction(value); err != nil {
			return nil, err
		}
	}
	observationStarted := false
	if evidence.ProbeObservedAt.IsZero() {
		consecutive := 0
		var lastProbeObservedAt time.Time
		for consecutive < plan.Health.RequiredConsecutiveSuccesses {
			if !m.clock.Now().Before(evidence.ProbeDeadline) {
				return nil, ErrHealth
			}
			err := m.check(ctx, receipt, plan)
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			if err == nil {
				consecutive++
				lastProbeObservedAt = m.clock.Now().UTC()
			} else if healthFailureCode(err) != "HEALTH_FAILED" {
				// A definitive failure (the native runtime of this
				// release could not be switched): no retry fixes it.
				return nil, err
			} else {
				consecutive = 0
			}
			if consecutive < plan.Health.RequiredConsecutiveSuccesses {
				if err := m.clock.Sleep(ctx, plan.Health.Interval); err != nil {
					return nil, err
				}
			}
		}
		evidence.ProbeObservedAt = lastProbeObservedAt
		evidence.ProbeDeadline = evidence.ProbeObservedAt.Add(plan.Health.ObservationWindow)
		value.Result.ActiveEvidence = cloneActiveProbeEvidence(evidence)
		if err := m.fs.saveTransaction(value); err != nil {
			return nil, err
		}
		observationStarted = true
	}
	if !observationStarted && evidence.EvidenceSHA256 == "" {
		return nil, ErrHealth
	}
	for m.clock.Now().Before(evidence.ProbeDeadline) {
		if err := m.check(ctx, receipt, plan); err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			if healthFailureCode(err) != "HEALTH_FAILED" {
				return nil, err
			}
			return nil, ErrHealth
		}
		evidence.ProbeObservedAt = m.clock.Now().UTC()
		if evidence.ProbeObservedAt.After(evidence.ProbeDeadline) {
			return nil, ErrHealth
		}
		if err := m.clock.Sleep(ctx, minDuration(plan.Health.Interval, evidence.ProbeDeadline.Sub(m.clock.Now()))); err != nil {
			return nil, err
		}
	}
	probe, ok := m.probe.(evidenceProbe)
	if !ok {
		return nil, ErrHealth
	}
	probeCtx, cancelProbe := context.WithTimeout(ctx, plan.Health.ProbeTimeout)
	configEvidence, err := probe.Evidence(probeCtx, receipt, append([]string(nil), plan.Health.Command...))
	cancelProbe()
	if err != nil || !validActiveProbeDigest(configEvidence.ActiveConfigSHA256) ||
		!validActiveProbeDigest(configEvidence.LastKnownGoodConfigSHA256) ||
		!validActiveProbeDigest(receipt.ArtifactSHA256) || !validActiveProbeDigest(lastKnownGoodArtifactSHA256) {
		return nil, ErrHealth
	}
	evidence.ActiveArtifactSHA256 = receipt.ArtifactSHA256
	evidence.ActiveConfigSHA256 = configEvidence.ActiveConfigSHA256
	evidence.LastKnownGoodArtifactSHA256 = lastKnownGoodArtifactSHA256
	evidence.LastKnownGoodConfigSHA256 = configEvidence.LastKnownGoodConfigSHA256
	evidence.EvidenceSHA256 = activeProbeEvidenceDigest(value.InstallerTransactionID, *evidence)
	if err := validateActiveProbeEvidence(value.InstallerTransactionID, evidence); err != nil {
		return nil, ErrHealth
	}
	value.Result.ActiveEvidence = cloneActiveProbeEvidence(evidence)
	if err := m.fs.saveTransaction(value); err != nil {
		return nil, err
	}
	return evidence, nil
}

func (m *Manager) check(ctx context.Context, receipt ActivationReceipt, plan Plan) error {
	probeCtx, cancel := context.WithTimeout(ctx, plan.Health.ProbeTimeout)
	defer cancel()
	return m.probe.Check(probeCtx, receipt, append([]string(nil), plan.Health.Command...))
}

func (m *Manager) rollback(ctx context.Context, value *transaction) (Result, error) {
	if value.RollbackStarted {
		receipt, err := m.inspectReceipt(ctx, value.InstallerTransactionID)
		if err == nil {
			if validateRollbackReceipt(receipt, value, m.config.ReceiptKeys, m.clock.Now().UTC()) == nil {
				return m.finishRolledBack(ctx, value)
			}
			if validateActiveReceipt(receipt, value, m.config.ReceiptKeys, m.clock.Now().UTC()) == nil {
				return m.rollbackFailed(value, &receipt)
			} else {
				return Result{}, ErrInvalidReceipt
			}
		} else if errors.Is(err, ErrInstallerUnknown) {
			current, currentErr := m.installer.Current(ctx)
			if currentErr != nil {
				return Result{}, ErrInstallerUncertain
			}
			if validateRollbackReceipt(current, value, m.config.ReceiptKeys, m.clock.Now().UTC()) == nil {
				return m.finishRolledBack(ctx, value)
			}
			if validateActiveReceipt(current, value, m.config.ReceiptKeys, m.clock.Now().UTC()) == nil {
				return m.rollbackFailed(value, &current)
			} else {
				return Result{}, ErrInstallerUncertain
			}
		} else {
			return Result{}, ErrInstallerUncertain
		}
	}
	if err := m.beforeActivating(ctx, value.Before.CurrentVersion); err != nil {
		if ctx.Err() != nil {
			return Result{}, ctx.Err()
		}
		// The previous version cannot read the node's state: rolling back
		// would stop the agent. Keep the running version and report it.
		value.ErrorCode = stateIncompatibleCode
		active := value.ActiveReceipt
		return m.rollbackFailed(value, &active)
	}
	value.RollbackStarted = true
	if err := m.fs.saveTransaction(value); err != nil {
		return Result{}, err
	}
	rollbackCtx, cancelRollback := context.WithTimeout(ctx, value.Plan.Health.ActivationTimeout)
	receipt, rollbackErr := m.installer.Rollback(rollbackCtx, RollbackRequest{
		InstallerTransactionID: value.InstallerTransactionID, ReleaseSequence: value.Plan.ReleaseSequence,
		ArtifactSHA256: value.Plan.Artifact.SHA256, ExpectedCurrentVersion: value.Plan.TargetVersion,
		RollbackVersion: value.Before.CurrentVersion, ActiveReceipt: value.ActiveReceipt,
		PreviousReceipt: value.Before,
	})
	cancelRollback()
	if receipt.SchemaVersion != 0 {
		if err := validateRollbackReceipt(receipt, value, m.config.ReceiptKeys, m.clock.Now().UTC()); err != nil {
			return Result{}, err
		}
		return m.finishRolledBack(ctx, value)
	}
	if rollbackErr == nil {
		return Result{}, ErrInvalidReceipt
	}
	queried, queryErr := m.inspectReceipt(ctx, value.InstallerTransactionID)
	if queryErr == nil {
		if validateRollbackReceipt(queried, value, m.config.ReceiptKeys, m.clock.Now().UTC()) == nil {
			return m.finishRolledBack(ctx, value)
		}
		if validateActiveReceipt(queried, value, m.config.ReceiptKeys, m.clock.Now().UTC()) == nil {
			return m.rollbackFailed(value, &queried)
		}
		return Result{}, ErrInvalidReceipt
	}
	if errors.Is(queryErr, ErrInstallerUnknown) {
		return Result{}, ErrInstallerUncertain
	}
	return m.rollbackFailed(value, nil)
}

func (m *Manager) succeed(value *transaction) (Result, error) {
	result := Result{
		PlanID: value.Plan.PlanID, Revision: value.Plan.Revision, ExecutionSequence: value.Plan.ExecutionSequence,
		ReleaseSequence: value.Plan.ReleaseSequence,
		State:           StateSucceeded, CurrentVersion: value.Plan.TargetVersion,
		PreviousVersion: value.Plan.CurrentVersion, InstallerTransactionID: value.InstallerTransactionID,
		ActiveEvidence: cloneActiveProbeEvidence(value.Result.ActiveEvidence),
	}
	value.Result = result
	value.Phase = phaseDone
	if err := m.fs.saveTransaction(value); err != nil {
		return Result{}, err
	}
	return result, nil
}

func (m *Manager) finishRolledBack(ctx context.Context, value *transaction) (Result, error) {
	current, err := m.installer.Current(ctx)
	if err != nil {
		return Result{}, ErrInstallerUncertain
	}
	if err := validateReceipt(current, m.config.ReceiptKeys, m.clock.Now().UTC()); err != nil ||
		current.Status != ReceiptStatusActive || current.CurrentVersion != value.Before.CurrentVersion ||
		current.ArtifactSHA256 != value.Before.ArtifactSHA256 {
		return m.rollbackFailed(value, &current)
	}
	value.Result.ActiveEvidence = nil
	evidence, err := m.healthGate(ctx, current, value, value.Plan.Artifact.SHA256)
	if err != nil {
		return m.rollbackFailed(value, &current)
	}
	result := Result{
		PlanID: value.Plan.PlanID, Revision: value.Plan.Revision, ExecutionSequence: value.Plan.ExecutionSequence,
		ReleaseSequence: value.Plan.ReleaseSequence,
		State:           StateRolledBack, CurrentVersion: value.Before.CurrentVersion,
		PreviousVersion: value.Plan.TargetVersion, InstallerTransactionID: value.InstallerTransactionID,
		ErrorCode: value.ErrorCode, ActiveEvidence: evidence,
	}
	value.Result = result
	value.Phase = phaseDone
	if err := m.fs.saveTransaction(value); err != nil {
		return Result{}, err
	}
	return result, errorForCode(value.ErrorCode)
}

func (m *Manager) fail(value *transaction, code string, cause error) (Result, error) {
	result := Result{
		PlanID: value.Plan.PlanID, Revision: value.Plan.Revision, ExecutionSequence: value.Plan.ExecutionSequence,
		ReleaseSequence: value.Plan.ReleaseSequence,
		State:           StateFailed, CurrentVersion: value.Plan.CurrentVersion,
		InstallerTransactionID: value.InstallerTransactionID, ErrorCode: code, AlertRequired: true,
	}
	value.Result = result
	value.ErrorCode = code
	value.Phase = phaseDone
	if err := m.fs.saveTransaction(value); err != nil {
		return Result{}, err
	}
	return result, cause
}

func (m *Manager) rollbackFailed(value *transaction, active *ActivationReceipt) (Result, error) {
	result := Result{
		PlanID: value.Plan.PlanID, Revision: value.Plan.Revision, ExecutionSequence: value.Plan.ExecutionSequence,
		ReleaseSequence: value.Plan.ReleaseSequence,
		State:           StateFailed, InstallerTransactionID: value.InstallerTransactionID,
		ErrorCode: "ROLLBACK_FAILED", AlertRequired: true,
	}
	if active != nil {
		result.CurrentVersion = active.CurrentVersion
		result.PreviousVersion = active.PreviousVersion
		if value.ErrorCode != "" {
			result.ErrorCode = value.ErrorCode
		}
		value.Phase = phaseDone
	}
	value.Result = result
	if err := m.fs.saveTransaction(value); err != nil {
		return Result{}, err
	}
	return result, ErrRollback
}

// stateIncompatibleCode reports a version change Config.BeforeActivating
// refused.
const stateIncompatibleCode = "L4_STATE_INCOMPATIBLE"

func (m *Manager) beforeActivating(ctx context.Context, version string) error {
	if m.config.BeforeActivating == nil {
		return nil
	}
	if err := m.config.BeforeActivating(ctx, version); err != nil {
		return fmt.Errorf("%w: %v", ErrStateIncompatible, err)
	}
	return nil
}

// HealthCoder is a health probe failure with its own upgrade status code
// (e.g. RUNTIME_PRECHECK_FAILED from the native runtime switch).
type HealthCoder interface{ HealthCode() string }

var healthCodePattern = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,63}$`)

func healthFailureCode(err error) string {
	var coder HealthCoder
	if errors.As(err, &coder) && healthCodePattern.MatchString(coder.HealthCode()) {
		return coder.HealthCode()
	}
	return "HEALTH_FAILED"
}

func errorForCode(code string) error {
	switch code {
	case "HEALTH_FAILED":
		return ErrHealth
	case "RUNTIME_SIGNATURE_INVALID", "RUNTIME_AGENT_MISMATCH", "RUNTIME_INSTALL_FAILED", "RUNTIME_PRECHECK_FAILED",
		"RUNTIME_SWITCH_FAILED", "RUNTIME_RELOAD_FAILED", "RUNTIME_NOT_PACKAGED", "RUNTIME_STATUS_UNAVAILABLE":
		return ErrHealth
	case "PLAN_EXPIRED":
		return ErrExpired
	case "INSTALLER_ROLLED_BACK":
		return ErrActivation
	case stateIncompatibleCode:
		return ErrStateIncompatible
	default:
		return ErrActivation
	}
}

type boundedWriter struct {
	destination io.Writer
	remaining   int64
	written     int64
}

func (w *boundedWriter) Write(value []byte) (int, error) {
	if int64(len(value)) > w.remaining {
		written := 0
		if w.remaining > 0 {
			var err error
			written, err = w.destination.Write(value[:w.remaining])
			w.written += int64(written)
			w.remaining -= int64(written)
			if err != nil {
				return written, err
			}
		}
		return written, ErrArtifactTooLarge
	}
	written, err := w.destination.Write(value)
	w.written += int64(written)
	w.remaining -= int64(written)
	return written, err
}

func minDuration(left, right time.Duration) time.Duration {
	if left < right {
		return left
	}
	return right
}
