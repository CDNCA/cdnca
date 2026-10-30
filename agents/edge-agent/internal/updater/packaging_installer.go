package updater

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/packaging/helper"
	"github.com/cdnca/cdnca/agents/edge-agent/packaging/helper/protocol"
)

const (
	readOnlyTransportAttempts     = 6
	readOnlyTransportInitialDelay = 50 * time.Millisecond
)

type packagingRoundTripper interface {
	RoundTrip(context.Context, protocol.Request, *os.File) (protocol.Response, error)
}

type PackagingInstaller struct {
	transport packagingRoundTripper
}

var errInstallerProtocol = errors.New("installer protocol negotiation failed")

func NewPackagingInstaller() (*PackagingInstaller, error) {
	client, err := helper.NewClient()
	if err != nil {
		return nil, ErrInstaller
	}
	return &PackagingInstaller{transport: client}, nil
}

func (*PackagingInstaller) ProtocolVersion() int { return protocol.JournalVersion }

func (i *PackagingInstaller) Current(ctx context.Context) (ActivationReceipt, error) {
	return i.call(ctx, protocol.Request{ProtocolVersion: protocol.Version, Operation: protocol.OperationCurrent}, nil, false)
}

func (i *PackagingInstaller) Install(ctx context.Context, request InstallRequest) (ActivationReceipt, error) {
	if request.Artifact == nil {
		return ActivationReceipt{}, ErrInstaller
	}
	current := receiptToProtocol(request.CurrentReceipt)
	return i.call(ctx, protocol.Request{
		ProtocolVersion: protocol.Version, Operation: protocol.OperationInstall,
		TransactionID: request.InstallerTransactionID, ReleaseSequence: request.ReleaseSequence,
		CurrentVersion: request.CurrentVersion, TargetVersion: request.TargetVersion,
		Platform: request.Platform, Architecture: request.Architecture,
		ArtifactSHA256: request.ArtifactSHA256, ArtifactSize: request.ArtifactSize,
		AuditBasename: filepath.Base(request.StagedPath), CurrentReceipt: &current,
	}, request.Artifact, true)
}

func (i *PackagingInstaller) Prepare(ctx context.Context, request InstallRequest) (PreparedInstall, error) {
	if request.Artifact == nil {
		return PreparedInstall{}, ErrInstaller
	}
	prepareRequest := prepareInstallerRequest(request)
	packet, err := protocol.MarshalRequest(prepareRequest)
	if err != nil {
		return PreparedInstall{}, ErrInstaller
	}
	digest := sha256.Sum256(packet)
	expectedDigest := hex.EncodeToString(digest[:])
	response, err := i.roundTrip(ctx, prepareRequest, request.Artifact, true)
	if err != nil {
		return PreparedInstall{}, err
	}
	if response.PreparedAck == nil || !preparedInstallMatchesRequest(
		preparedInstallFromProtocol(*response.PreparedAck), request, expectedDigest,
	) {
		return PreparedInstall{}, ErrInstallerUncertain
	}
	return preparedInstallFromProtocol(*response.PreparedAck), nil
}

func prepareInstallerRequest(request InstallRequest) protocol.Request {
	current := receiptToProtocol(request.CurrentReceipt)
	protocolVersion := protocol.JournalVersion
	var action protocol.Action
	if request.ExecutionSequence != 0 {
		protocolVersion = protocol.JournalV3Version
		action = protocol.Action(request.Action)
	}
	return protocol.Request{
		ProtocolVersion: protocolVersion, Operation: protocol.OperationPrepareInstall,
		TransactionID: request.InstallerTransactionID, ExecutionSequence: request.ExecutionSequence,
		ReleaseSequence: request.ReleaseSequence, Action: action,
		CurrentVersion: request.CurrentVersion, TargetVersion: request.TargetVersion,
		Platform: request.Platform, Architecture: request.Architecture,
		ArtifactSHA256: request.ArtifactSHA256, ArtifactSize: request.ArtifactSize,
		AuditBasename: filepath.Base(request.StagedPath), CurrentReceipt: &current,
	}
}

func prepareInstallerRequestDigest(request InstallRequest) (string, error) {
	packet, err := protocol.MarshalRequest(prepareInstallerRequest(request))
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(packet)
	return hex.EncodeToString(digest[:]), nil
}

func (i *PackagingInstaller) Inspect(ctx context.Context, transactionID string) (InstallerTransaction, error) {
	status, err := i.inspect(ctx, transactionID, protocol.JournalVersion)
	if err == nil {
		return status, nil
	}
	return i.inspect(ctx, transactionID, protocol.JournalV3Version)
}

func (i *PackagingInstaller) MarkInstalling(ctx context.Context, prepared PreparedInstall) (InstallerTransaction, error) {
	value := preparedInstallToProtocol(prepared)
	protocolVersion := protocol.JournalV4Version
	response, err := i.roundTrip(ctx, protocol.Request{
		ProtocolVersion: protocolVersion, Operation: protocol.OperationMarkInstalling,
		TransactionID: prepared.InstallerTransactionID, InstallPayloadSHA256: prepared.InstallPayloadSHA256,
		PreparedAck: &value,
	}, nil, true)
	if errors.Is(err, errInstallerProtocol) {
		legacyVersion := protocol.JournalVersion
		if prepared.ExecutionSequence != 0 {
			legacyVersion = protocol.JournalV3Version
		}
		receipt, activateErr := i.call(ctx, protocol.Request{
			ProtocolVersion: legacyVersion, Operation: protocol.OperationActivateInstall,
			TransactionID: prepared.InstallerTransactionID, InstallPayloadSHA256: prepared.InstallPayloadSHA256,
			PreparedAck: &value,
		}, nil, true)
		if activateErr != nil {
			return InstallerTransaction{}, activateErr
		}
		if !receiptMatchesPreparedInstall(receipt, prepared) || receipt.Status != ReceiptStatusActive {
			return InstallerTransaction{}, ErrInstallerUncertain
		}
		return InstallerTransaction{InstallerTransactionID: prepared.InstallerTransactionID,
			Phase: InstallerTransactionActive, Prepared: prepared, Receipt: receipt}, nil
	}
	if err != nil {
		if errors.Is(err, errInstallerProtocol) {
			return InstallerTransaction{}, ErrInstallerUncertain
		}
		return InstallerTransaction{}, err
	}
	if response.TransactionStatus == nil {
		return InstallerTransaction{}, ErrInstaller
	}
	status := installerTransactionFromProtocol(*response.TransactionStatus)
	if status.Phase != InstallerTransactionInstalling || status.Prepared != prepared || status.Receipt != (ActivationReceipt{}) {
		return InstallerTransaction{}, ErrInstallerUncertain
	}
	readbackVersion := protocol.JournalVersion
	if prepared.ExecutionSequence != 0 {
		readbackVersion = protocol.JournalV3Version
	}
	readback, inspectErr := i.roundTrip(ctx, protocol.Request{
		ProtocolVersion: readbackVersion, Operation: protocol.OperationInspectTransaction,
		TransactionID: prepared.InstallerTransactionID,
	}, nil, false)
	if inspectErr != nil || readback.ProtocolVersion != readbackVersion || readback.TransactionStatus == nil {
		return InstallerTransaction{}, ErrInstallerUncertain
	}
	confirmed := installerTransactionFromProtocol(*readback.TransactionStatus)
	if confirmed.InstallerTransactionID != prepared.InstallerTransactionID || confirmed.Phase != InstallerTransactionInstalling ||
		confirmed.Prepared != prepared || confirmed.Receipt != (ActivationReceipt{}) {
		return InstallerTransaction{}, ErrInstallerUncertain
	}
	return confirmed, nil
}

func preparedInstallMatchesRequest(prepared PreparedInstall, request InstallRequest, expectedDigest string) bool {
	return validPreparedInstall(prepared, request.InstallerTransactionID) &&
		prepared.InstallPayloadSHA256 == expectedDigest &&
		prepared.ExecutionSequence == request.ExecutionSequence &&
		prepared.ReleaseSequence == request.ReleaseSequence &&
		prepared.ArtifactSHA256 == request.ArtifactSHA256 &&
		prepared.PreviousVersion == request.CurrentVersion &&
		prepared.TargetVersion == request.TargetVersion
}

func receiptMatchesPreparedInstall(receipt ActivationReceipt, prepared PreparedInstall) bool {
	if !validPreparedInstall(prepared, prepared.InstallerTransactionID) ||
		receipt.SchemaVersion != prepared.SchemaVersion ||
		receipt.InstallerTransactionID != prepared.InstallerTransactionID ||
		receipt.ExecutionSequence != prepared.ExecutionSequence ||
		receipt.ReleaseSequence != prepared.ReleaseSequence ||
		receipt.ArtifactSHA256 != prepared.ArtifactSHA256 {
		return false
	}
	switch receipt.Status {
	case ReceiptStatusActive:
		return receipt.CurrentVersion == prepared.TargetVersion && receipt.PreviousVersion == prepared.PreviousVersion
	case ReceiptStatusRolledBack:
		return receipt.CurrentVersion == prepared.PreviousVersion && receipt.PreviousVersion == prepared.TargetVersion
	default:
		return false
	}
}

func (i *PackagingInstaller) inspect(ctx context.Context, transactionID string, version int) (InstallerTransaction, error) {
	response, err := i.roundTrip(ctx, protocol.Request{
		ProtocolVersion: version, Operation: protocol.OperationInspectTransaction,
		TransactionID: transactionID,
	}, nil, false)
	if err != nil {
		return InstallerTransaction{}, err
	}
	if response.ProtocolVersion != version || response.TransactionStatus == nil {
		return InstallerTransaction{}, ErrInstaller
	}
	if response.TransactionStatus.TransactionID != transactionID {
		return InstallerTransaction{}, ErrInstallerUncertain
	}
	return installerTransactionFromProtocol(*response.TransactionStatus), nil
}

func (i *PackagingInstaller) Activate(ctx context.Context, prepared PreparedInstall) (ActivationReceipt, error) {
	value := preparedInstallToProtocol(prepared)
	protocolVersion := protocol.JournalVersion
	if prepared.ExecutionSequence != 0 {
		protocolVersion = protocol.JournalV3Version
	}
	response, err := i.roundTrip(ctx, protocol.Request{
		ProtocolVersion: protocolVersion, Operation: protocol.OperationActivateInstall,
		TransactionID: prepared.InstallerTransactionID, InstallPayloadSHA256: prepared.InstallPayloadSHA256,
		PreparedAck: &value,
	}, nil, true)
	if err != nil {
		return ActivationReceipt{}, err
	}
	if response.Receipt == nil {
		return ActivationReceipt{}, ErrInstaller
	}
	receipt := receiptFromProtocol(*response.Receipt)
	if !receiptMatchesPreparedInstall(receipt, prepared) {
		return ActivationReceipt{}, ErrInstallerUncertain
	}
	return receipt, nil
}

func (i *PackagingInstaller) Abort(ctx context.Context, prepared PreparedInstall) (InstallerTransaction, error) {
	value := preparedInstallToProtocol(prepared)
	protocolVersion := protocol.JournalVersion
	if prepared.ExecutionSequence != 0 {
		protocolVersion = protocol.JournalV3Version
	}
	response, err := i.roundTrip(ctx, protocol.Request{
		ProtocolVersion: protocolVersion, Operation: protocol.OperationAbortPrepared,
		TransactionID: prepared.InstallerTransactionID, InstallPayloadSHA256: prepared.InstallPayloadSHA256,
		PreparedAck: &value,
	}, nil, true)
	if err != nil {
		return InstallerTransaction{}, err
	}
	if response.TransactionStatus == nil {
		return InstallerTransaction{}, ErrInstaller
	}
	status := installerTransactionFromProtocol(*response.TransactionStatus)
	if status.Phase != InstallerTransactionAborted || status.Prepared != prepared || status.Receipt != (ActivationReceipt{}) {
		return InstallerTransaction{}, ErrInstallerUncertain
	}
	return status, nil
}

func (i *PackagingInstaller) Query(ctx context.Context, transactionID string) (ActivationReceipt, error) {
	return i.call(ctx, protocol.Request{
		ProtocolVersion: protocol.Version, Operation: protocol.OperationQuery, TransactionID: transactionID,
	}, nil, false)
}

func (i *PackagingInstaller) Rollback(ctx context.Context, request RollbackRequest) (ActivationReceipt, error) {
	active := receiptToProtocol(request.ActiveReceipt)
	previous := receiptToProtocol(request.PreviousReceipt)
	return i.call(ctx, protocol.Request{
		ProtocolVersion: protocol.Version, Operation: protocol.OperationRollback,
		TransactionID: request.InstallerTransactionID, ReleaseSequence: request.ReleaseSequence,
		ArtifactSHA256: request.ArtifactSHA256, ExpectedCurrentVersion: request.ExpectedCurrentVersion,
		RollbackVersion: request.RollbackVersion, ActiveReceipt: &active, PreviousReceipt: &previous,
	}, nil, true)
}

func (i *PackagingInstaller) call(ctx context.Context, request protocol.Request, artifact *os.File, mutating bool) (ActivationReceipt, error) {
	response, err := i.roundTrip(ctx, request, artifact, mutating)
	if err != nil {
		return ActivationReceipt{}, err
	}
	if response.Receipt == nil {
		return ActivationReceipt{}, ErrInstaller
	}
	return receiptFromProtocol(*response.Receipt), nil
}

func (i *PackagingInstaller) roundTrip(ctx context.Context, request protocol.Request, artifact *os.File, mutating bool) (protocol.Response, error) {
	if i == nil || i.transport == nil {
		return protocol.Response{}, ErrInstaller
	}
	attempts := 1
	if !mutating {
		attempts = readOnlyTransportAttempts
	}
	var response protocol.Response
	var err error
	retryDelay := readOnlyTransportInitialDelay
	for attempt := 0; attempt < attempts; attempt++ {
		response, err = i.transport.RoundTrip(ctx, request, artifact)
		if err == nil || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) || ctx.Err() != nil || attempt+1 == attempts {
			break
		}
		timer := time.NewTimer(retryDelay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return protocol.Response{}, ctx.Err()
		case <-timer.C:
			retryDelay *= 2
		}
	}
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return protocol.Response{}, err
		}
		if mutating && request.ProtocolVersion == protocol.JournalV4Version &&
			request.Operation == protocol.OperationMarkInstalling {
			var negotiationErr *helper.LegacyNegotiationError
			if errors.As(err, &negotiationErr) && negotiationErr.RequestVersion == protocol.JournalV4Version &&
				negotiationErr.PeerVersion == protocol.Version && negotiationErr.Code == protocol.ErrorBadRequest {
				return protocol.Response{}, errInstallerProtocol
			}
		}
		if mutating {
			return protocol.Response{}, ErrInstallerUncertain
		}
		return protocol.Response{}, ErrInstaller
	}
	if !response.OK {
		switch response.ErrorCode {
		case protocol.ErrorTransactionUnknown:
			return protocol.Response{}, ErrInstallerUnknown
		case protocol.ErrorProtocol:
			if mutating {
				return protocol.Response{}, ErrInstallerUncertain
			}
			return protocol.Response{}, ErrInstaller
		case protocol.ErrorTransactionConflict, protocol.ErrorCurrentUnavailable, protocol.ErrorStateUncertain, protocol.ErrorDeadline:
			return protocol.Response{}, ErrInstallerUncertain
		default:
			return protocol.Response{}, ErrInstaller
		}
	}
	return response, nil
}

func preparedInstallToProtocol(prepared PreparedInstall) protocol.PreparedAck {
	return protocol.PreparedAck{
		SchemaVersion: prepared.SchemaVersion, TransactionID: prepared.InstallerTransactionID,
		InstallPayloadSHA256: prepared.InstallPayloadSHA256, ExecutionSequence: prepared.ExecutionSequence,
		ReleaseSequence: prepared.ReleaseSequence,
		ArtifactSHA256:  prepared.ArtifactSHA256, ManifestSHA256: prepared.ManifestSHA256,
		ExecutableSHA256: prepared.ExecutableSHA256, SBOMSHA256: prepared.SBOMSHA256,
		PreviousVersion: prepared.PreviousVersion, TargetVersion: prepared.TargetVersion,
	}
}

func preparedInstallFromProtocol(prepared protocol.PreparedAck) PreparedInstall {
	return PreparedInstall{
		SchemaVersion: prepared.SchemaVersion, InstallerTransactionID: prepared.TransactionID,
		InstallPayloadSHA256: prepared.InstallPayloadSHA256, ExecutionSequence: prepared.ExecutionSequence,
		ReleaseSequence: prepared.ReleaseSequence,
		ArtifactSHA256:  prepared.ArtifactSHA256, ManifestSHA256: prepared.ManifestSHA256,
		ExecutableSHA256: prepared.ExecutableSHA256, SBOMSHA256: prepared.SBOMSHA256,
		PreviousVersion: prepared.PreviousVersion, TargetVersion: prepared.TargetVersion,
	}
}

func installerTransactionFromProtocol(status protocol.TransactionStatus) InstallerTransaction {
	result := InstallerTransaction{InstallerTransactionID: status.TransactionID, Phase: InstallerTransactionPhase(status.Phase)}
	if status.PreparedAck != nil {
		result.Prepared = preparedInstallFromProtocol(*status.PreparedAck)
	}
	if status.Receipt != nil {
		result.Receipt = receiptFromProtocol(*status.Receipt)
	}
	return result
}

func receiptToProtocol(receipt ActivationReceipt) protocol.Receipt {
	return protocol.Receipt{
		SchemaVersion: receipt.SchemaVersion, InstallerTransactionID: receipt.InstallerTransactionID,
		ExecutionSequence: receipt.ExecutionSequence, ReleaseSequence: receipt.ReleaseSequence,
		ArtifactSHA256: receipt.ArtifactSHA256,
		CurrentVersion: receipt.CurrentVersion, PreviousVersion: receipt.PreviousVersion,
		Status: string(receipt.Status), IssuedAt: receipt.IssuedAt,
		Signature: protocol.Signature{KeyID: receipt.Signature.KeyID, Value: receipt.Signature.Value},
	}
}

func receiptFromProtocol(receipt protocol.Receipt) ActivationReceipt {
	return ActivationReceipt{
		SchemaVersion: receipt.SchemaVersion, InstallerTransactionID: receipt.InstallerTransactionID,
		ExecutionSequence: receipt.ExecutionSequence, ReleaseSequence: receipt.ReleaseSequence,
		ArtifactSHA256: receipt.ArtifactSHA256,
		CurrentVersion: receipt.CurrentVersion, PreviousVersion: receipt.PreviousVersion,
		Status: ReceiptStatus(receipt.Status), IssuedAt: receipt.IssuedAt,
		Signature: Signature{KeyID: receipt.Signature.KeyID, Value: receipt.Signature.Value},
	}
}
