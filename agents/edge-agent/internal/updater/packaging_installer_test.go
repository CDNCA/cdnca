package updater

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/packaging/helper"
	"github.com/cdnca/cdnca/agents/edge-agent/packaging/helper/protocol"
)

type recordingPackagingTransport struct {
	request        protocol.Request
	requests       []protocol.Request
	artifact       *os.File
	response       protocol.Response
	responses      []protocol.Response
	responseErrors []error
	err            error
	errs           []error
	block          bool
	calls          int
}

func (t *recordingPackagingTransport) RoundTrip(ctx context.Context, request protocol.Request, artifact *os.File) (protocol.Response, error) {
	call := t.calls
	t.calls++
	t.request = request
	t.requests = append(t.requests, request)
	t.artifact = artifact
	if t.block {
		<-ctx.Done()
		return protocol.Response{}, ctx.Err()
	}
	if call < len(t.errs) && t.errs[call] != nil {
		return protocol.Response{}, t.errs[call]
	}
	if call < len(t.responses) {
		if call < len(t.responseErrors) && t.responseErrors[call] != nil {
			return t.responses[call], t.responseErrors[call]
		}
		return t.responses[call], nil
	}
	return t.response, t.err
}

func packagingReceipt() ActivationReceipt {
	digest := sha256.Sum256([]byte("bundle"))
	return ActivationReceipt{
		SchemaVersion: 1, InstallerTransactionID: "txn-123", ReleaseSequence: 2,
		ArtifactSHA256: hex.EncodeToString(digest[:]), CurrentVersion: "1.1.0", PreviousVersion: "1.0.0",
		Status: ReceiptStatusActive, IssuedAt: time.Date(2026, 7, 28, 0, 0, 0, 0, time.UTC),
		Signature: Signature{KeyID: "helper-2026-01", Value: base64.RawStdEncoding.EncodeToString(make([]byte, 64))},
	}
}

func successfulPackagingTransport(receipt ActivationReceipt) *recordingPackagingTransport {
	value := receiptToProtocol(receipt)
	return &recordingPackagingTransport{response: protocol.Success(value)}
}

func packagingPreparedInstall() PreparedInstall {
	digest := sha256.Sum256([]byte("prepared-install"))
	return PreparedInstall{
		SchemaVersion: 1, InstallerTransactionID: "txn-123",
		InstallPayloadSHA256: hex.EncodeToString(digest[:]), ReleaseSequence: 2,
		ArtifactSHA256: packagingReceipt().ArtifactSHA256, ManifestSHA256: hex.EncodeToString(digest[:]),
		ExecutableSHA256: hex.EncodeToString(digest[:]), SBOMSHA256: hex.EncodeToString(digest[:]),
		PreviousVersion: "1.0.0", TargetVersion: "1.1.0",
	}
}

func preparePacketDigestForTest(t *testing.T, request InstallRequest) string {
	t.Helper()
	current := receiptToProtocol(request.CurrentReceipt)
	packet, err := protocol.MarshalRequest(protocol.Request{
		ProtocolVersion: protocol.JournalVersion, Operation: protocol.OperationPrepareInstall,
		TransactionID: request.InstallerTransactionID, ReleaseSequence: request.ReleaseSequence,
		CurrentVersion: request.CurrentVersion, TargetVersion: request.TargetVersion,
		Platform: request.Platform, Architecture: request.Architecture,
		ArtifactSHA256: request.ArtifactSHA256, ArtifactSize: request.ArtifactSize,
		AuditBasename: filepath.Base(request.StagedPath), CurrentReceipt: &current,
	})
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(packet)
	return hex.EncodeToString(digest[:])
}

func TestPackagingInstallerV2MapsPrepareInspectActivateWithoutLegacyFallback(t *testing.T) {
	receipt := packagingReceipt()
	transport := &recordingPackagingTransport{}
	installer := &PackagingInstaller{transport: transport}
	if got := installer.ProtocolVersion(); got != protocol.JournalVersion {
		t.Fatalf("ProtocolVersion() = %d, want %d", got, protocol.JournalVersion)
	}

	artifact, err := os.CreateTemp(t.TempDir(), "artifact-*")
	if err != nil {
		t.Fatal(err)
	}
	defer artifact.Close()
	request := InstallRequest{
		InstallerTransactionID: "txn-123", ReleaseSequence: 2,
		CurrentVersion: "1.0.0", TargetVersion: "1.1.0", Platform: "linux", Architecture: "amd64",
		ArtifactSHA256: receipt.ArtifactSHA256, ArtifactSize: 1234,
		StagedPath: filepath.Join("private", "verified", "artifact"), Artifact: artifact,
		CurrentReceipt: receipt,
	}
	prepared := packagingPreparedInstall()
	prepared.InstallPayloadSHA256 = preparePacketDigestForTest(t, request)
	transport.response = protocol.Prepared(protocol.JournalVersion, preparedInstallToProtocol(prepared))
	gotPrepared, err := installer.Prepare(context.Background(), request)
	if err != nil || gotPrepared != prepared {
		t.Fatalf("Prepare() = (%#v, %v)", gotPrepared, err)
	}
	if transport.request.ProtocolVersion != protocol.JournalVersion || transport.request.Operation != protocol.OperationPrepareInstall ||
		transport.request.AuditBasename != "artifact" || transport.artifact != artifact {
		t.Fatalf("prepare transport = (%#v, %p), want v2 prepare with artifact", transport.request, transport.artifact)
	}

	aborter, ok := any(installer).(interface {
		Abort(context.Context, PreparedInstall) (InstallerTransaction, error)
	})
	if !ok {
		t.Fatal("PackagingInstaller does not expose durable abort_prepared")
	}
	transport.response = protocol.Inspected(protocol.JournalVersion, protocol.TransactionStatus{
		TransactionID: prepared.InstallerTransactionID, Phase: protocol.TransactionAborted,
		PreparedAck: pointerPreparedAck(preparedInstallToProtocol(prepared)),
	})
	aborted, err := aborter.Abort(context.Background(), prepared)
	if err != nil || aborted.Phase != InstallerTransactionPhase("aborted") || aborted.Prepared != prepared {
		t.Fatalf("Abort() = (%#v, %v)", aborted, err)
	}
	if transport.request.Operation != protocol.OperationAbortPrepared || transport.request.PreparedAck == nil || transport.artifact != nil {
		t.Fatalf("abort transport = (%#v, %p)", transport.request, transport.artifact)
	}

	transport.response = protocol.Inspected(protocol.JournalVersion, protocol.TransactionStatus{
		TransactionID: "txn-123", Phase: protocol.TransactionPrepared, PreparedAck: pointerPreparedAck(preparedInstallToProtocol(prepared)),
	})
	gotStatus, err := installer.Inspect(context.Background(), "txn-123")
	if err != nil || gotStatus.Phase != InstallerTransactionPrepared || gotStatus.Prepared != prepared || gotStatus.Receipt != (ActivationReceipt{}) {
		t.Fatalf("Inspect() = (%#v, %v)", gotStatus, err)
	}
	if transport.request.ProtocolVersion != protocol.JournalVersion || transport.request.Operation != protocol.OperationInspectTransaction || transport.artifact != nil {
		t.Fatalf("inspect transport = (%#v, %p)", transport.request, transport.artifact)
	}

	transport.responses = []protocol.Response{
		protocol.Inspected(protocol.JournalV4Version, protocol.TransactionStatus{
			TransactionID: "txn-123", Phase: protocol.TransactionInstalling, PreparedAck: pointerPreparedAck(preparedInstallToProtocol(prepared)),
		}),
		protocol.Inspected(protocol.JournalVersion, protocol.TransactionStatus{
			TransactionID: "txn-123", Phase: protocol.TransactionInstalling, PreparedAck: pointerPreparedAck(preparedInstallToProtocol(prepared)),
		}),
	}
	transport.calls = 0
	transport.requests = nil
	marked, err := installer.MarkInstalling(context.Background(), prepared)
	if err != nil || marked.Phase != InstallerTransactionInstalling || marked.Prepared != prepared || marked.Receipt != (ActivationReceipt{}) {
		t.Fatalf("MarkInstalling() = (%#v, %v)", marked, err)
	}
	if len(transport.requests) < 2 || transport.requests[len(transport.requests)-2].ProtocolVersion != protocol.JournalV4Version ||
		transport.requests[len(transport.requests)-2].Operation != protocol.OperationMarkInstalling ||
		transport.requests[len(transport.requests)-2].InstallPayloadSHA256 != prepared.InstallPayloadSHA256 ||
		transport.requests[len(transport.requests)-2].PreparedAck == nil ||
		transport.request.ProtocolVersion != protocol.JournalVersion || transport.request.Operation != protocol.OperationInspectTransaction ||
		transport.artifact != nil {
		t.Fatalf("mark installing/readback transport = (%#v, %p), requests=%#v", transport.request, transport.artifact, transport.requests)
	}

	transport.response = protocol.SuccessForVersion(protocol.JournalVersion, receiptToProtocol(receipt))
	gotReceipt, err := installer.Activate(context.Background(), prepared)
	if err != nil || gotReceipt != receipt {
		t.Fatalf("Activate() = (%#v, %v)", gotReceipt, err)
	}
	if transport.request.ProtocolVersion != protocol.JournalVersion || transport.request.Operation != protocol.OperationActivateInstall ||
		transport.request.InstallPayloadSHA256 != prepared.InstallPayloadSHA256 || transport.request.PreparedAck == nil || transport.artifact != nil {
		t.Fatalf("activate transport = (%#v, %p)", transport.request, transport.artifact)
	}
}

func TestPackagingInstallerMarkInstallingDoesNotFallbackForSameVersionProtocolError(t *testing.T) {
	prepared := packagingPreparedInstall()
	transport := &recordingPackagingTransport{responses: []protocol.Response{
		protocol.FailureForVersion(protocol.JournalV4Version, protocol.ErrorProtocol),
	}}
	installer := &PackagingInstaller{transport: transport}
	marked, err := installer.MarkInstalling(context.Background(), prepared)
	if !errors.Is(err, ErrInstallerUncertain) || marked != (InstallerTransaction{}) || transport.calls != 1 ||
		transport.requests[0].ProtocolVersion != protocol.JournalV4Version ||
		transport.requests[0].Operation != protocol.OperationMarkInstalling {
		t.Fatalf("legacy mark fallback = (%#v, %v), requests=%#v", marked, err, transport.requests)
	}
}

func TestPackagingInstallerMarkInstallingRequiresDurableHelperReadback(t *testing.T) {
	prepared := packagingPreparedInstall()
	transport := &recordingPackagingTransport{responses: []protocol.Response{
		protocol.Inspected(protocol.JournalV4Version, protocol.TransactionStatus{
			TransactionID: prepared.InstallerTransactionID, Phase: protocol.TransactionInstalling,
			PreparedAck: pointerPreparedAck(preparedInstallToProtocol(prepared)),
		}),
		protocol.Inspected(protocol.JournalVersion, protocol.TransactionStatus{
			TransactionID: prepared.InstallerTransactionID, Phase: protocol.TransactionUnknown,
		}),
	}}
	installer := &PackagingInstaller{transport: transport}
	marked, err := installer.MarkInstalling(context.Background(), prepared)
	if !errors.Is(err, ErrInstallerUncertain) || marked != (InstallerTransaction{}) || transport.calls != 2 ||
		transport.requests[0].Operation != protocol.OperationMarkInstalling ||
		transport.requests[1].Operation != protocol.OperationInspectTransaction {
		t.Fatalf("accepted non-durable helper installing response = (%#v, %v), calls=%d, requests=%#v",
			marked, err, transport.calls, transport.requests)
	}
}

func TestPackagingInstallerMarkInstallingUsesV3ReadbackForExecutionSequence(t *testing.T) {
	prepared := packagingPreparedInstall()
	prepared.SchemaVersion = 2
	prepared.ExecutionSequence = 11
	ack := preparedInstallToProtocol(prepared)
	transport := &recordingPackagingTransport{responses: []protocol.Response{
		protocol.Inspected(protocol.JournalV4Version, protocol.TransactionStatus{
			TransactionID: prepared.InstallerTransactionID, Phase: protocol.TransactionInstalling, PreparedAck: &ack,
		}),
		protocol.Inspected(protocol.JournalV3Version, protocol.TransactionStatus{
			TransactionID: prepared.InstallerTransactionID, Phase: protocol.TransactionInstalling, PreparedAck: &ack,
		}),
	}}
	installer := &PackagingInstaller{transport: transport}
	marked, err := installer.MarkInstalling(context.Background(), prepared)
	if err != nil || marked.Phase != InstallerTransactionInstalling || marked.Prepared != prepared || marked.Receipt != (ActivationReceipt{}) {
		t.Fatalf("MarkInstalling() = (%#v, %v)", marked, err)
	}
	if len(transport.requests) != 2 || transport.requests[0].ProtocolVersion != protocol.JournalV4Version ||
		transport.requests[0].Operation != protocol.OperationMarkInstalling ||
		transport.requests[1].ProtocolVersion != protocol.JournalV3Version ||
		transport.requests[1].Operation != protocol.OperationInspectTransaction {
		t.Fatalf("v3 mark installing/readback requests = %#v", transport.requests)
	}
}

func TestPackagingInstallerMarkInstallingDoesNotFallbackForUnprovenTransportProtocolError(t *testing.T) {
	prepared := packagingPreparedInstall()
	transport := &recordingPackagingTransport{err: &helper.ProtocolError{Code: protocol.ErrorProtocol}}
	installer := &PackagingInstaller{transport: transport}
	marked, err := installer.MarkInstalling(context.Background(), prepared)
	if !errors.Is(err, ErrInstallerUncertain) || marked != (InstallerTransaction{}) || transport.calls != 1 ||
		transport.requests[0].ProtocolVersion != protocol.JournalV4Version ||
		transport.requests[0].Operation != protocol.OperationMarkInstalling {
		t.Fatalf("unproven transport protocol error fallback = (%#v, %v), requests=%#v", marked, err, transport.requests)
	}
}

func TestPackagingInstallerMutatingProtocolErrorsFailClosed(t *testing.T) {
	for _, version := range []int{protocol.JournalVersion, protocol.JournalV3Version} {
		version := version
		t.Run(fmt.Sprintf("prepare-v%d", version), func(t *testing.T) {
			artifact, err := os.CreateTemp(t.TempDir(), "artifact-*")
			if err != nil {
				t.Fatal(err)
			}
			defer artifact.Close()
			receipt := packagingReceipt()
			request := InstallRequest{
				InstallerTransactionID: "txn-123", ReleaseSequence: 2,
				CurrentVersion: "1.0.0", TargetVersion: "1.1.0", Platform: "linux", Architecture: "amd64",
				ArtifactSHA256: receipt.ArtifactSHA256, ArtifactSize: 1,
				StagedPath: filepath.Join("private", "verified", "artifact"), Artifact: artifact,
				CurrentReceipt: receipt,
			}
			if version == protocol.JournalV3Version {
				request.ExecutionSequence = 11
				request.Action = ActionUpgrade
			}
			transport := &recordingPackagingTransport{response: protocol.FailureForVersion(version, protocol.ErrorProtocol)}
			_, err = (&PackagingInstaller{transport: transport}).Prepare(context.Background(), request)
			if !errors.Is(err, ErrInstallerUncertain) || transport.calls != 1 {
				t.Fatalf("Prepare() error = %v, calls=%d", err, transport.calls)
			}
		})

		for _, operation := range []struct {
			name string
			call func(*PackagingInstaller, PreparedInstall) error
		}{
			{name: "activate", call: func(installer *PackagingInstaller, prepared PreparedInstall) error {
				_, err := installer.Activate(context.Background(), prepared)
				return err
			}},
			{name: "abort", call: func(installer *PackagingInstaller, prepared PreparedInstall) error {
				_, err := installer.Abort(context.Background(), prepared)
				return err
			}},
		} {
			operation := operation
			t.Run(fmt.Sprintf("%s-v%d", operation.name, version), func(t *testing.T) {
				prepared := packagingPreparedInstall()
				if version == protocol.JournalV3Version {
					prepared.ExecutionSequence = 11
				}
				transport := &recordingPackagingTransport{response: protocol.FailureForVersion(version, protocol.ErrorProtocol)}
				err := operation.call(&PackagingInstaller{transport: transport}, prepared)
				if !errors.Is(err, ErrInstallerUncertain) || transport.calls != 1 {
					t.Fatalf("%s() error = %v, calls=%d", operation.name, err, transport.calls)
				}
			})
		}
	}
}

func TestPackagingInstallerMarkInstallingFallsBackForLegacyBadRequestPeer(t *testing.T) {
	prepared := packagingPreparedInstall()
	receipt := packagingReceipt()
	transport := &recordingPackagingTransport{
		responses: []protocol.Response{
			{ProtocolVersion: protocol.Version, ErrorCode: protocol.ErrorBadRequest},
			protocol.SuccessForVersion(protocol.JournalVersion, receiptToProtocol(receipt)),
		},
		responseErrors: []error{&helper.LegacyNegotiationError{
			RequestVersion: protocol.JournalV4Version, PeerVersion: protocol.Version, Code: protocol.ErrorBadRequest,
		}},
	}
	installer := &PackagingInstaller{transport: transport}
	marked, err := installer.MarkInstalling(context.Background(), prepared)
	if err != nil || marked.Phase != InstallerTransactionActive || marked.Prepared != prepared ||
		marked.Receipt != receipt || transport.calls != 2 ||
		transport.requests[0].ProtocolVersion != protocol.JournalV4Version ||
		transport.requests[0].Operation != protocol.OperationMarkInstalling ||
		transport.requests[1].ProtocolVersion != protocol.JournalVersion ||
		transport.requests[1].Operation != protocol.OperationActivateInstall {
		t.Fatalf("legacy bad-request fallback = (%#v, %v), requests=%#v responses=%#v", marked, err, transport.requests, transport.responses)
	}
}

func TestPackagingInstallerRejectsLegacyReceiptIdentityMismatch(t *testing.T) {
	prepared := packagingPreparedInstall()
	receipt := packagingReceipt()
	receipt.InstallerTransactionID = "txn-other"
	transport := &recordingPackagingTransport{
		responses: []protocol.Response{
			{ProtocolVersion: protocol.Version, ErrorCode: protocol.ErrorBadRequest},
			protocol.SuccessForVersion(protocol.JournalVersion, receiptToProtocol(receipt)),
		},
		responseErrors: []error{&helper.LegacyNegotiationError{
			RequestVersion: protocol.JournalV4Version, PeerVersion: protocol.Version, Code: protocol.ErrorBadRequest,
		}},
	}
	installer := &PackagingInstaller{transport: transport}
	marked, err := installer.MarkInstalling(context.Background(), prepared)
	if !errors.Is(err, ErrInstallerUncertain) || marked != (InstallerTransaction{}) || transport.calls != 2 ||
		transport.requests[1].Operation != protocol.OperationActivateInstall {
		t.Fatalf("accepted mismatched legacy receipt = (%#v, %v), requests=%#v", marked, err, transport.requests)
	}
}

func TestPackagingInstallerPrepareRejectsAckOutsideCanonicalRequestDigest(t *testing.T) {
	receipt := packagingReceipt()
	artifact, err := os.CreateTemp(t.TempDir(), "artifact-*")
	if err != nil {
		t.Fatal(err)
	}
	defer artifact.Close()
	request := InstallRequest{
		InstallerTransactionID: "txn-123", ReleaseSequence: 2,
		CurrentVersion: "1.0.0", TargetVersion: "1.1.0", Platform: "linux", Architecture: "amd64",
		ArtifactSHA256: receipt.ArtifactSHA256, ArtifactSize: 1234,
		StagedPath: filepath.Join("private", "verified", "artifact"), Artifact: artifact,
		CurrentReceipt: receipt,
	}
	prepared := packagingPreparedInstall()
	if prepared.InstallPayloadSHA256 == preparePacketDigestForTest(t, request) {
		t.Fatal("test ACK digest unexpectedly matches canonical prepare packet")
	}
	transport := &recordingPackagingTransport{response: protocol.Prepared(protocol.JournalVersion, preparedInstallToProtocol(prepared))}
	installer := &PackagingInstaller{transport: transport}
	if got, err := installer.Prepare(context.Background(), request); !errors.Is(err, ErrInstallerUncertain) || got != (PreparedInstall{}) || transport.calls != 1 {
		t.Fatalf("tampered prepare ACK = (%#v, %v), calls=%d", got, err, transport.calls)
	}
}

func TestPackagingInstallerPrepareRejectsAckOutsideInstallIdentity(t *testing.T) {
	receipt := packagingReceipt()
	artifact, err := os.CreateTemp(t.TempDir(), "artifact-*")
	if err != nil {
		t.Fatal(err)
	}
	defer artifact.Close()
	request := InstallRequest{
		InstallerTransactionID: "txn-123", ReleaseSequence: 2,
		CurrentVersion: "1.0.0", TargetVersion: "1.1.0", Platform: "linux", Architecture: "amd64",
		ArtifactSHA256: receipt.ArtifactSHA256, ArtifactSize: 1234,
		StagedPath: filepath.Join("private", "verified", "artifact"), Artifact: artifact,
		CurrentReceipt: receipt,
	}
	expectedDigest := preparePacketDigestForTest(t, request)
	otherArtifactDigest := sha256.Sum256([]byte("other-artifact"))
	otherArtifactSHA := hex.EncodeToString(otherArtifactDigest[:])
	for _, test := range []struct {
		name   string
		mutate func(*protocol.PreparedAck)
	}{
		{name: "transaction", mutate: func(ack *protocol.PreparedAck) { ack.TransactionID = "txn-other" }},
		{name: "execution", mutate: func(ack *protocol.PreparedAck) { ack.ExecutionSequence = 11 }},
		{name: "release", mutate: func(ack *protocol.PreparedAck) { ack.ReleaseSequence = 3 }},
		{name: "artifact", mutate: func(ack *protocol.PreparedAck) { ack.ArtifactSHA256 = otherArtifactSHA }},
		{name: "previous", mutate: func(ack *protocol.PreparedAck) { ack.PreviousVersion = "0.9.0" }},
		{name: "target", mutate: func(ack *protocol.PreparedAck) { ack.TargetVersion = "1.2.0" }},
		{name: "schema", mutate: func(ack *protocol.PreparedAck) { ack.SchemaVersion = 2 }},
	} {
		t.Run(test.name, func(t *testing.T) {
			ack := preparedInstallToProtocol(packagingPreparedInstall())
			ack.InstallPayloadSHA256 = expectedDigest
			test.mutate(&ack)
			transport := &recordingPackagingTransport{response: protocol.Prepared(protocol.JournalVersion, ack)}
			got, err := (&PackagingInstaller{transport: transport}).Prepare(context.Background(), request)
			if !errors.Is(err, ErrInstallerUncertain) || got != (PreparedInstall{}) || transport.calls != 1 {
				t.Fatalf("accepted mismatched ACK = (%#v, %v), calls=%d", got, err, transport.calls)
			}
		})
	}
}

func TestPackagingInstallerActivateRejectsReceiptOutsidePreparedIdentity(t *testing.T) {
	prepared := packagingPreparedInstall()
	otherArtifactDigest := sha256.Sum256([]byte("other-artifact"))
	otherArtifactSHA := hex.EncodeToString(otherArtifactDigest[:])
	for _, test := range []struct {
		name   string
		mutate func(*ActivationReceipt)
	}{
		{name: "transaction", mutate: func(receipt *ActivationReceipt) { receipt.InstallerTransactionID = "txn-other" }},
		{name: "execution", mutate: func(receipt *ActivationReceipt) { receipt.ExecutionSequence = 11 }},
		{name: "release", mutate: func(receipt *ActivationReceipt) { receipt.ReleaseSequence = 3 }},
		{name: "artifact", mutate: func(receipt *ActivationReceipt) { receipt.ArtifactSHA256 = otherArtifactSHA }},
		{name: "current", mutate: func(receipt *ActivationReceipt) { receipt.CurrentVersion = "1.2.0" }},
		{name: "previous", mutate: func(receipt *ActivationReceipt) { receipt.PreviousVersion = "0.9.0" }},
		{name: "status", mutate: func(receipt *ActivationReceipt) { receipt.Status = ReceiptStatusRolledBack }},
		{name: "schema", mutate: func(receipt *ActivationReceipt) { receipt.SchemaVersion = 2; receipt.ExecutionSequence = 11 }},
	} {
		t.Run(test.name, func(t *testing.T) {
			receipt := packagingReceipt()
			test.mutate(&receipt)
			transport := &recordingPackagingTransport{response: protocol.SuccessForVersion(protocol.JournalVersion, receiptToProtocol(receipt))}
			got, err := (&PackagingInstaller{transport: transport}).Activate(context.Background(), prepared)
			if !errors.Is(err, ErrInstallerUncertain) || got != (ActivationReceipt{}) || transport.calls != 1 {
				t.Fatalf("accepted mismatched receipt = (%#v, %v), calls=%d", got, err, transport.calls)
			}
		})
	}
	receipt := packagingReceipt()
	receipt.Status = ReceiptStatusRolledBack
	receipt.CurrentVersion = prepared.PreviousVersion
	receipt.PreviousVersion = prepared.TargetVersion
	transport := &recordingPackagingTransport{response: protocol.SuccessForVersion(protocol.JournalVersion, receiptToProtocol(receipt))}
	got, err := (&PackagingInstaller{transport: transport}).Activate(context.Background(), prepared)
	if err != nil || got != receipt {
		t.Fatalf("rejected valid rolled-back receipt = (%#v, %v)", got, err)
	}
}

func TestPackagingInstallerV2RetriesOnlyInspectAndFailsClosedOnResponseLoss(t *testing.T) {
	reset := errors.New("socket activation reset")
	prepared := packagingPreparedInstall()
	status := protocol.TransactionStatus{
		TransactionID: prepared.InstallerTransactionID, Phase: protocol.TransactionPrepared,
		PreparedAck: pointerPreparedAck(preparedInstallToProtocol(prepared)),
	}
	transport := &recordingPackagingTransport{
		response: protocol.Inspected(protocol.JournalVersion, status), errs: []error{reset, nil},
	}
	installer := &PackagingInstaller{transport: transport}
	if got, err := installer.Inspect(context.Background(), prepared.InstallerTransactionID); err != nil || got.Prepared != prepared || transport.calls != 2 {
		t.Fatalf("Inspect retry = (%#v, %v), calls=%d", got, err, transport.calls)
	}

	transport = &recordingPackagingTransport{err: reset}
	installer = &PackagingInstaller{transport: transport}
	if _, err := installer.Activate(context.Background(), prepared); !errors.Is(err, ErrInstallerUncertain) || transport.calls != 1 {
		t.Fatalf("Activate response loss = %v, calls=%d", err, transport.calls)
	}
}

func TestPackagingInstallerInspectRecoversV3JournalWithoutProtocolDowngrade(t *testing.T) {
	prepared := packagingPreparedInstall()
	prepared.SchemaVersion = 2
	prepared.ExecutionSequence = 11
	status := protocol.TransactionStatus{
		TransactionID: prepared.InstallerTransactionID, Phase: protocol.TransactionPrepared,
		PreparedAck: pointerPreparedAck(preparedInstallToProtocol(prepared)),
	}
	transport := &recordingPackagingTransport{responses: []protocol.Response{
		protocol.FailureForVersion(protocol.JournalVersion, protocol.ErrorProtocol),
		protocol.Inspected(protocol.JournalV3Version, status),
	}}
	installer := &PackagingInstaller{transport: transport}
	got, err := installer.Inspect(context.Background(), prepared.InstallerTransactionID)
	if err != nil || got.Prepared != prepared || transport.calls != 2 || len(transport.requests) != 2 ||
		transport.requests[0].ProtocolVersion != protocol.JournalVersion ||
		transport.requests[1].ProtocolVersion != protocol.JournalV3Version {
		t.Fatalf("v3 inspect recovery = (%#v, %v), requests=%#v", got, err, transport.requests)
	}
}

func TestPackagingInstallerInspectRejectsTransactionIdentityMismatch(t *testing.T) {
	status := protocol.TransactionStatus{
		TransactionID: "txn-other", Phase: protocol.TransactionUnknown,
	}
	transport := &recordingPackagingTransport{responses: []protocol.Response{
		protocol.Inspected(protocol.JournalVersion, status),
		protocol.Inspected(protocol.JournalV3Version, status),
	}}
	installer := &PackagingInstaller{transport: transport}
	got, err := installer.Inspect(context.Background(), "txn-123")
	if !errors.Is(err, ErrInstallerUncertain) || got != (InstallerTransaction{}) || transport.calls != 2 ||
		transport.requests[0].ProtocolVersion != protocol.JournalVersion ||
		transport.requests[1].ProtocolVersion != protocol.JournalV3Version {
		t.Fatalf("mismatched inspect identity = (%#v, %v), calls=%d, requests=%#v", got, err, transport.calls, transport.requests)
	}
}

func pointerPreparedAck(value protocol.PreparedAck) *protocol.PreparedAck { return &value }

func TestPackagingInstallerMapsAllOperationsWithoutPathAuthority(t *testing.T) {
	receipt := packagingReceipt()
	transport := successfulPackagingTransport(receipt)
	installer := &PackagingInstaller{transport: transport}

	if got, err := installer.Current(context.Background()); err != nil || got != receipt {
		t.Fatalf("current = %#v, %v", got, err)
	}
	if transport.request.Operation != protocol.OperationCurrent || transport.artifact != nil {
		t.Fatal("current transport shape mismatch")
	}

	if got, err := installer.Query(context.Background(), "txn-123"); err != nil || got != receipt {
		t.Fatalf("query = %#v, %v", got, err)
	}
	if transport.request.Operation != protocol.OperationQuery || transport.request.TransactionID != "txn-123" || transport.artifact != nil {
		t.Fatal("query transport shape mismatch")
	}

	file, err := os.CreateTemp(t.TempDir(), "artifact-*")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	request := InstallRequest{
		InstallerTransactionID: "txn-123", ReleaseSequence: 2,
		CurrentVersion: "1.0.0", TargetVersion: "1.1.0", Platform: "linux", Architecture: "amd64",
		ArtifactSHA256: receipt.ArtifactSHA256, ArtifactSize: 1234,
		StagedPath: filepath.Join("private", "verified", "artifact"), Artifact: file,
		CurrentReceipt: receipt,
	}
	if got, err := installer.Install(context.Background(), request); err != nil || got != receipt {
		t.Fatalf("install = %#v, %v", got, err)
	}
	if transport.request.Operation != protocol.OperationInstall || transport.request.AuditBasename != "artifact" ||
		transport.request.CurrentReceipt == nil || transport.artifact != file {
		t.Fatal("install transport shape mismatch")
	}
	if transport.request.AuditBasename == request.StagedPath {
		t.Fatal("staged path crossed the helper boundary")
	}

	rollback := RollbackRequest{
		InstallerTransactionID: "txn-123", ReleaseSequence: 2, ArtifactSHA256: receipt.ArtifactSHA256,
		ExpectedCurrentVersion: "1.1.0", RollbackVersion: "1.0.0",
		ActiveReceipt: receipt, PreviousReceipt: receipt,
	}
	if got, err := installer.Rollback(context.Background(), rollback); err != nil || got != receipt {
		t.Fatalf("rollback = %#v, %v", got, err)
	}
	if transport.request.Operation != protocol.OperationRollback || transport.request.ActiveReceipt == nil ||
		transport.request.PreviousReceipt == nil || transport.artifact != nil {
		t.Fatal("rollback transport shape mismatch")
	}
}

func TestPackagingInstallerStableErrorMapping(t *testing.T) {
	for _, test := range []struct {
		name string
		code protocol.ErrorCode
		want error
	}{
		{"unknown", protocol.ErrorTransactionUnknown, ErrInstallerUnknown},
		{"conflict", protocol.ErrorTransactionConflict, ErrInstallerUncertain},
		{"current unavailable", protocol.ErrorCurrentUnavailable, ErrInstallerUncertain},
		{"uncertain", protocol.ErrorStateUncertain, ErrInstallerUncertain},
		{"deadline", protocol.ErrorDeadline, ErrInstallerUncertain},
		{"policy", protocol.ErrorSocketPolicy, ErrInstaller},
		{"packaging", protocol.ErrorPackagingFailed, ErrInstaller},
	} {
		t.Run(test.name, func(t *testing.T) {
			transport := &recordingPackagingTransport{response: protocol.Failure(test.code)}
			installer := &PackagingInstaller{transport: transport}
			_, err := installer.Query(context.Background(), "txn-123")
			if !errors.Is(err, test.want) {
				t.Fatalf("error = %v, want %v", err, test.want)
			}
		})
	}

	installer := &PackagingInstaller{transport: &recordingPackagingTransport{err: errors.New("response lost")}}
	_, err := installer.Rollback(context.Background(), RollbackRequest{})
	if !errors.Is(err, ErrInstallerUncertain) {
		t.Fatalf("mutating transport error = %v", err)
	}
}

func TestPackagingInstallerRetriesOnlyReadOnlyTransportErrors(t *testing.T) {
	reset := errors.New("socket activation reset")
	receipt := packagingReceipt()

	for _, operation := range []struct {
		name string
		call func(*PackagingInstaller) (ActivationReceipt, error)
	}{
		{"current", func(installer *PackagingInstaller) (ActivationReceipt, error) {
			return installer.Current(context.Background())
		}},
		{"query", func(installer *PackagingInstaller) (ActivationReceipt, error) {
			return installer.Query(context.Background(), "txn-123")
		}},
	} {
		t.Run(operation.name, func(t *testing.T) {
			transport := successfulPackagingTransport(receipt)
			transport.errs = []error{reset, nil}
			got, err := operation.call(&PackagingInstaller{transport: transport})
			if err != nil || got != receipt || transport.calls != 2 {
				t.Fatalf("call = (%#v, %v), transport calls = %d", got, err, transport.calls)
			}
		})
	}

	persistentErrors := make([]error, readOnlyTransportAttempts)
	for index := range persistentErrors {
		persistentErrors[index] = reset
	}
	transport := &recordingPackagingTransport{errs: persistentErrors}
	_, err := (&PackagingInstaller{transport: transport}).Current(context.Background())
	if !errors.Is(err, ErrInstaller) || transport.calls != readOnlyTransportAttempts {
		t.Fatalf("persistent read-only error = %v, transport calls = %d", err, transport.calls)
	}

	artifact, err := os.CreateTemp(t.TempDir(), "artifact-*")
	if err != nil {
		t.Fatal(err)
	}
	defer artifact.Close()
	transport = &recordingPackagingTransport{err: reset}
	installer := &PackagingInstaller{transport: transport}
	_, err = installer.Install(context.Background(), InstallRequest{Artifact: artifact})
	if !errors.Is(err, ErrInstallerUncertain) || transport.calls != 1 {
		t.Fatalf("install error = %v, transport calls = %d", err, transport.calls)
	}
	transport.calls = 0
	_, err = installer.Rollback(context.Background(), RollbackRequest{})
	if !errors.Is(err, ErrInstallerUncertain) || transport.calls != 1 {
		t.Fatalf("rollback error = %v, transport calls = %d", err, transport.calls)
	}
}

func TestPackagingInstallerHonorsContextDeadline(t *testing.T) {
	transport := &recordingPackagingTransport{block: true}
	installer := &PackagingInstaller{transport: transport}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	_, err := installer.Current(ctx)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("error = %v", err)
	}
	if transport.calls != 1 {
		t.Fatalf("deadline transport calls = %d", transport.calls)
	}
}

func TestPackagingInstallerHonorsCancellationDuringReadOnlyBackoff(t *testing.T) {
	transport := &recordingPackagingTransport{err: errors.New("socket activation reset")}
	installer := &PackagingInstaller{transport: transport}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cancelTimer := time.AfterFunc(10*time.Millisecond, cancel)
	defer cancelTimer.Stop()
	_, err := installer.Current(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v", err)
	}
	if transport.calls != 1 {
		t.Fatalf("canceled backoff transport calls = %d", transport.calls)
	}
}

func TestDefaultConfigBundleLimitIsKnownIntegrationRED(t *testing.T) {
	config := DefaultConfig(t.TempDir(), "1.0.0", nil, nil, nil, nil, nil)
	if config.MaxArtifactBytes != protocol.MaxArtifactBytes {
		t.Fatalf("DefaultConfig limit %d does not equal frozen bundle maximum %d on %s/%s", config.MaxArtifactBytes, protocol.MaxArtifactBytes, runtime.GOOS, runtime.GOARCH)
	}
}
