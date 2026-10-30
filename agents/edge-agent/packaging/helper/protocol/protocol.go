package protocol

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"time"
	"unicode/utf8"
)

const (
	Version                = 1
	JournalVersion         = 2
	JournalV3Version       = 3
	JournalV4Version       = 4
	MaxPacketBytes         = 32768
	MaxArtifactBytes int64 = 285229182
)

type Action string

const (
	ActionUpgrade  Action = "upgrade"
	ActionRollback Action = "rollback"
)

type Operation string

const (
	OperationCurrent  Operation = "current"
	OperationQuery    Operation = "query"
	OperationInstall  Operation = "install"
	OperationRollback Operation = "rollback"

	OperationPrepareInstall     Operation = "prepare_install"
	OperationInspectTransaction Operation = "inspect_transaction"
	OperationMarkInstalling     Operation = "mark_installing"
	OperationActivateInstall    Operation = "activate_install"
	OperationAbortPrepared      Operation = "abort_prepared"
)

type ErrorCode string

const (
	ErrorBadRequest          ErrorCode = "ERR_BAD_REQUEST"
	ErrorProtocol            ErrorCode = "ERR_PROTOCOL"
	ErrorUnauthorized        ErrorCode = "ERR_UNAUTHORIZED"
	ErrorSocketPolicy        ErrorCode = "ERR_SOCKET_POLICY"
	ErrorFDRequired          ErrorCode = "ERR_FD_REQUIRED"
	ErrorFDForbidden         ErrorCode = "ERR_FD_FORBIDDEN"
	ErrorFDUnsafe            ErrorCode = "ERR_FD_UNSAFE"
	ErrorArtifactMismatch    ErrorCode = "ERR_ARTIFACT_MISMATCH"
	ErrorTransactionConflict ErrorCode = "ERR_TRANSACTION_CONFLICT"
	ErrorTransactionUnknown  ErrorCode = "ERR_TRANSACTION_UNKNOWN"
	ErrorCurrentUnavailable  ErrorCode = "ERR_CURRENT_UNAVAILABLE"
	ErrorPackagingFailed     ErrorCode = "ERR_PACKAGING_FAILED"
	ErrorRollbackFailed      ErrorCode = "ERR_ROLLBACK_FAILED"
	ErrorStateUncertain      ErrorCode = "ERR_STATE_UNCERTAIN"
	ErrorDeadline            ErrorCode = "ERR_DEADLINE"
	ErrorInternal            ErrorCode = "ERR_INTERNAL"
)

type Signature struct {
	KeyID string `json:"key_id"`
	Value string `json:"value"`
}

type Receipt struct {
	SchemaVersion          int       `json:"schema_version"`
	InstallerTransactionID string    `json:"installer_transaction_id"`
	ExecutionSequence      uint64    `json:"execution_sequence,omitempty"`
	ReleaseSequence        uint64    `json:"release_sequence"`
	ArtifactSHA256         string    `json:"artifact_sha256"`
	CurrentVersion         string    `json:"current_version"`
	PreviousVersion        string    `json:"previous_version,omitempty"`
	Status                 string    `json:"status"`
	IssuedAt               time.Time `json:"issued_at"`
	Signature              Signature `json:"signature"`
}

type PreparedAck struct {
	SchemaVersion        int    `json:"schema_version"`
	TransactionID        string `json:"transaction_id"`
	InstallPayloadSHA256 string `json:"install_payload_sha256"`
	ExecutionSequence    uint64 `json:"execution_sequence,omitempty"`
	ReleaseSequence      uint64 `json:"release_sequence"`
	ArtifactSHA256       string `json:"artifact_sha256"`
	ManifestSHA256       string `json:"manifest_sha256"`
	ExecutableSHA256     string `json:"executable_sha256"`
	SBOMSHA256           string `json:"sbom_sha256"`
	PreviousVersion      string `json:"previous_version"`
	TargetVersion        string `json:"target_version"`
}

type TransactionPhase string

const (
	TransactionUnknown    TransactionPhase = "unknown"
	TransactionPrepared   TransactionPhase = "prepared"
	TransactionAborted    TransactionPhase = "aborted"
	TransactionInstalling TransactionPhase = "installing"
	TransactionActive     TransactionPhase = "active"
	TransactionRolledBack TransactionPhase = "rolled_back"
)

type TransactionStatus struct {
	TransactionID string           `json:"transaction_id"`
	Phase         TransactionPhase `json:"phase"`
	PreparedAck   *PreparedAck     `json:"prepared_ack,omitempty"`
	Receipt       *Receipt         `json:"receipt,omitempty"`
}

type Request struct {
	ProtocolVersion        int          `json:"protocol_version"`
	Operation              Operation    `json:"operation"`
	TransactionID          string       `json:"transaction_id,omitempty"`
	ExecutionSequence      uint64       `json:"execution_sequence,omitempty"`
	ReleaseSequence        uint64       `json:"release_sequence,omitempty"`
	Action                 Action       `json:"action,omitempty"`
	CurrentVersion         string       `json:"current_version,omitempty"`
	TargetVersion          string       `json:"target_version,omitempty"`
	Platform               string       `json:"platform,omitempty"`
	Architecture           string       `json:"architecture,omitempty"`
	ArtifactSHA256         string       `json:"artifact_sha256,omitempty"`
	ArtifactSize           int64        `json:"artifact_size,omitempty"`
	AuditBasename          string       `json:"audit_basename,omitempty"`
	CurrentReceipt         *Receipt     `json:"current_receipt,omitempty"`
	InstallPayloadSHA256   string       `json:"install_payload_sha256,omitempty"`
	PreparedAck            *PreparedAck `json:"prepared_ack,omitempty"`
	ExpectedCurrentVersion string       `json:"expected_current_version,omitempty"`
	RollbackVersion        string       `json:"rollback_version,omitempty"`
	ActiveReceipt          *Receipt     `json:"active_receipt,omitempty"`
	PreviousReceipt        *Receipt     `json:"previous_receipt,omitempty"`
}

type Response struct {
	ProtocolVersion   int                `json:"protocol_version"`
	OK                bool               `json:"ok"`
	Receipt           *Receipt           `json:"receipt,omitempty"`
	PreparedAck       *PreparedAck       `json:"prepared_ack,omitempty"`
	TransactionStatus *TransactionStatus `json:"transaction_status,omitempty"`
	ErrorCode         ErrorCode          `json:"error_code,omitempty"`
}

var (
	ErrMalformed = errors.New("malformed helper protocol packet")
	idPattern    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
)

func MarshalRequest(request Request) ([]byte, error) {
	if err := ValidateRequest(request); err != nil {
		return nil, err
	}
	return marshalBounded(request)
}

func ParseRequest(packet []byte) (Request, error) {
	var request Request
	if err := parseCanonical(packet, &request); err != nil {
		return Request{}, err
	}
	if err := ValidateRequest(request); err != nil {
		return Request{}, err
	}
	canonical, err := json.Marshal(request)
	if err != nil || !bytes.Equal(packet, canonical) {
		return Request{}, ErrMalformed
	}
	return request, nil
}

func MarshalResponse(response Response) ([]byte, error) {
	if err := ValidateResponse(response); err != nil {
		return nil, err
	}
	return marshalBounded(response)
}

func ParseResponse(packet []byte) (Response, error) {
	var response Response
	if err := parseCanonical(packet, &response); err != nil {
		return Response{}, err
	}
	if err := ValidateResponse(response); err != nil {
		return Response{}, err
	}
	canonical, err := json.Marshal(response)
	if err != nil || !bytes.Equal(packet, canonical) {
		return Response{}, ErrMalformed
	}
	return response, nil
}

func Success(receipt Receipt) Response {
	if receipt.SchemaVersion == 2 {
		return SuccessForVersion(JournalV3Version, receipt)
	}
	return SuccessForVersion(Version, receipt)
}

func Failure(code ErrorCode) Response {
	return FailureForVersion(Version, code)
}

func SuccessForVersion(version int, receipt Receipt) Response {
	return Response{ProtocolVersion: version, OK: true, Receipt: &receipt}
}

func Prepared(version int, ack PreparedAck) Response {
	return Response{ProtocolVersion: version, OK: true, PreparedAck: &ack}
}

func Inspected(version int, status TransactionStatus) Response {
	return Response{ProtocolVersion: version, OK: true, TransactionStatus: &status}
}

func FailureForVersion(version int, code ErrorCode) Response {
	return Response{ProtocolVersion: version, ErrorCode: code}
}

func OperationTimeout(operation Operation) time.Duration {
	switch operation {
	case OperationCurrent, OperationInspectTransaction:
		return 5 * time.Second
	case OperationQuery, OperationInstall, OperationRollback, OperationPrepareInstall, OperationMarkInstalling, OperationActivateInstall, OperationAbortPrepared:
		return 300 * time.Second
	default:
		return 0
	}
}

func ValidateRequest(request Request) error {
	if OperationTimeout(request.Operation) == 0 {
		return ErrMalformed
	}
	switch request.ProtocolVersion {
	case Version:
		switch request.Operation {
		case OperationCurrent:
			if request != (Request{ProtocolVersion: Version, Operation: OperationCurrent}) {
				return ErrMalformed
			}
		case OperationQuery:
			expected := Request{ProtocolVersion: Version, Operation: OperationQuery, TransactionID: request.TransactionID}
			if request != expected || !validID(request.TransactionID) {
				return ErrMalformed
			}
		case OperationInstall:
			return validateInstallRequest(request, Version, OperationInstall)
		case OperationRollback:
			if request.ActiveReceipt == nil || request.PreviousReceipt == nil || !validID(request.TransactionID) ||
				request.ReleaseSequence == 0 || !validDigest(request.ArtifactSHA256) ||
				!validID(request.ExpectedCurrentVersion) || !validID(request.RollbackVersion) ||
				validateReceipt(*request.ActiveReceipt) != nil || validateReceipt(*request.PreviousReceipt) != nil {
				return ErrMalformed
			}
			expected := Request{
				ProtocolVersion: Version, Operation: OperationRollback, TransactionID: request.TransactionID,
				ReleaseSequence: request.ReleaseSequence, ArtifactSHA256: request.ArtifactSHA256,
				ExpectedCurrentVersion: request.ExpectedCurrentVersion, RollbackVersion: request.RollbackVersion,
				ActiveReceipt: request.ActiveReceipt, PreviousReceipt: request.PreviousReceipt,
			}
			if request != expected {
				return ErrMalformed
			}
		default:
			return ErrMalformed
		}
	case JournalVersion, JournalV3Version:
		version := request.ProtocolVersion
		switch request.Operation {
		case OperationPrepareInstall:
			return validateInstallRequest(request, version, OperationPrepareInstall)
		case OperationInspectTransaction:
			expected := Request{ProtocolVersion: version, Operation: OperationInspectTransaction, TransactionID: request.TransactionID}
			if request != expected || !validID(request.TransactionID) {
				return ErrMalformed
			}
		case OperationActivateInstall, OperationAbortPrepared:
			if request.PreparedAck == nil || !validID(request.TransactionID) || !validDigest(request.InstallPayloadSHA256) ||
				validatePreparedAck(*request.PreparedAck, version) != nil || request.PreparedAck.TransactionID != request.TransactionID ||
				request.PreparedAck.InstallPayloadSHA256 != request.InstallPayloadSHA256 {
				return ErrMalformed
			}
			expected := Request{
				ProtocolVersion: version, Operation: request.Operation, TransactionID: request.TransactionID,
				InstallPayloadSHA256: request.InstallPayloadSHA256, PreparedAck: request.PreparedAck,
			}
			if request != expected {
				return ErrMalformed
			}
		default:
			return ErrMalformed
		}
	case JournalV4Version:
		if request.Operation != OperationMarkInstalling {
			return ErrMalformed
		}
		return validateMarkInstallingRequest(request, JournalV4Version)
	default:
		return ErrMalformed
	}
	return nil
}

func validateMarkInstallingRequest(request Request, version int) error {
	if request.PreparedAck == nil || !validID(request.TransactionID) || !validDigest(request.InstallPayloadSHA256) ||
		validatePreparedAck(*request.PreparedAck, version) != nil || request.PreparedAck.TransactionID != request.TransactionID ||
		request.PreparedAck.InstallPayloadSHA256 != request.InstallPayloadSHA256 {
		return ErrMalformed
	}
	expected := Request{
		ProtocolVersion: version, Operation: OperationMarkInstalling, TransactionID: request.TransactionID,
		InstallPayloadSHA256: request.InstallPayloadSHA256, PreparedAck: request.PreparedAck,
	}
	if request != expected {
		return ErrMalformed
	}
	return nil
}

func validateInstallRequest(request Request, version int, operation Operation) error {
	if request.CurrentReceipt == nil || !validID(request.TransactionID) || request.ReleaseSequence == 0 ||
		!validID(request.CurrentVersion) || !validID(request.TargetVersion) || request.Platform != "linux" ||
		(request.Architecture != "amd64" && request.Architecture != "arm64") || !validDigest(request.ArtifactSHA256) ||
		request.ArtifactSize <= 0 || request.ArtifactSize > MaxArtifactBytes || !validID(request.AuditBasename) ||
		validateReceipt(*request.CurrentReceipt) != nil {
		return ErrMalformed
	}
	if version == JournalV3Version {
		if request.ExecutionSequence == 0 || !validAction(request.Action) {
			return ErrMalformed
		}
	} else if request.ExecutionSequence != 0 || request.Action != "" {
		return ErrMalformed
	}
	expected := Request{
		ProtocolVersion: version, Operation: operation, TransactionID: request.TransactionID,
		ExecutionSequence: request.ExecutionSequence,
		ReleaseSequence:   request.ReleaseSequence, CurrentVersion: request.CurrentVersion,
		Action:        request.Action,
		TargetVersion: request.TargetVersion, Platform: request.Platform, Architecture: request.Architecture,
		ArtifactSHA256: request.ArtifactSHA256, ArtifactSize: request.ArtifactSize,
		AuditBasename: request.AuditBasename, CurrentReceipt: request.CurrentReceipt,
	}
	if request != expected {
		return ErrMalformed
	}
	return nil
}

func ValidateResponse(response Response) error {
	if response.ProtocolVersion != Version && response.ProtocolVersion != JournalVersion &&
		response.ProtocolVersion != JournalV3Version && response.ProtocolVersion != JournalV4Version {
		return ErrMalformed
	}
	payloads := 0
	if response.Receipt != nil {
		payloads++
	}
	if response.PreparedAck != nil {
		payloads++
	}
	if response.TransactionStatus != nil {
		payloads++
	}
	if response.OK {
		if payloads != 1 || response.ErrorCode != "" {
			return ErrMalformed
		}
		if response.ProtocolVersion == Version {
			if response.Receipt == nil || validateReceiptForVersion(*response.Receipt, Version) != nil {
				return ErrMalformed
			}
			return nil
		}
		switch {
		case response.Receipt != nil:
			return validateReceiptForVersion(*response.Receipt, response.ProtocolVersion)
		case response.PreparedAck != nil:
			return validatePreparedAck(*response.PreparedAck, response.ProtocolVersion)
		default:
			return validateTransactionStatus(*response.TransactionStatus, response.ProtocolVersion)
		}
	}
	if payloads != 0 || !validErrorCode(response.ErrorCode) {
		return ErrMalformed
	}
	return nil
}

func validatePreparedAck(ack PreparedAck, version int) error {
	wantSchema := 1
	if version == JournalV3Version {
		wantSchema = 2
	}
	if version == JournalV4Version {
		if ack.SchemaVersion == 1 && ack.ExecutionSequence != 0 || ack.SchemaVersion == 2 && ack.ExecutionSequence == 0 {
			return ErrMalformed
		}
		return validatePreparedAck(ack, preparedAckVersionForSchema(ack.SchemaVersion))
	}
	if ack.SchemaVersion != wantSchema || !validID(ack.TransactionID) || !validDigest(ack.InstallPayloadSHA256) ||
		ack.ReleaseSequence == 0 || !validDigest(ack.ArtifactSHA256) || !validDigest(ack.ManifestSHA256) ||
		!validDigest(ack.ExecutableSHA256) || !validDigest(ack.SBOMSHA256) || !validID(ack.PreviousVersion) ||
		!validID(ack.TargetVersion) || ack.PreviousVersion == ack.TargetVersion {
		return ErrMalformed
	}
	if version == JournalV3Version && ack.ExecutionSequence == 0 || version != JournalV3Version && ack.ExecutionSequence != 0 {
		return ErrMalformed
	}
	return nil
}

func preparedAckVersionForSchema(schemaVersion int) int {
	if schemaVersion == 2 {
		return JournalV3Version
	}
	return JournalVersion
}

func validateTransactionStatus(status TransactionStatus, version int) error {
	if !validID(status.TransactionID) {
		return ErrMalformed
	}
	if status.Phase == TransactionUnknown {
		if status.PreparedAck != nil || status.Receipt != nil {
			return ErrMalformed
		}
		return nil
	}
	if status.PreparedAck == nil || validatePreparedAck(*status.PreparedAck, version) != nil || status.PreparedAck.TransactionID != status.TransactionID {
		return ErrMalformed
	}
	switch status.Phase {
	case TransactionPrepared, TransactionAborted, TransactionInstalling:
		if status.Receipt != nil {
			return ErrMalformed
		}
	case TransactionActive, TransactionRolledBack:
		if status.Receipt == nil || validateReceiptForVersion(*status.Receipt, version) != nil || !receiptMatchesStatus(*status.Receipt, *status.PreparedAck, status.Phase) {
			return ErrMalformed
		}
	default:
		return ErrMalformed
	}
	return nil
}

func receiptMatchesStatus(receipt Receipt, ack PreparedAck, phase TransactionPhase) bool {
	if receipt.InstallerTransactionID != ack.TransactionID || receipt.ExecutionSequence != ack.ExecutionSequence ||
		receipt.ReleaseSequence != ack.ReleaseSequence || receipt.ArtifactSHA256 != ack.ArtifactSHA256 {
		return false
	}
	if phase == TransactionActive {
		return receipt.Status == "active" && receipt.CurrentVersion == ack.TargetVersion && receipt.PreviousVersion == ack.PreviousVersion
	}
	return receipt.Status == "rolled_back" && receipt.CurrentVersion == ack.PreviousVersion && receipt.PreviousVersion == ack.TargetVersion
}

func parseCanonical(packet []byte, destination any) error {
	if len(packet) == 0 || len(packet) > MaxPacketBytes || !utf8.Valid(packet) || bytes.HasPrefix(packet, []byte{0xef, 0xbb, 0xbf}) {
		return ErrMalformed
	}
	decoder := json.NewDecoder(bytes.NewReader(packet))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return ErrMalformed
	}
	if decoder.More() {
		return ErrMalformed
	}
	return nil
}

func marshalBounded(value any) ([]byte, error) {
	packet, err := json.Marshal(value)
	if err != nil || len(packet) == 0 || len(packet) > MaxPacketBytes {
		return nil, ErrMalformed
	}
	return packet, nil
}

func validateReceipt(receipt Receipt) error {
	if (receipt.SchemaVersion != 1 && receipt.SchemaVersion != 2) || !validID(receipt.InstallerTransactionID) || receipt.ReleaseSequence == 0 ||
		!validDigest(receipt.ArtifactSHA256) || !validID(receipt.CurrentVersion) ||
		(receipt.PreviousVersion != "" && !validID(receipt.PreviousVersion)) ||
		(receipt.Status != "active" && receipt.Status != "rolled_back") || receipt.IssuedAt.IsZero() ||
		receipt.IssuedAt.Location() != time.UTC || !validID(receipt.Signature.KeyID) || !validSignature(receipt.Signature.Value) {
		return ErrMalformed
	}
	if receipt.SchemaVersion == 1 && receipt.ExecutionSequence != 0 || receipt.SchemaVersion == 2 && receipt.ExecutionSequence == 0 {
		return ErrMalformed
	}
	return nil
}

func validateReceiptForVersion(receipt Receipt, version int) error {
	if version == Version {
		if receipt.SchemaVersion != 1 && receipt.SchemaVersion != 2 {
			return ErrMalformed
		}
		return validateReceipt(receipt)
	}
	if version == JournalV4Version {
		return validateReceipt(receipt)
	}
	wantSchema := 1
	if version == JournalV3Version {
		wantSchema = 2
	}
	if receipt.SchemaVersion != wantSchema {
		return ErrMalformed
	}
	return validateReceipt(receipt)
}

func validAction(action Action) bool {
	return action == ActionUpgrade || action == ActionRollback
}

func validID(value string) bool {
	return idPattern.MatchString(value)
}

func validDigest(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == 32 && fmt.Sprintf("%x", decoded) == value
}

func validSignature(value string) bool {
	decoded, err := base64.RawStdEncoding.DecodeString(value)
	return err == nil && len(decoded) == 64 && base64.RawStdEncoding.EncodeToString(decoded) == value
}

func validErrorCode(code ErrorCode) bool {
	switch code {
	case ErrorBadRequest, ErrorProtocol, ErrorUnauthorized, ErrorSocketPolicy, ErrorFDRequired,
		ErrorFDForbidden, ErrorFDUnsafe, ErrorArtifactMismatch, ErrorTransactionConflict,
		ErrorTransactionUnknown, ErrorCurrentUnavailable, ErrorPackagingFailed, ErrorRollbackFailed,
		ErrorStateUncertain, ErrorDeadline, ErrorInternal:
		return true
	default:
		return false
	}
}
