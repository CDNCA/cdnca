package controlbackup

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

const backupRunSignatureDomain = "cdnca.control-backup-run/v1\x00"
const backupRunFactLimit = 8 << 10

func SignBackupRunStart(start BackupRunStart, keyID string, key ed25519.PrivateKey) (SignedBackupRunFact, error) {
	if !validBackupRunStart(start) {
		return SignedBackupRunFact{}, ErrBackupRunInvalid
	}
	return signBackupRunFact(start, keyID, key)
}

func SignBackupRunTerminal(terminal BackupRunTerminal, keyID string, key ed25519.PrivateKey) (SignedBackupRunFact, error) {
	if !validBackupRunTerminal(terminal) {
		return SignedBackupRunFact{}, ErrBackupRunInvalid
	}
	return signBackupRunFact(terminal, keyID, key)
}

func signBackupRunFact(value any, keyID string, key ed25519.PrivateKey) (SignedBackupRunFact, error) {
	if !identifierPattern.MatchString(keyID) || len(key) != ed25519.PrivateKeySize {
		return SignedBackupRunFact{}, ErrBackupRunInvalid
	}
	payload, err := json.Marshal(value)
	if err != nil {
		return SignedBackupRunFact{}, ErrBackupRunInvalid
	}
	digest := sha256.Sum256(payload)
	return SignedBackupRunFact{Schema: SignedBackupRunSchema, Payload: payload,
		PayloadSHA256: hex.EncodeToString(digest[:]), SigningKeyID: keyID,
		Signature: base64.RawStdEncoding.EncodeToString(ed25519.Sign(key, append([]byte(backupRunSignatureDomain), payload...)))}, nil
}

// DecodeBackupRunFact requires the canonical envelope produced by the writer,
// rejecting duplicate keys, unknown fields and trailing data before import.
func DecodeBackupRunFact(encoded []byte) (SignedBackupRunFact, error) {
	var signed SignedBackupRunFact
	if len(encoded) > backupRunFactLimit || DecodeStrictJSON(encoded, &signed) != nil {
		return signed, ErrBackupRunIntegrity
	}
	canonical, err := json.Marshal(signed)
	if err != nil || !bytes.Equal(bytes.TrimSpace(encoded), canonical) {
		return SignedBackupRunFact{}, ErrBackupRunIntegrity
	}
	return signed, nil
}

func VerifyBackupRun(start SignedBackupRunFact, terminal *SignedBackupRunFact,
	keys map[string]ed25519.PublicKey, expected BackupRunExpectation,
) (VerifiedBackupRun, error) {
	if !validBackupRunExpectation(expected) {
		return VerifiedBackupRun{}, ErrBackupRunInvalid
	}
	var decodedStart BackupRunStart
	if verifyBackupRunFact(start, keys, &decodedStart) != nil || !validBackupRunStart(decodedStart) {
		return VerifiedBackupRun{}, ErrBackupRunIntegrity
	}
	if decodedStart.InstallationID != expected.InstallationID || decodedStart.SourceClusterID != expected.SourceClusterID ||
		(expected.BackupID != "" && decodedStart.BackupID != expected.BackupID) ||
		(expected.PlanSHA256 != "" && decodedStart.PlanSHA256 != expected.PlanSHA256) {
		return VerifiedBackupRun{}, ErrBackupRunConflict
	}
	verified := VerifiedBackupRun{Start: decodedStart, SignedStart: start}
	if terminal == nil {
		return verified, nil
	}
	var decodedTerminal BackupRunTerminal
	if verifyBackupRunFact(*terminal, keys, &decodedTerminal) != nil || !validBackupRunTerminal(decodedTerminal) ||
		decodedTerminal.BackupID != decodedStart.BackupID || decodedTerminal.StartSHA256 != start.PayloadSHA256 ||
		decodedTerminal.CompletedAt.Before(decodedStart.StartedAt) {
		return VerifiedBackupRun{}, ErrBackupRunIntegrity
	}
	verified.Terminal, verified.SignedTerminal = &decodedTerminal, terminal
	return verified, nil
}

func verifyBackupRunFact(signed SignedBackupRunFact, keys map[string]ed25519.PublicKey, destination any) error {
	key := keys[signed.SigningKeyID]
	if signed.Schema != SignedBackupRunSchema || !identifierPattern.MatchString(signed.SigningKeyID) ||
		len(key) != ed25519.PublicKeySize || len(signed.Payload) == 0 || len(signed.Payload) > backupRunFactLimit ||
		!validSHA256(signed.PayloadSHA256) {
		return ErrBackupRunIntegrity
	}
	digest := sha256.Sum256(signed.Payload)
	signature, err := base64.RawStdEncoding.DecodeString(signed.Signature)
	if err != nil || hex.EncodeToString(digest[:]) != signed.PayloadSHA256 ||
		!ed25519.Verify(key, append([]byte(backupRunSignatureDomain), signed.Payload...), signature) ||
		DecodeStrictJSON(signed.Payload, destination) != nil {
		return ErrBackupRunIntegrity
	}
	canonical, err := json.Marshal(destination)
	if err != nil || !bytes.Equal(canonical, signed.Payload) {
		return ErrBackupRunIntegrity
	}
	return nil
}

func validBackupRunExpectation(expected BackupRunExpectation) bool {
	installation, err := uuid.Parse(expected.InstallationID)
	return err == nil && installation != uuid.Nil && installation.String() == expected.InstallationID &&
		identifierPattern.MatchString(expected.SourceClusterID) &&
		(expected.BackupID == "" || identifierPattern.MatchString(expected.BackupID)) &&
		(expected.PlanSHA256 == "" || validSHA256(expected.PlanSHA256))
}

func validBackupRunTime(value time.Time) bool {
	_, offset := value.Zone()
	return !value.IsZero() && value.Year() >= 1970 && value.Year() <= 9999 && offset == 0
}

func validBackupRunStart(start BackupRunStart) bool {
	return start.Schema == BackupRunStartSchema && identifierPattern.MatchString(start.BackupID) &&
		validSHA256(start.PlanSHA256) && validBackupRunTime(start.StartedAt) &&
		validBackupRunExpectation(BackupRunExpectation{InstallationID: start.InstallationID, SourceClusterID: start.SourceClusterID})
}

func validBackupRunTerminal(terminal BackupRunTerminal) bool {
	if terminal.Schema != BackupRunTerminalSchema || !identifierPattern.MatchString(terminal.BackupID) ||
		!validSHA256(terminal.StartSHA256) || !validBackupRunTime(terminal.CompletedAt) {
		return false
	}
	if terminal.State == BackupRunSucceeded {
		return terminal.ResultCode == "backup_succeeded" && validSHA256(terminal.ManifestSHA256) &&
			terminal.RecoveryPointAt != nil && validBackupRunTime(*terminal.RecoveryPointAt) &&
			!terminal.RecoveryPointAt.After(terminal.CompletedAt) &&
			terminal.ObservedRPOSeconds != nil && *terminal.ObservedRPOSeconds >= 0
	}
	if terminal.State != BackupRunFailed || terminal.ManifestSHA256 != "" ||
		terminal.RecoveryPointAt != nil || terminal.ObservedRPOSeconds != nil {
		return false
	}
	switch terminal.ResultCode {
	case "backup_invalid_config", "backup_capture_failed", "backup_invalid_result", "backup_manifest_failed":
		return true
	default:
		return false
	}
}
