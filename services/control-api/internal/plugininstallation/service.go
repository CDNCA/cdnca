package plugininstallation

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"slices"
	"time"

	"github.com/google/uuid"
	"golang.org/x/mod/semver"
)

type Service struct {
	Store    Store
	Verifier CandidateVerifier
	Now      func() time.Time
}

func (service Service) Apply(ctx context.Context, command Command) (MutationResult, error) {
	if ctx == nil || service.Store == nil || service.Now == nil || !validCommand(command) {
		return MutationResult{}, ErrInvalidInput
	}
	now := service.Now().UTC().Truncate(time.Second)
	if now.IsZero() {
		return MutationResult{}, ErrInvalidInput
	}
	digest, err := commandDigest(command)
	if err != nil {
		return MutationResult{}, err
	}
	var result MutationResult
	err = service.Store.Transact(ctx, command.TenantID, command.AuthorizationID, func(tx Transaction) error {
		replay, found, err := tx.Replay(command.IdempotencyKey)
		if err != nil {
			return err
		}
		if found {
			if replay.RequestDigest != digest || replay.Action != command.Action || replay.RequestID != command.RequestID {
				return ErrIdempotencyConflict
			}
			result = MutationResult{Installation: cloneInstallation(replay.Snapshot), Receipt: cloneReceipt(replay)}
			return nil
		}

		current, exists, err := tx.Current()
		if err != nil {
			return err
		}
		next, receipt, err := service.transition(ctx, tx, current, exists, command, digest, now)
		if err != nil {
			return err
		}
		if err := tx.Save(next, receipt); err != nil {
			return err
		}
		result = MutationResult{Installation: cloneInstallation(next), Receipt: cloneReceipt(receipt)}
		return nil
	})
	if err != nil {
		return MutationResult{}, err
	}
	return result, nil
}

func (service Service) transition(ctx context.Context, tx Transaction, current Installation, exists bool, command Command,
	digest [sha256.Size]byte, now time.Time) (Installation, Receipt, error) {
	if command.Action == ActionConfirm {
		if exists {
			return Installation{}, Receipt{}, ErrTransitionInvalid
		}
		// The local target binding is the first confirmed scope: another tenant cannot confirm the same
		// license authorization into a second head (report section 4, point 4).
		if bound, err := tx.BoundElsewhere(); err != nil {
			return Installation{}, Receipt{}, err
		} else if bound {
			return Installation{}, Receipt{}, ErrFactDenied
		}
		if err := requireConsent(command.Candidate, nil, command); err != nil {
			return Installation{}, Receipt{}, err
		}
		if service.Verifier == nil {
			return Installation{}, Receipt{}, ErrFactRequired
		}
		if err := service.Verifier.VerifyCandidate(ctx, command.Candidate, command.Facts); err != nil {
			return Installation{}, Receipt{}, err
		}
		next := installationFromCandidate(command.Candidate, now)
		next.Revision = 1
		next.IdentityGeneration = 1
		next.Status = StatusEnabled
		next.LKGVerificationID = next.VerificationID
		next.LKGVersion = next.Version
		return next, newReceipt(command, digest, Installation{}, next, ReceiptInstalled, now), nil
	}
	if !exists {
		return Installation{}, Receipt{}, ErrNotFound
	}
	if current.Schema != Schema || current.TenantID != command.TenantID ||
		current.ResourceScope != command.Candidate.ResourceScope || current.EntrypointType != command.Candidate.EntrypointType ||
		current.InstallationID != command.InstallationID || current.AuthorizationID != command.AuthorizationID ||
		current.PluginID != command.Candidate.PluginID {
		return Installation{}, Receipt{}, ErrFactDenied
	}
	if command.ExpectedRevision != current.Revision {
		return Installation{}, Receipt{}, ErrRevisionConflict
	}
	if current.Revision == ^uint64(0) || current.IdentityGeneration == ^uint64(0) {
		return Installation{}, Receipt{}, ErrTransitionInvalid
	}
	next := cloneInstallation(current)
	next.Revision++
	next.UpdatedAt = now
	switch command.Action {
	case ActionUpgrade:
		if current.Status != StatusEnabled && current.Status != StatusDisabled {
			return Installation{}, Receipt{}, ErrTransitionInvalid
		}
		if semver.Compare("v"+command.Candidate.Version, "v"+current.Version) <= 0 {
			return Installation{}, Receipt{}, ErrTransitionInvalid
		}
		if err := requireConsent(command.Candidate, current.ApprovedScopes, command); err != nil {
			return Installation{}, Receipt{}, err
		}
		if service.Verifier == nil {
			return Installation{}, Receipt{}, ErrFactRequired
		}
		if err := service.Verifier.VerifyCandidate(ctx, command.Candidate, command.Facts); err != nil {
			return Installation{}, Receipt{}, err
		}
		if !command.Applied {
			if !validFailureCode(command.StableReasonCode) {
				return Installation{}, Receipt{}, ErrInvalidInput
			}
			next.StableReasonCode = command.StableReasonCode
			receipt := newReceipt(command, digest, current, next, ReceiptUpgradeFailedLKGPreserved, now)
			receipt.AttemptedVerificationID = command.Candidate.VerificationID
			receipt.AttemptedVersion = command.Candidate.Version
			receipt.StableReasonCode = command.StableReasonCode
			receipt.Snapshot = cloneInstallation(next)
			return next, receipt, nil
		}
		next = installationFromCandidate(command.Candidate, now)
		next.Status = current.Status
		next.Revision = current.Revision + 1
		next.IdentityGeneration = current.IdentityGeneration + 1
		next.LKGVerificationID = next.VerificationID
		next.LKGVersion = next.Version
		receipt := newReceipt(command, digest, current, next, ReceiptUpgradeApplied, now)
		receipt.AttemptedVerificationID = command.Candidate.VerificationID
		receipt.AttemptedVersion = command.Candidate.Version
		return next, receipt, nil
	case ActionDisable:
		if current.Status != StatusEnabled || !validReason(command.Reason) || !sameCurrentCandidate(current, command.Candidate) {
			return Installation{}, Receipt{}, ErrTransitionInvalid
		}
		next.Status = StatusDisabled
		next.IdentityGeneration++
		return next, newReceipt(command, digest, current, next, ReceiptDisabled, now), nil
	case ActionResume:
		// Symmetric to disable: same verified candidate, LKG and scopes; only the runtime identity rotates.
		if current.Status != StatusDisabled || !sameCurrentCandidate(current, command.Candidate) {
			return Installation{}, Receipt{}, ErrTransitionInvalid
		}
		next.Status = StatusEnabled
		next.IdentityGeneration++
		return next, newReceipt(command, digest, current, next, ReceiptResumed, now), nil
	case ActionUninstall:
		if current.Status != StatusEnabled && current.Status != StatusDisabled || !validReason(command.Reason) ||
			!sameCurrentCandidate(current, command.Candidate) {
			return Installation{}, Receipt{}, ErrTransitionInvalid
		}
		next.Status = StatusUninstalled
		next.IdentityGeneration++
		return next, newReceipt(command, digest, current, next, ReceiptUninstalled, now), nil
	default:
		return Installation{}, Receipt{}, ErrTransitionInvalid
	}
}

func validCommand(command Command) bool {
	if command.TenantID == uuid.Nil || command.InstallationID == uuid.Nil || command.AuthorizationID == uuid.Nil ||
		command.ExpectedRevision == 0 || !idempotencyPattern.MatchString(command.IdempotencyKey) ||
		!validRequestID(command.RequestID) || !validCandidate(command.Candidate) ||
		command.Candidate.TenantID != command.TenantID || command.Candidate.InstallationID != command.InstallationID ||
		command.Candidate.AuthorizationID != command.AuthorizationID {
		return false
	}
	switch command.Action {
	case ActionConfirm, ActionUpgrade:
		return command.Reason == "" && (command.Applied || command.Action == ActionUpgrade && validFailureCode(command.StableReasonCode))
	case ActionDisable, ActionUninstall:
		return len(command.Facts) == 0 && validReason(command.Reason) && command.StableReasonCode == ""
	case ActionResume:
		return len(command.Facts) == 0 && command.Reason == "" && command.StableReasonCode == "" &&
			!command.SensitivePermissionsConfirmed && !command.NewPermissionsConfirmed
	default:
		return false
	}
}

func requireConsent(candidate Candidate, historical []string, command Command) error {
	newScopes := make([]string, 0, len(candidate.ApprovedScopes))
	for _, scope := range candidate.ApprovedScopes {
		if _, found := slices.BinarySearch(historical, scope); !found {
			newScopes = append(newScopes, scope)
		}
	}
	if len(newScopes) > 0 && !command.NewPermissionsConfirmed {
		return ErrConsentRequired
	}
	for _, scope := range candidate.ApprovedScopes {
		if _, sensitive := slices.BinarySearch(candidate.SensitiveScopes, scope); sensitive && !command.SensitivePermissionsConfirmed {
			return ErrConsentRequired
		}
	}
	return nil
}

func sameCurrentCandidate(current Installation, candidate Candidate) bool {
	return current.TenantID == candidate.TenantID && current.ResourceScope == candidate.ResourceScope &&
		current.EntrypointType == candidate.EntrypointType &&
		current.InstallationID == candidate.InstallationID &&
		current.AuthorizationID == candidate.AuthorizationID && current.PluginID == candidate.PluginID &&
		current.Version == candidate.Version && current.VerificationID == candidate.VerificationID &&
		current.ManifestSHA256 == candidate.ManifestSHA256 &&
		current.ConfigurationSchemaSHA256 == candidate.ConfigurationSchemaSHA256 &&
		slices.Equal(current.ManifestScopes, candidate.ManifestScopes) && slices.Equal(current.ApprovedScopes, candidate.ApprovedScopes)
}

func commandDigest(command Command) ([sha256.Size]byte, error) {
	type factDigest struct {
		Scope     string `json:"scope"`
		RequestID string `json:"request_id"`
		Identity  string `json:"identity_sha256"`
		Decision  string `json:"decision_sha256"`
	}
	facts := make([]factDigest, len(command.Facts))
	for index, fact := range command.Facts {
		identity, decision := sha256.Sum256(fact.IdentityJSON), sha256.Sum256(fact.DecisionJSON)
		facts[index] = factDigest{Scope: fact.Scope, RequestID: fact.RequestID,
			Identity: string(identity[:]), Decision: string(decision[:])}
	}
	encoded, err := json.Marshal(struct {
		TenantID           uuid.UUID    `json:"tenant_id"`
		InstallationID     uuid.UUID    `json:"installation_id"`
		AuthorizationID    uuid.UUID    `json:"authorization_id"`
		Action             string       `json:"action"`
		ExpectedRevision   uint64       `json:"expected_revision"`
		RequestID          string       `json:"request_id"`
		Candidate          Candidate    `json:"candidate"`
		Facts              []factDigest `json:"facts"`
		SensitiveConfirmed bool         `json:"sensitive_confirmed"`
		NewConfirmed       bool         `json:"new_confirmed"`
		Applied            bool         `json:"applied"`
		StableReasonCode   string       `json:"stable_reason_code"`
		Reason             string       `json:"reason"`
	}{command.TenantID, command.InstallationID, command.AuthorizationID, command.Action,
		command.ExpectedRevision, command.RequestID, command.Candidate, facts,
		command.SensitivePermissionsConfirmed, command.NewPermissionsConfirmed, command.Applied,
		command.StableReasonCode, command.Reason})
	if err != nil {
		return [sha256.Size]byte{}, ErrInvalidInput
	}
	return sha256.Sum256(encoded), nil
}

func installationFromCandidate(candidate Candidate, now time.Time) Installation {
	return Installation{Schema: Schema, TenantID: candidate.TenantID, InstallationID: candidate.InstallationID,
		AuthorizationID: candidate.AuthorizationID, VerificationID: candidate.VerificationID,
		PluginID: candidate.PluginID, Version: candidate.Version, ResourceScope: candidate.ResourceScope,
		EntrypointType: candidate.EntrypointType,
		ManifestSHA256: candidate.ManifestSHA256, ConfigurationSchemaSHA256: candidate.ConfigurationSchemaSHA256,
		ManifestScopes: append([]string{}, candidate.ManifestScopes...), ApprovedScopes: append([]string{}, candidate.ApprovedScopes...),
		SensitiveScopes: append([]string{}, candidate.SensitiveScopes...), UpdatedAt: now}
}

func newReceipt(command Command, digest [sha256.Size]byte, current, next Installation,
	result string, now time.Time) Receipt {
	return Receipt{ID: uuid.New(), TenantID: command.TenantID, AuthorizationID: command.AuthorizationID,
		Action: command.Action, IdempotencyKey: command.IdempotencyKey, RequestID: command.RequestID,
		RequestDigest: digest, FromRevision: current.Revision, ToRevision: next.Revision, Result: result,
		Reason: command.Reason, StableReasonCode: command.StableReasonCode, Snapshot: cloneInstallation(next), OccurredAt: now}
}

func cloneInstallation(value Installation) Installation {
	value.ManifestScopes = append([]string{}, value.ManifestScopes...)
	value.ApprovedScopes = append([]string{}, value.ApprovedScopes...)
	value.SensitiveScopes = append([]string{}, value.SensitiveScopes...)
	return value
}

func cloneReceipt(value Receipt) Receipt {
	value.Snapshot = cloneInstallation(value.Snapshot)
	return value
}

func validFailureCode(value string) bool {
	switch value {
	case "apply_failed", "configuration_rejected", "health_check_failed", "service_identity_failed":
		return true
	default:
		return false
	}
}
