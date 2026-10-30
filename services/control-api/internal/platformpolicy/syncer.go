package platformpolicy

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/entitlementguard"
	"github.com/google/uuid"
)

const (
	defaultSyncInterval = time.Minute
	defaultBackoffMin   = time.Second
	defaultBackoffMax   = 5 * time.Minute
)

type PolicyClient interface {
	Resolve(context.Context, ResolveInput, ed25519.PrivateKey, time.Time) (ResolveResult, error)
	Acknowledge(context.Context, AckInput, ed25519.PrivateKey, time.Time) (AckResult, error)
}

type LocalStore interface {
	Load(context.Context) (LocalState, error)
	PendingCandidates(context.Context, time.Time, int) ([]StoredTarget, error)
	RecordFetched(context.Context, []byte, SignedPlatformPolicy, time.Time) (bool, error)
	RecordRejected(context.Context, string, string, time.Time) error
	Apply(context.Context, VerifiedPolicy, time.Time) error
	SavePosition(context.Context, SyncPosition, time.Time) error
	PendingAcks(context.Context, time.Time, int) ([]PendingAck, error)
	CompleteAck(context.Context, uuid.UUID, time.Time) error
	DeferAck(context.Context, uuid.UUID, string, time.Time, time.Time) error
}

type KeysetRefresher interface {
	Refresh(context.Context) error
}

// SignerRevocationChecker reports whether an authentic policy signer is
// revoked by the last verified signer-revocation checkpoint.
type SignerRevocationChecker interface {
	CheckSignerRevocation(entitlementguard.SignerArtifactClass, string) error
}

type SyncerConfig struct {
	Client PolicyClient
	Store  LocalStore
	Trust  DetachedVerifier
	// SignerRevocation, when set, rejects new candidates signed by a revoked
	// key. The already-applied LKG policy is restored unchanged so that a
	// revocation never empties the effective policy; a successor signed by a
	// trusted key replaces it.
	SignerRevocation SignerRevocationChecker
	Keysets          KeysetRefresher
	State            *State
	InstallationID   uuid.UUID
	PrivateKey       ed25519.PrivateKey
	ControlVersion   string
	ProtocolVersion  int
	Now              func() time.Time
	Wait             func(context.Context, time.Duration) error
	Logger           *slog.Logger
	SyncInterval     time.Duration
	BackoffMin       time.Duration
	BackoffMax       time.Duration
}

type Syncer struct {
	client          PolicyClient
	store           LocalStore
	trust           DetachedVerifier
	revocation      SignerRevocationChecker
	keysets         KeysetRefresher
	state           *State
	installationID  uuid.UUID
	privateKey      ed25519.PrivateKey
	controlVersion  string
	protocolVersion int
	now             func() time.Time
	wait            func(context.Context, time.Duration) error
	logger          *slog.Logger
	syncInterval    time.Duration
	backoffMin      time.Duration
	backoffMax      time.Duration
}

func NewSyncer(ctx context.Context, config SyncerConfig) (*Syncer, error) {
	if ctx == nil || config.Client == nil || config.Store == nil || config.Trust == nil || config.State == nil ||
		config.InstallationID == uuid.Nil || len(config.PrivateKey) != ed25519.PrivateKeySize ||
		!validSemver(config.ControlVersion) || config.ProtocolVersion < 1 {
		return nil, ErrInvalidClient
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	if config.Wait == nil {
		config.Wait = waitContext
	}
	if config.Logger == nil {
		config.Logger = slog.Default()
	}
	if config.SyncInterval == 0 {
		config.SyncInterval = defaultSyncInterval
	}
	if config.BackoffMin == 0 {
		config.BackoffMin = defaultBackoffMin
	}
	if config.BackoffMax == 0 {
		config.BackoffMax = defaultBackoffMax
	}
	if config.SyncInterval <= 0 || config.BackoffMin <= 0 || config.BackoffMax < config.BackoffMin {
		return nil, ErrInvalidClient
	}
	syncer := &Syncer{
		client: config.Client, store: config.Store, trust: config.Trust, revocation: config.SignerRevocation,
		keysets: config.Keysets,
		state:   config.State, installationID: config.InstallationID,
		privateKey: append(ed25519.PrivateKey(nil), config.PrivateKey...), controlVersion: config.ControlVersion,
		protocolVersion: config.ProtocolVersion, now: config.Now, wait: config.Wait, logger: config.Logger,
		syncInterval: config.SyncInterval, backoffMin: config.BackoffMin, backoffMax: config.BackoffMax,
	}
	if err := syncer.restore(ctx); err != nil {
		return nil, err
	}
	return syncer, nil
}

func (syncer *Syncer) Run(ctx context.Context) error {
	delay := time.Duration(0)
	failureDelay := time.Duration(0)
	for {
		if delay > 0 {
			if err := syncer.wait(ctx, delay); err != nil {
				return err
			}
		}
		err := syncer.SyncOnce(ctx)
		if err == nil {
			delay = syncer.syncInterval
			failureDelay = 0
			continue
		}
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) && ctx.Err() != nil {
			return ctx.Err()
		}
		syncer.logger.Warn("platform policy synchronization deferred", "error", err)
		if failureDelay < syncer.backoffMin || failureDelay > syncer.backoffMax {
			failureDelay = syncer.backoffMin
		} else if failureDelay < syncer.backoffMax/2 {
			failureDelay *= 2
		} else {
			failureDelay = syncer.backoffMax
		}
		delay = failureDelay
	}
}

func (syncer *Syncer) SyncOnce(ctx context.Context) error {
	keysetRefreshFailed := false
	if syncer.keysets != nil {
		if err := syncer.keysets.Refresh(ctx); err != nil {
			keysetRefreshFailed = true
			syncer.logger.Warn("platform policy signing keyset refresh deferred; retaining last-known-good trust", "error", err)
		}
	}
	if err := syncer.processPendingCandidates(ctx, keysetRefreshFailed); err != nil {
		return err
	}
	if err := syncer.restore(ctx); err != nil {
		return err
	}
	local, err := syncer.store.Load(ctx)
	if err != nil {
		return err
	}
	input := syncer.resolveInput(local)
	resolved, err := syncer.client.Resolve(ctx, input, syncer.privateKey, syncer.now().UTC())
	var serviceError *ServiceError
	if err != nil && input.Cursor != nil && errors.As(err, &serviceError) &&
		serviceError.StatusCode == http.StatusConflict && serviceError.Code == "cursor_invalid" {
		if clearErr := syncer.store.SavePosition(ctx,
			SyncPosition{ResolvedAt: local.Position.ResolvedAt}, syncer.now().UTC()); clearErr != nil {
			return clearErr
		}
		syncer.logger.Warn("platform policy cursor rejected; retrying without cursor")
		input.Cursor, input.KnownETag = nil, nil
		resolved, err = syncer.client.Resolve(ctx, input, syncer.privateKey, syncer.now().UTC())
	}
	if err != nil {
		return err
	}
	for _, target := range resolved.Targets {
		now := syncer.now().UTC()
		if _, err := syncer.store.RecordFetched(ctx, target.Encoded, target.Signed, now); err != nil {
			return err
		}
		if err := syncer.processCandidate(ctx, StoredTarget{Signed: target.Signed, Encoded: target.Encoded},
			now, keysetRefreshFailed); err != nil {
			return err
		}
	}
	resolvedAt := resolved.ResolvedAt
	position := SyncPosition{Cursor: stringPointer(resolved.Cursor), ETag: stringPointer(resolved.ETag), ResolvedAt: &resolvedAt}
	if err := syncer.store.SavePosition(ctx, position, syncer.now().UTC()); err != nil {
		return err
	}
	if err := syncer.restore(ctx); err != nil {
		return err
	}
	return syncer.flushAcknowledgements(ctx)
}

func (syncer *Syncer) restore(ctx context.Context) error {
	local, err := syncer.store.Load(ctx)
	if err != nil {
		return err
	}
	active, source := local.GlobalActive, ScopeGlobal
	if local.InstallationActive != nil {
		active, source = local.InstallationActive, ScopeInstallation
	}
	if active == nil {
		return syncer.state.Replace(Snapshot{Policy: DefaultPolicy(), Source: "default", Defaulted: true})
	}
	verified, err := Verify(active.Signed, syncer.trust, VerifyOptions{
		Now: syncer.now().UTC(), InstallationID: syncer.installationID, ControlVersion: syncer.controlVersion,
		ProtocolVersion: syncer.protocolVersion, DeliveredByResolve: true, AllowExpiredApplied: true,
	})
	if err != nil || verified.Signed.Policy == nil {
		if err == nil {
			err = ErrLocalValidation
		}
		return fmt.Errorf("restore active platform policy: %w", err)
	}
	return syncer.state.Replace(Snapshot{Policy: *verified.Signed.Policy, Source: source,
		TargetRevisionID: verified.Signed.Envelope.TargetRevisionID,
		ExpiresAt:        time.Unix(verified.Signed.Envelope.ExpiresAt, 0).UTC()})
}

func (syncer *Syncer) processPendingCandidates(ctx context.Context, keysetRefreshFailed bool) error {
	now := syncer.now().UTC()
	candidates, err := syncer.store.PendingCandidates(ctx, now, 64)
	if err != nil {
		return err
	}
	for _, candidate := range candidates {
		if err := syncer.processCandidate(ctx, candidate, now, keysetRefreshFailed); err != nil {
			return err
		}
	}
	return nil
}

func (syncer *Syncer) processCandidate(ctx context.Context, target StoredTarget, now time.Time,
	keysetRefreshFailed bool) error {
	local, err := syncer.store.Load(ctx)
	if err != nil {
		return err
	}
	options := VerifyOptions{
		Now: now, InstallationID: syncer.installationID, ControlVersion: syncer.controlVersion,
		ProtocolVersion: syncer.protocolVersion, DeliveredByResolve: true,
	}
	if target.Signed.Envelope.ScopeKind == ScopeGlobal {
		options.Head = local.GlobalHead
	} else {
		options.Head = local.InstallationHead
	}
	verified, verifyErr := Verify(target.Signed, syncer.trust, options)
	if verifyErr == nil && syncer.revocation != nil {
		if err := syncer.revocation.CheckSignerRevocation(entitlementguard.SignerArtifactPolicy,
			target.Signed.Envelope.KeyID); err != nil {
			syncer.logger.Warn("platform policy candidate rejected: signing key revoked",
				"event", "platform_policy.signer_revoked", "reason", "signer_revoked",
				"target_revision_id", target.Signed.Envelope.TargetRevisionID,
				"key_id", target.Signed.Envelope.KeyID)
			verifyErr = errors.Join(ErrSignerRevoked, err)
		}
	}
	if errors.Is(verifyErr, ErrNotYetValid) {
		return nil
	}
	if errors.Is(verifyErr, ErrUnknownSigningKey) && keysetRefreshFailed {
		return nil
	}
	if verifyErr != nil {
		if err := syncer.store.RecordRejected(ctx, target.Signed.Envelope.TargetRevisionID,
			RejectionCode(verifyErr), now); err != nil && !errors.Is(err, ErrAckTransition) {
			return err
		}
		return nil
	}
	if verified.Duplicate {
		return nil
	}
	if err := syncer.store.Apply(ctx, verified, now); err != nil {
		syncer.logger.Error("platform policy atomic apply failed",
			"target_revision_id", target.Signed.Envelope.TargetRevisionID,
			"scope_kind", target.Signed.Envelope.ScopeKind,
			"scope_revision", target.Signed.Envelope.ScopeRevision,
			"error", err)
		if rejectErr := syncer.store.RecordRejected(ctx, target.Signed.Envelope.TargetRevisionID,
			"atomic_apply_failed", now); rejectErr != nil && !errors.Is(rejectErr, ErrAckTransition) {
			return errors.Join(err, rejectErr)
		}
	}
	return nil
}

func (syncer *Syncer) resolveInput(local LocalState) ResolveInput {
	input := ResolveInput{
		InstallationID: syncer.installationID, ControlVersion: syncer.controlVersion,
		ControlProtocolVersion: syncer.protocolVersion, Cursor: cloneString(local.Position.Cursor),
		KnownETag: cloneString(local.Position.ETag),
	}
	if local.GlobalHead != nil {
		input.KnownGlobalRevision = local.GlobalHead.ScopeRevision
	}
	if local.InstallationHead != nil {
		input.KnownInstallationRevision = local.InstallationHead.ScopeRevision
	}
	active := local.GlobalActive
	if local.InstallationActive != nil {
		active = local.InstallationActive
	}
	if active != nil {
		input.ActiveTargetRevisionID = &active.Signed.Envelope.TargetRevisionID
		input.ActivePolicySHA256 = &active.Signed.Envelope.CanonicalPolicySHA256
	}
	return input
}

func (syncer *Syncer) flushAcknowledgements(ctx context.Context) error {
	for {
		now := syncer.now().UTC()
		pending, err := syncer.store.PendingAcks(ctx, now, 64)
		if err != nil {
			return err
		}
		if len(pending) == 0 {
			return nil
		}
		for _, item := range pending {
			_, err := syncer.client.Acknowledge(ctx, AckInput{
				InstallationID: syncer.installationID, TargetRevisionID: item.TargetRevisionID,
				ScopeKind: item.ScopeKind, ScopeRevision: item.ScopeRevision,
				CanonicalPolicySHA256: item.CanonicalPolicySHA256, Status: item.Status,
				ErrorCode: cloneString(item.ErrorCode), ObservedAt: item.ObservedAt,
			}, syncer.privateKey, now)
			if err == nil {
				if err := syncer.store.CompleteAck(ctx, item.EventID, syncer.now().UTC()); err != nil {
					return err
				}
				continue
			}
			retryAfter, canRetry := retryable(err)
			if !canRetry {
				retryAfter = syncer.backoffMax
			}
			if retryAfter < syncer.backoffMin {
				retryAfter = syncer.backoffMin
			}
			if retryAfter > syncer.backoffMax {
				retryAfter = syncer.backoffMax
			}
			code := "transport_error"
			var serviceError *ServiceError
			if errors.As(err, &serviceError) && serviceError.Code != "" {
				code = serviceError.Code
			}
			if deferErr := syncer.store.DeferAck(ctx, item.EventID, code, now.Add(retryAfter), now); deferErr != nil {
				return errors.Join(err, deferErr)
			}
			return err
		}
	}
}

func stringPointer(value string) *string {
	if value == "" {
		return nil
	}
	return &value
}

func waitContext(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
