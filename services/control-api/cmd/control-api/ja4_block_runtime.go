package main

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"sort"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/analytics"
	"github.com/cdnca/cdnca/services/control-api/internal/iamstage2b"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/ja4block"
	"github.com/cdnca/cdnca/services/control-api/internal/ja4blockhttp"
	"github.com/cdnca/cdnca/services/control-api/internal/mfa"
	"github.com/cdnca/cdnca/services/control-api/internal/mfahttp"
	"github.com/cdnca/cdnca/services/control-api/internal/securitybinding"
	"github.com/cdnca/cdnca/services/control-api/internal/securitybundle"
	"github.com/cdnca/cdnca/services/control-api/internal/securitypolicy"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const ja4BlockStepUpAudience = "security.ja4_block.create"

type ja4BlockProductionConfig struct {
	Enabled         bool
	TargetFreshness time.Duration
	Window          time.Duration
	SnapshotTTL     time.Duration
	PageSize        uint16
	MaxPages        int
	BundleValidity  time.Duration
	Worker          ja4block.RuntimeConfig
}

func defaultJA4BlockProductionConfig(enabled bool, bundleValidity time.Duration) ja4BlockProductionConfig {
	return ja4BlockProductionConfig{
		Enabled: enabled, TargetFreshness: 2 * time.Minute,
		Window: 24 * time.Hour, SnapshotTTL: 10 * time.Minute, PageSize: 100, MaxPages: 100,
		BundleValidity: bundleValidity,
		Worker: ja4block.RuntimeConfig{
			WorkerID: "control-api-ja4-block", PollInterval: time.Second, ErrorBackoff: 5 * time.Second,
			OperationTimeout: 5 * time.Second, ReceiptLease: 30 * time.Second,
		},
	}
}

type ja4BlockProductionDependencies struct {
	Pool      *pgxpool.Pool
	Analytics *analytics.Service
	Identity  *identity.Service
	StepUp    mfahttp.StepUpConsumer
	Signer    securitybundle.Signer
	Now       func() time.Time
}

type ja4BlockProductionRuntime struct {
	worker  *ja4block.Runtime
	handler http.Handler
}

func openJA4BlockProductionRuntime(config ja4BlockProductionConfig,
	dependencies ja4BlockProductionDependencies,
) (*ja4BlockProductionRuntime, error) {
	if !config.Enabled {
		return nil, nil
	}
	if !configuredRuntimePool(dependencies.Pool) || dependencies.Analytics == nil ||
		dependencies.Identity == nil || !dependencies.Identity.Configured() ||
		nilRuntimeDependency(dependencies.StepUp) || nilRuntimeDependency(dependencies.Signer) ||
		dependencies.Now == nil {
		return nil, errors.New("JA4 block production dependencies are required")
	}
	targets, err := ja4block.NewPostgresPublicationTargetResolver(
		dependencies.Pool, dependencies.Now, config.TargetFreshness,
	)
	if err != nil {
		return nil, err
	}
	authority, err := ja4block.NewAnalyticsAuthority(dependencies.Analytics, targets,
		ja4block.AnalyticsAuthorityConfig{
			Actor:  analytics.Actor{ScopeKind: "platform", Permissions: []string{"platform.admin", analytics.ReadPermission}},
			Window: config.Window, SnapshotTTL: config.SnapshotTTL, PageSize: config.PageSize,
			MaxPages: config.MaxPages, Clock: dependencies.Now,
		})
	if err != nil {
		return nil, err
	}
	bundlePublisher, err := securitybundle.NewPublisher(dependencies.Signer, securitybundle.Config{
		Clock: dependencies.Now, Validity: config.BundleValidity,
	})
	if err != nil {
		return nil, err
	}
	publications, err := securitybinding.NewStore(dependencies.Pool, bundlePublisher, dependencies.Now)
	if err != nil {
		return nil, err
	}
	store, err := ja4block.NewPostgresStore(dependencies.Pool, dependencies.Now)
	if err != nil {
		return nil, err
	}
	service, err := ja4block.NewService(
		store, authority,
		securitypolicy.NewService(securitypolicy.NewStoreWithClock(dependencies.Pool, dependencies.Now)),
		publications, dependencies.Now,
	)
	if err != nil {
		return nil, err
	}
	receipts, err := ja4block.NewPostgresEdgeReceiptQueue(dependencies.Pool)
	if err != nil {
		return nil, err
	}
	worker, err := ja4block.NewRuntime(service, receipts, config.Worker, dependencies.Now)
	if err != nil {
		return nil, err
	}
	stepUp := &ja4BlockStepUpVerifier{
		pool: dependencies.Pool, consumer: dependencies.StepUp, now: dependencies.Now,
	}
	handler, err := ja4blockhttp.NewHandler(ja4blockhttp.Dependencies{
		Application: service, AuthenticateSession: dependencies.Identity.AuthenticateSession,
		VerifyStepUp: stepUp.Verify,
	})
	if err != nil {
		return nil, err
	}
	return &ja4BlockProductionRuntime{worker: worker, handler: handler}, nil
}

func (runtime *ja4BlockProductionRuntime) HandlerFactory() func() (http.Handler, error) {
	if runtime == nil || runtime.handler == nil {
		return nil
	}
	return func() (http.Handler, error) { return runtime.handler, nil }
}

func (runtime *ja4BlockProductionRuntime) Run(ctx context.Context) error {
	if runtime == nil || runtime.worker == nil {
		return ja4block.ErrInvalidConfiguration
	}
	return runtime.worker.Run(ctx)
}

func (runtime *ja4BlockProductionRuntime) Ready() error {
	if runtime == nil || runtime.worker == nil || runtime.handler == nil {
		return ja4block.ErrInvalidConfiguration
	}
	return runtime.worker.Ready()
}

func (runtime *ja4BlockProductionRuntime) Close() error {
	if runtime == nil || runtime.worker == nil {
		return nil
	}
	return runtime.worker.Close()
}

type ja4BlockStepUpVerifier struct {
	pool     *pgxpool.Pool
	consumer mfahttp.StepUpConsumer
	now      func() time.Time
}

func (verifier *ja4BlockStepUpVerifier) Verify(ctx context.Context,
	check ja4blockhttp.StepUpCheck,
) (ja4blockhttp.StepUpEvidence, error) {
	if verifier == nil || !configuredRuntimePool(verifier.pool) || nilRuntimeDependency(verifier.consumer) ||
		verifier.now == nil || ctx == nil || check.SessionID == uuid.Nil || check.UserID == uuid.Nil ||
		check.ScopeID == uuid.Nil || check.TargetTenantScopeID == uuid.Nil || check.Token == "" ||
		check.Action != ja4BlockStepUpAudience || check.RequestID == "" || check.RequestSHA256 == ([32]byte{}) {
		return ja4blockhttp.StepUpEvidence{}, ja4blockhttp.ErrStepUpRequired
	}
	var evidence mfa.Evidence
	var targetTenantID uuid.UUID
	err := pgx.BeginFunc(ctx, verifier.pool, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, `SELECT tenant_id FROM access_scopes
			WHERE id=$1 AND kind='tenant'`, check.TargetTenantScopeID).Scan(&targetTenantID); err != nil {
			return err
		}
		authorityScopes := []uuid.UUID{check.ScopeID}
		if check.TargetTenantScopeID != check.ScopeID {
			authorityScopes = append(authorityScopes, check.TargetTenantScopeID)
		}
		sort.Slice(authorityScopes, func(left, right int) bool {
			return bytes.Compare(authorityScopes[left][:], authorityScopes[right][:]) < 0
		})
		lockedScopes, err := iamstage2b.BeginAuthorityMutation(
			ctx, tx, iamstage2b.OperationMFAConsumeStepUp, authorityScopes,
		)
		if err != nil {
			return err
		}
		evidence, err = verifier.consumer.ConsumeStepUpTxWithScopes(ctx, tx, mfa.Actor{
			UserID: check.UserID, ScopeID: check.ScopeID, SessionID: check.SessionID,
		}, lockedScopes, mfa.ConsumeStepUpRequest{
			Token: check.Token, TenantID: targetTenantID, Audience: ja4BlockStepUpAudience, Action: check.Action,
			ResourceBindingDigest: check.RequestSHA256[:],
			Context:               mfa.RequestContext{RequestID: check.RequestID, TraceID: check.RequestID},
		})
		return err
	})
	now := verifier.now().UTC()
	if err != nil || evidence.ProofID == uuid.Nil || evidence.ActorUserID != check.UserID ||
		evidence.ActorScopeID != check.ScopeID || evidence.SessionID != check.SessionID ||
		evidence.TenantID != targetTenantID ||
		evidence.Audience != ja4BlockStepUpAudience || evidence.Action != check.Action ||
		!bytes.Equal(evidence.ResourceBindingDigest, check.RequestSHA256[:]) || evidence.VerifiedAt.IsZero() ||
		evidence.VerifiedAt.After(now) || !evidence.ExpiresAt.After(now) {
		return ja4blockhttp.StepUpEvidence{}, ja4blockhttp.ErrStepUpRequired
	}
	return ja4blockhttp.StepUpEvidence{ID: evidence.ProofID, VerifiedAt: evidence.VerifiedAt}, nil
}
