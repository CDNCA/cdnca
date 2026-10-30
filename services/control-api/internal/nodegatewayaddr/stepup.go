package nodegatewayaddr

import (
	"bytes"
	"context"
	"crypto/sha256"
	"sort"
	"strings"

	"github.com/cdnca/cdnca/services/control-api/internal/iamstage2b"
	"github.com/cdnca/cdnca/services/control-api/internal/mfa"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// StepUpBinding binds the MFA proof to exactly what is submitted (address,
// server name, target; node order does not matter).
func StepUpBinding(request CreateRequest) [32]byte {
	ids := make([]string, len(request.NodeIDs))
	for index, id := range request.NodeIDs {
		ids[index] = id.String()
	}
	sort.Strings(ids)
	return sha256.Sum256([]byte("cdnca.node-gateway-address/v1\x00" + request.Address + "\x00" + request.ServerName + "\x00" +
		request.TargetKind + "\x00" + request.Region + "\x00" + strings.Join(ids, ",")))
}

// RetryBinding binds a retry proof to the change.
func RetryBinding(changeID uuid.UUID) [32]byte {
	return sha256.Sum256([]byte("cdnca.node-gateway-address-retry/v1\x00" + changeID.String()))
}

// StepUp consumes a platform-scoped proof for action bound to binding.
type StepUp interface {
	Consume(ctx context.Context, actor Actor, token, action string, binding [32]byte) error
}

type StepUpConsumer interface {
	ConsumeStepUpTxWithScopes(context.Context, pgx.Tx, mfa.Actor, []uuid.UUID, mfa.ConsumeStepUpRequest) (mfa.Evidence, error)
}

// PlatformStepUp consumes the proof in its own transaction (as migrate import).
type PlatformStepUp struct {
	Pool     *pgxpool.Pool
	Consumer StepUpConsumer
}

func (p PlatformStepUp) Consume(ctx context.Context, actor Actor, token, action string, binding [32]byte) error {
	if p.Pool == nil || p.Consumer == nil || token == "" || actor.SessionID == uuid.Nil {
		return ErrStepUpRequired
	}
	requestID := "ngw-" + uuid.NewString()
	var evidence mfa.Evidence
	err := pgx.BeginFunc(ctx, p.Pool, func(tx pgx.Tx) error {
		locked, err := iamstage2b.BeginAuthorityMutation(ctx, tx, iamstage2b.OperationMFAConsumeStepUp, []uuid.UUID{actor.ScopeID})
		if err != nil {
			return err
		}
		evidence, err = p.Consumer.ConsumeStepUpTxWithScopes(ctx, tx, mfa.Actor{UserID: actor.UserID,
			ScopeID: actor.ScopeID, SessionID: actor.SessionID}, locked, mfa.ConsumeStepUpRequest{
			Token: token, PlatformScope: true, Audience: StepUpAudience, Action: action,
			ResourceBindingDigest: binding[:], Context: mfa.RequestContext{RequestID: requestID, TraceID: requestID},
		})
		return err
	})
	if err != nil || evidence.ProofID == uuid.Nil || !evidence.PlatformScope || evidence.TenantID != uuid.Nil ||
		evidence.ActorUserID != actor.UserID || evidence.ActorScopeID != actor.ScopeID || evidence.SessionID != actor.SessionID ||
		evidence.Audience != StepUpAudience || evidence.Action != action || evidence.UseOrdinal != 1 ||
		!bytes.Equal(evidence.ResourceBindingDigest, binding[:]) {
		return ErrStepUpRequired
	}
	return nil
}
