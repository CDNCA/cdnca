package cachecontrol

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// resubmitKey is the new operation's idempotency key: the original operation
// and the caller's batch key (one "re-submit selected" shares it), so a retry
// of the same batch replays and another batch creates another operation.
func resubmitKey(operationID uuid.UUID, batchKey string) string {
	digest := sha256.Sum256([]byte(batchKey))
	return "resubmit." + operationID.String() + "." + hex.EncodeToString(digest[:8])
}

// Resubmit creates a new operation from an existing one (「重新提交」):
// the same site, action, target type, targets and retry budget, on the nodes
// the original named, or on every node carrying the site now when it named
// none (an automatic operation, or a follow-up of one).
func (store *Store) Resubmit(ctx context.Context, actor Actor, request ResubmitRequest) (OperationWriteResult, error) {
	if ctx == nil || !validActor(actor) || request.OperationID == uuid.Nil ||
		!validWriteMetadata(request.BatchKey, request.RequestID) {
		return OperationWriteResult{}, ErrInvalidInput
	}
	var source Operation
	err := pgx.BeginTxFunc(ctx, store.pool, pgx.TxOptions{IsoLevel: pgx.RepeatableRead}, func(tx pgx.Tx) error {
		if _, err := store.authorizeActor(ctx, tx, actor, "sites.manage"); err != nil {
			return err
		}
		var err error
		source, err = loadOperation(ctx, tx, actor.ScopeID, request.OperationID)
		return err
	})
	if err != nil {
		return OperationWriteResult{}, fmt.Errorf("read resubmitted cache operation: %w", err)
	}
	if source.MaxAttempts < 1 || len(source.Targets) == 0 {
		return OperationWriteResult{}, errors.New("resubmitted cache operation has invalid facts")
	}
	create := CreateOperationRequest{
		SiteID: source.SiteID, Action: source.Action, TargetType: source.TargetType,
		MaxRetries: source.MaxAttempts - 1, IdempotencyKey: resubmitKey(source.ID, request.BatchKey),
		RequestID: request.RequestID,
	}
	if source.TargetType != TargetWholeSite {
		create.Targets = make([]string, len(source.Targets))
		for index, target := range source.Targets {
			create.Targets[index] = target.CanonicalURL
		}
	}
	if !source.AutoNodes {
		create.NodeIDs = make([]uuid.UUID, len(source.Nodes))
		for index, node := range source.Nodes {
			create.NodeIDs[index] = node.NodeID
		}
	}
	result, err := store.createOperation(ctx, actor, create, source.ID)
	if err != nil {
		return OperationWriteResult{}, store.withWriteRejection(ctx, actor, rejectedWrite{
			action: WriteResubmit, operationID: source.ID, key: request.BatchKey, requestID: request.RequestID,
		}, err)
	}
	return result, nil
}
