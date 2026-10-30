package sched302table

import (
	"context"
	"crypto/sha256"
	"errors"
	"log/slog"
	"time"

	"github.com/cdnca/cdnca/libs/edgeconfig/sched302"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// Signer signs table_json (the configuration artifact key).
type Signer interface {
	KeyID() string
	Sign(context.Context, []byte) ([]byte, error)
}

// Publisher hands one node's signed table to the gateway (JetStream).
type Publisher interface {
	Publish(ctx context.Context, nodeID string, table *agentv1.Sched302Table) error
}

// Worker recomputes and pushes the tables.
type Worker struct {
	pool      *pgxpool.Pool
	signer    Signer
	publisher Publisher
	now       func() time.Time
	logger    *slog.Logger
	// refresh resends an unchanged table after this (well within the node's
	// hold, so it never goes stale while the control plane runs).
	refresh time.Duration
	load    func(context.Context, *pgxpool.Pool, time.Time) ([]Site, error)
}

func NewWorker(pool *pgxpool.Pool, signer Signer, publisher Publisher, now func() time.Time, logger *slog.Logger) (*Worker, error) {
	if pool == nil || signer == nil || signer.KeyID() == "" || publisher == nil {
		return nil, errors.New("schedule302 table worker needs a pool, a signer and a publisher")
	}
	if now == nil {
		now = time.Now
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &Worker{pool: pool, signer: signer, publisher: publisher, now: now, logger: logger,
		refresh: time.Duration(sched302.HoldSeconds) * time.Second / 3, load: LoadSites}, nil
}

// Interval is how often tables are recomputed: a health change reaches
// the nodes within about a second plus the gateway hop.
const Interval = time.Second

// Run ticks every Interval until ctx ends (a control-api runtime worker).
func (worker *Worker) Run(ctx context.Context) error {
	ticker := time.NewTicker(Interval)
	defer ticker.Stop()
	for {
		if err := worker.Tick(ctx); err != nil && ctx.Err() == nil {
			worker.logger.Warn("schedule302 tables", "error", err)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

// Tick pushes every node whose table changed or is due for a refresh. A
// node that no longer serves any schedule302 site gets an empty table once
// (it stops redirecting at once instead of waiting for the hold).
func (worker *Worker) Tick(ctx context.Context) error {
	now := worker.now().UTC()
	sites, err := worker.load(ctx, worker.pool, now)
	if err != nil {
		return err
	}
	tables := Tables(sites, now.Unix())
	states, err := loadPushStates(ctx, worker.pool)
	if err != nil {
		return err
	}
	empty := [sha256.Size]byte{}
	for nodeID, state := range states {
		if _, serving := tables[nodeID]; !serving && state.digest != empty {
			tables[nodeID] = sched302.Table{Schema: sched302.TableSchema, NodeID: nodeID.String(), GeneratedAt: now.Unix(),
				Sites: []sched302.TableSite{}}
		}
	}
	var firstErr error
	for nodeID, table := range tables {
		digest := Digest(table)
		state, known := states[nodeID]
		if len(table.Sites) == 0 {
			digest = empty
		}
		if known && state.digest == digest && now.Sub(state.pushedAt) < worker.refresh {
			continue
		}
		if known && len(table.Sites) == 0 && state.digest == empty {
			continue
		}
		table.Revision = uint64(state.revision + 1)
		if err := worker.push(ctx, nodeID, table); err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		if err := savePushState(ctx, worker.pool, nodeID, pushState{revision: int64(table.Revision), digest: digest, pushedAt: now}); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func (worker *Worker) push(ctx context.Context, nodeID uuid.UUID, table sched302.Table) error {
	encoded, err := sched302.Encode(table)
	if err != nil {
		return err
	}
	signature, err := worker.signer.Sign(ctx, encoded)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(encoded)
	carrier := &agentv1.Sched302Table{
		Event:  &commonv1.EventMetadata{EventId: uuid.NewString(), RequestId: uuid.NewString(), OccurredTime: timestamppb.New(worker.now())},
		Schema: agentv1.Sched302Schema_SCHED302_SCHEMA_V1, NodeId: nodeID.String(), Revision: table.Revision,
		TableJson: encoded, TableSha256: digest[:],
		SignatureAlgorithm: agentv1.ArtifactSignatureAlgorithm_ARTIFACT_SIGNATURE_ALGORITHM_ED25519,
		SigningKeyId:       worker.signer.KeyID(), Signature: signature,
	}
	return worker.publisher.Publish(ctx, nodeID.String(), carrier)
}
