package edgestatus

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nats-io/nats.go"
)

const (
	// strandedReplayPage is how many running deployments one page lists.
	strandedReplayPage = 500
	// strandedReplayRetry and strandedReplayMaxRetry bound the backoff after
	// a round that hit a transient database or NATS error.
	strandedReplayRetry    = 2 * time.Second
	strandedReplayMaxRetry = time.Minute
	// strandedReplayMaxMessages and strandedReplayMaxBytes bound one batch:
	// the stream keeps every status (max_age 0) and a node's subject also
	// carries its other deployments' statuses since the oldest running one (an
	// activated or reverting deployment never times out). A node subject is
	// read in batches of at most this many messages and kept payload bytes;
	// each batch is projected before the next is read, from where the
	// subscription stopped, until the subject's current end.
	strandedReplayMaxMessages = 10000
	strandedReplayMaxBytes    = 8 << 20
)

// strandedReplay re-projects, once per process, the statuses the status stream
// (limits retention) still holds for deployments that are still running.
// Before the sequence gap wait, a status that overtook a missing predecessor
// was terminated and never delivered again (11-26 fresh install: STAGED..
// HEALTHY dropped, the deployment stuck at STARTED, the node's heartbeats
// refused). Replaying them in sequence order through the same projection
// moves such a deployment on; anything already stored is a duplicate, and a
// status refused before is refused again without side effects. A round that
// hits a transient error is retried with backoff. A round that moved any
// deployment is followed by another (a status read before its predecessor is
// projected on a later pass); the replay completes after a whole round over
// every running deployment moved none. Each further round needs one more
// stored status, so the rounds are bounded by the statuses to replay.
type strandedReplay struct {
	pool        *pgxpool.Pool
	consumer    *NATSConsumer
	validator   *Validator
	project     func(context.Context, Envelope) (ProjectionResult, error)
	logger      *slog.Logger
	pageSize    int
	retry       time.Duration
	maxMessages int
	maxBytes    int
	// maxWaiting and maxWaitingBytes bound the statuses one node carries to
	// its next batch while their predecessor is not stored yet.
	maxWaiting      int
	maxWaitingBytes int
	running         atomic.Bool
	done            atomic.Bool
	failures        atomic.Int64
	batches         atomic.Int64
	dropped         atomic.Int64
	rounds          atomic.Int64
}

func newStrandedReplay(pool *pgxpool.Pool, consumer *NATSConsumer, validator *Validator, store *Store,
	logger *slog.Logger,
) *strandedReplay {
	return &strandedReplay{pool: pool, consumer: consumer, validator: validator, project: store.Project,
		logger: logger, pageSize: strandedReplayPage, retry: strandedReplayRetry,
		maxMessages: strandedReplayMaxMessages, maxBytes: strandedReplayMaxBytes,
		maxWaiting: strandedReplayMaxMessages, maxWaitingBytes: strandedReplayMaxBytes}
}

type replayKey struct {
	deploymentID uuid.UUID
	attempt      uint32
}

type replayCounts struct {
	deployments, advanced, refused int
}

// start runs the replay in the background until a round completes, unless it
// already completed or is running.
func (r *strandedReplay) start(ctx context.Context) {
	if r == nil || r.done.Load() || !r.running.CompareAndSwap(false, true) {
		return
	}
	go func() {
		defer r.running.Store(false)
		delay := r.retry
		for {
			counts, err := r.run(ctx)
			if ctx.Err() != nil {
				return
			}
			if err == nil {
				r.done.Store(true)
				r.logger.Info("stranded deployment status replay finished", "running_deployments", counts.deployments,
					"advanced", counts.advanced, "refused", counts.refused, "failed_rounds", r.failures.Load(),
					"rounds", r.rounds.Load(), "batches", r.batches.Load(), "dropped_waiting", r.dropped.Load())
				return
			}
			failures := r.failures.Add(1)
			r.logger.Warn("stranded deployment status replay failed, will retry", "error", err,
				"failed_rounds", failures, "retry_in", delay)
			timer := time.NewTimer(delay)
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
			}
			delay = min(2*delay, strandedReplayMaxRetry)
		}
	}()
}

// run repeats rounds until one moves no deployment.
func (r *strandedReplay) run(ctx context.Context) (replayCounts, error) {
	var total replayCounts
	for {
		counts, err := r.round(ctx)
		r.rounds.Add(1)
		total.advanced += counts.advanced
		// The first round saw every deployment that was running; the
		// last one's refusals are those nothing could move.
		if r.rounds.Load() == 1 || total.deployments == 0 {
			total.deployments = max(total.deployments, counts.deployments)
		}
		total.refused = counts.refused
		if err != nil || counts.advanced == 0 {
			return total, err
		}
	}
}

// round goes once over every running deployment, a page at a time.
func (r *strandedReplay) round(ctx context.Context) (replayCounts, error) {
	var counts replayCounts
	var afterCreated time.Time
	var afterID uuid.UUID
	var afterAttempt int32 = -1
	for {
		rows, err := r.pool.Query(ctx, `SELECT id,attempt,node_id,created_at FROM node_deployments
			WHERE state IN ('delivered','agent_queued','started','staged','prechecked','activated','reverting')
			  AND (created_at,id,attempt) > ($1,$2,$3)
			ORDER BY created_at,id,attempt LIMIT $4`, afterCreated, afterID, afterAttempt, r.pageSize)
		if err != nil {
			return counts, fmt.Errorf("list running deployments: %w", err)
		}
		wanted := map[replayKey]bool{}
		since := map[uuid.UUID]time.Time{}
		var nodes []uuid.UUID
		var id, node uuid.UUID
		var attempt int32
		var created time.Time
		listed := 0
		if _, err := pgx.ForEachRow(rows, []any{&id, &attempt, &node, &created}, func() error {
			listed++
			afterCreated, afterID, afterAttempt = created, id, attempt
			wanted[replayKey{deploymentID: id, attempt: uint32(attempt)}] = true
			if first, ok := since[node]; !ok || created.Before(first) {
				if !ok {
					nodes = append(nodes, node)
				}
				since[node] = created
			}
			return nil
		}); err != nil {
			return counts, fmt.Errorf("read running deployments: %w", err)
		}
		counts.deployments += listed
		for _, node := range nodes {
			if err := r.replayNode(ctx, node, since[node], wanted, &counts); err != nil {
				return counts, err
			}
		}
		if listed < r.pageSize {
			return counts, nil
		}
	}
}

// replayNode replays one node's subjects batch by batch. A status whose
// predecessor is not stored yet (ErrSequenceGap) is carried into the next
// batch, where the predecessor may be (stream order 1,2,4..7,3: 4..7 wait for
// 3); whatever still waits after the node's last batch has no predecessor in
// the stream. Carried statuses are those of running deployments only, a few
// per deployment; past maxWaiting or maxWaitingBytes the latest are dropped
// for this round, counted and logged, and read again by the next round.
func (r *strandedReplay) replayNode(ctx context.Context, node uuid.UUID, since time.Time,
	wanted map[replayKey]bool, counts *replayCounts,
) error {
	var waiting []Envelope
	project := func(batch []Envelope) error {
		var err error
		waiting, err = r.projectBatch(ctx, append(waiting, batch...), counts)
		if err != nil {
			return err
		}
		bytes := 0
		for index, envelope := range waiting {
			bytes += len(envelope.Payload)
			if index >= r.maxWaiting || bytes > r.maxWaitingBytes {
				dropped := len(waiting) - index
				r.dropped.Add(int64(dropped))
				counts.refused += dropped
				r.logger.Warn("stranded deployment status replay deferred statuses waiting for a predecessor to the next round",
					"node_id", node.String(), "dropped", dropped, "max_waiting", r.maxWaiting,
					"max_waiting_bytes", r.maxWaitingBytes)
				waiting = waiting[:index]
				break
			}
		}
		return nil
	}
	prefix := r.consumer.config.SubjectPrefix
	for _, subject := range []string{prefix + "." + node.String(), prefix + ".generic-v2." + node.String() + ".*"} {
		// A minute before the deployment: the PostgreSQL and NATS clocks.
		if err := r.read(ctx, subject, since.Add(-time.Minute), wanted, project); err != nil {
			return err
		}
	}
	counts.refused += len(waiting)
	return nil
}

// projectBatch projects the batch in sequence order and returns the statuses
// still waiting for a predecessor; a transient error ends the round.
func (r *strandedReplay) projectBatch(ctx context.Context, batch []Envelope, counts *replayCounts) ([]Envelope, error) {
	sort.SliceStable(batch, func(i, j int) bool {
		a, b := batch[i], batch[j]
		if a.DeploymentID != b.DeploymentID {
			return a.DeploymentID.String() < b.DeploymentID.String()
		}
		if a.Status.Attempt != b.Status.Attempt {
			return a.Status.Attempt < b.Status.Attempt
		}
		return a.Status.TransitionSequence < b.Status.TransitionSequence
	})
	var waiting []Envelope
	for _, envelope := range batch {
		operationCtx, cancel := context.WithTimeout(ctx, r.consumer.config.OperationTimeout)
		result, err := r.project(operationCtx, envelope)
		cancel()
		switch {
		case ctx.Err() != nil:
			return nil, ctx.Err()
		case err == nil:
			if result.Outcome == OutcomeAdvanced {
				counts.advanced++
			}
		case errors.Is(err, ErrSequenceGap):
			waiting = append(waiting, envelope)
		case permanentProjectionError(err):
			counts.refused++
		default:
			return nil, fmt.Errorf("replay deployment %s status %d: %w", envelope.DeploymentID,
				envelope.Status.TransitionSequence, err)
		}
	}
	return waiting, nil
}

// read goes through the subject's statuses from start to its current end with
// one short-lived ordered consumer, whose position is the cursor between
// batches. It keeps the decodable statuses of the wanted deployments (a
// repeated event is a duplicate to the projection) and hands them to project whenever a batch reaches maxMessages
// read or maxBytes kept, and at the end. The consumer's own count says whether
// there is anything to read, so a status that does not arrive in time is an
// error, not the end. A failed round starts over from start: projections are
// idempotent, so no cursor is persisted.
func (r *strandedReplay) read(ctx context.Context, subject string, start time.Time, wanted map[replayKey]bool,
	project func([]Envelope) error,
) error {
	subscription, err := r.consumer.js.SubscribeSync(subject, nats.OrderedConsumer(), nats.StartTime(start),
		nats.BindStream(r.consumer.config.Stream))
	if err != nil {
		return fmt.Errorf("replay deployment statuses of %s: %w", subject, err)
	}
	defer func() { _ = subscription.Unsubscribe() }()
	info, err := subscription.ConsumerInfo()
	if err != nil {
		return fmt.Errorf("replay deployment statuses of %s: %w", subject, err)
	}
	if info.NumPending == 0 && info.Delivered.Consumer == 0 {
		return nil
	}
	var batch []Envelope
	scanned, kept := 0, 0
	flush := func() error {
		r.batches.Add(1)
		err := project(batch)
		batch, scanned, kept = nil, 0, 0
		return err
	}
	for {
		waitCtx, cancel := context.WithTimeout(ctx, r.consumer.config.OperationTimeout)
		message, err := subscription.NextMsgWithContext(waitCtx)
		cancel()
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err != nil {
			return fmt.Errorf("replay deployment statuses of %s: %w", subject, err)
		}
		scanned++
		if envelope, err := r.validator.Decode(message.Subject, message.Data); err == nil &&
			wanted[replayKey{deploymentID: envelope.DeploymentID, attempt: envelope.Status.GetAttempt()}] {
			if len(batch) > 0 && kept+len(message.Data) > r.maxBytes {
				if err := flush(); err != nil {
					return err
				}
			}
			kept += len(message.Data)
			batch = append(batch, envelope)
		}
		metadata, err := message.Metadata()
		if err != nil {
			return fmt.Errorf("replay deployment statuses of %s: %w", subject, err)
		}
		if metadata.NumPending == 0 {
			return flush()
		}
		if scanned >= r.maxMessages {
			if err := flush(); err != nil {
				return err
			}
		}
	}
}
