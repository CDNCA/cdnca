package nodemonitoringoutbox

import (
	"errors"
	"time"

	"github.com/google/uuid"
)

const (
	CommandStream        = "NODE_MONITORING_COMMANDS"
	CommandSubjectBase   = "cdnca.agent.node-monitoring.commands"
	CommandMessagePrefix = "node-monitoring-v1-"
	StatePending         = "pending"
	StatePublishing      = "publishing"
	StatePublished       = "published"
	StateFailed          = "failed"
)

// ServingNodePredicate selects nodes that may receive node monitoring
// artifacts, for a query that aliases nodes as "node". An active node without
// a recorded first signed edge configuration activation has no OpenResty
// listener, so the Agent preflight would reject the artifact and the gateway
// would close the session on every redelivery. Activation publication and the
// reconciliation backfill must share this exact target set.
const ServingNodePredicate = `node.admin_state='active' AND EXISTS (
	SELECT 1 FROM node_config_state serving
	WHERE serving.node_id=node.id AND serving.current_config_version_id IS NOT NULL)`

var (
	ErrInvalidInput = errors.New("invalid node monitoring outbox input")
	ErrConflict     = errors.New("node monitoring outbox conflict")
)

type Command struct {
	ID             uuid.UUID
	NodeID         uuid.UUID
	ConfigRevision uint64
	Subject        string
	MessageID      string
	Payload        []byte
	PayloadSHA256  []byte
	ClaimToken     uuid.UUID
	AttemptCount   int
}

type Config struct {
	OperationTimeout time.Duration
	PollInterval     time.Duration
	ClaimLease       time.Duration
	RetryDelay       time.Duration
	BatchSize        int
	MaxPayloadBytes  int
	MaxAttempts      int
	Clock            func() time.Time
	WorkerID         uuid.UUID
}

func DefaultConfig() Config {
	return Config{
		OperationTimeout: 5 * time.Second,
		PollInterval:     500 * time.Millisecond,
		ClaimLease:       30 * time.Second,
		RetryDelay:       time.Second,
		BatchSize:        32,
		MaxPayloadBytes:  1 << 20,
		MaxAttempts:      16,
		Clock:            time.Now,
		WorkerID:         uuid.New(),
	}
}

func (config Config) validate() error {
	if config.OperationTimeout <= 0 || config.PollInterval <= 0 || config.ClaimLease <= config.OperationTimeout ||
		config.RetryDelay <= 0 || config.BatchSize < 1 || config.BatchSize > 128 ||
		config.MaxPayloadBytes < 1 || config.MaxPayloadBytes > 1<<20 || config.MaxAttempts < 1 || config.MaxAttempts > 16 ||
		config.Clock == nil || config.WorkerID == uuid.Nil {
		return ErrInvalidInput
	}
	return nil
}
