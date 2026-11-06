package plugininstallation

import (
	"context"

	"github.com/google/uuid"
)

// Store must serialize callbacks for one authorization (across all local scopes) and commit
// the state plus immutable receipt atomically.
type Store interface {
	Transact(context.Context, uuid.UUID, uuid.UUID, func(Transaction) error) error
}

type Transaction interface {
	Current() (Installation, bool, error)
	// BoundElsewhere reports that the authorization already has its local target binding: a head in another
	// local scope. One license authorization lands on exactly one local target on this controller.
	BoundElsewhere() (bool, error)
	Replay(idempotencyKey string) (Receipt, bool, error)
	Save(Installation, Receipt) error
}

// TargetSaver is a Transaction that can record the tenants of a platform-confirmed tenant plugin in the same
// transaction as its first head (control migration 636).
type TargetSaver interface {
	SaveTargets(Installation, Receipt, Targets) error
}
