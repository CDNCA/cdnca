// Package edgesignertrustsync accepts the offline-root signed node signer
// trust document (libs/entitlement/edgesignertrust), keeps every accepted
// revision (migration 340), and distributes the latest one to nodes.
// Design: docs/architecture/signer-revocation-offline-and-edge.md §3.
package edgesignertrustsync

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/cdnca/cdnca/libs/entitlement/edgesignertrust"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const acceptLock int64 = 501809704351931

const (
	SourceFetch  = "fetch"
	SourceImport = "import"

	ReasonAccepted          = "document_accepted"
	ReasonReplayed          = "document_replayed"
	ReasonInvalid           = "invalid_document"
	ReasonUntrusted         = "untrusted_signature"
	ReasonStale             = "stale_revision"
	ReasonConflict          = "revision_conflict"
	ReasonDroppedRevocation = "dropped_revocation"
	ReasonNotPublished      = "not_published"
	ReasonNetwork           = "network_unavailable"
	ReasonServer            = "server_unavailable"
)

// RejectedError is a document the store refused; the LKG is unchanged.
type RejectedError struct{ Reason string }

func (err *RejectedError) Error() string { return "edge signer trust document rejected: " + err.Reason }

// Accepted is the store's latest document after Accept.
type Accepted struct {
	Revision uint64
	Document []byte
	SHA256   [32]byte
	Replayed bool
}

type Store struct {
	pool *pgxpool.Pool
	pins []edgesignertrust.RootPin
	now  func() time.Time
}

func NewStore(pool *pgxpool.Pool, pins []edgesignertrust.RootPin, now func() time.Time) (*Store, error) {
	if pool == nil || len(pins) == 0 {
		return nil, errors.New("edge signer trust store needs a database and an offline root pin")
	}
	if now == nil {
		now = time.Now
	}
	return &Store{pool: pool, pins: append([]edgesignertrust.RootPin(nil), pins...), now: now}, nil
}

// Accept verifies encoded against the offline root pins and stores it when it
// is the next state: a higher revision that keeps every earlier revocation.
// The same revision with the same bytes is a replay. Every outcome is an
// event; a rejection returns *RejectedError.
func (store *Store) Accept(ctx context.Context, encoded []byte, source string) (Accepted, error) {
	if source != SourceFetch && source != SourceImport {
		return Accepted{}, errors.New("unknown edge signer trust source")
	}
	digest := sha256.Sum256(encoded)
	signed, err := edgesignertrust.Verify(encoded, store.pins)
	if err != nil {
		reason := ReasonInvalid
		if errors.Is(err, edgesignertrust.ErrUntrusted) {
			reason = ReasonUntrusted
		}
		return Accepted{}, store.reject(ctx, reason, 0, digest[:])
	}
	revision := signed.Document.Revision
	var result Accepted
	var rejected string
	err = pgx.BeginFunc(ctx, store.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock($1)", acceptLock); err != nil {
			return err
		}
		latest, found, err := latestTx(ctx, tx)
		if err != nil {
			return err
		}
		now := store.now().UTC()
		if found {
			switch {
			case revision < latest.Revision:
				rejected = ReasonStale
			case revision == latest.Revision && latest.SHA256 != digest:
				rejected = ReasonConflict
			case revision == latest.Revision:
				result = latest
				result.Replayed = true
				return insertEvent(ctx, tx, "replayed", ReasonReplayed, revision, digest[:], now)
			default:
				previous, err := edgesignertrust.Decode(latest.Document)
				if err != nil {
					return fmt.Errorf("stored edge signer trust document is invalid: %w", err)
				}
				for _, revoked := range previous.Document.RevokedKeys {
					if !signed.Document.Revokes(revoked.KeyID, nil) {
						rejected = ReasonDroppedRevocation
					}
				}
			}
			if rejected != "" {
				return insertEvent(ctx, tx, "rejected", rejected, revision, digest[:], now)
			}
		}
		if _, err := tx.Exec(ctx, `INSERT INTO edge_signer_trust_documents(revision,document,document_sha256,
			root_key_id,root_generation,revoked_keys,source,accepted_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8)`,
			int64(revision), encoded, digest[:], signed.Envelope.AuthorityKeyID,
			int64(signed.Envelope.AuthorityKeyGeneration), len(signed.Document.RevokedKeys), source, now); err != nil {
			return err
		}
		result = Accepted{Revision: revision, Document: append([]byte(nil), encoded...), SHA256: digest}
		return insertEvent(ctx, tx, "accepted", ReasonAccepted, revision, digest[:], now)
	})
	if err != nil {
		return Accepted{}, err
	}
	if rejected != "" {
		return Accepted{}, &RejectedError{Reason: rejected}
	}
	return result, nil
}

func (store *Store) reject(ctx context.Context, reason string, revision uint64, digest []byte) error {
	if err := store.RecordEvent(ctx, "rejected", reason, revision, digest); err != nil {
		return err
	}
	return &RejectedError{Reason: reason}
}

// RecordEvent appends an event (fetch outages use "unavailable").
func (store *Store) RecordEvent(ctx context.Context, event, reason string, revision uint64, digest []byte) error {
	return pgx.BeginFunc(ctx, store.pool, func(tx pgx.Tx) error {
		return insertEvent(ctx, tx, event, reason, revision, digest, store.now().UTC())
	})
}

func insertEvent(ctx context.Context, tx pgx.Tx, event, reason string, revision uint64, digest []byte, at time.Time) error {
	var revisionValue, digestValue any
	if revision > 0 {
		revisionValue = int64(revision)
	}
	if len(digest) == sha256.Size {
		digestValue = digest
	}
	_, err := tx.Exec(ctx, `INSERT INTO edge_signer_trust_events(id,event,reason,revision,document_sha256,occurred_at)
		VALUES($1,$2,$3,$4,$5,$6)`, uuid.New(), event, reason, revisionValue, digestValue, at)
	return err
}

// Latest returns the newest accepted document, re-verified against the pins
// so a tampered row is never distributed.
func (store *Store) Latest(ctx context.Context) (Accepted, bool, error) {
	var result Accepted
	var found bool
	err := pgx.BeginTxFunc(ctx, store.pool, pgx.TxOptions{AccessMode: pgx.ReadOnly}, func(tx pgx.Tx) error {
		var err error
		result, found, err = latestTx(ctx, tx)
		return err
	})
	if err != nil || !found {
		return Accepted{}, false, err
	}
	signed, err := edgesignertrust.Verify(result.Document, store.pins)
	if err != nil || signed.Document.Revision != result.Revision || sha256.Sum256(result.Document) != result.SHA256 {
		return Accepted{}, false, fmt.Errorf("stored edge signer trust document does not verify: %w", err)
	}
	return result, true, nil
}

func latestTx(ctx context.Context, tx pgx.Tx) (Accepted, bool, error) {
	var revision int64
	var document, digest []byte
	err := tx.QueryRow(ctx, `SELECT revision,document,document_sha256 FROM edge_signer_trust_documents
		ORDER BY revision DESC LIMIT 1`).Scan(&revision, &document, &digest)
	if errors.Is(err, pgx.ErrNoRows) {
		return Accepted{}, false, nil
	}
	if err != nil || revision <= 0 || len(digest) != sha256.Size {
		return Accepted{}, false, errors.Join(errors.New("read edge signer trust document"), err)
	}
	result := Accepted{Revision: uint64(revision), Document: document}
	copy(result.SHA256[:], digest)
	return result, true, nil
}

// RecordReceipt stores the latest receipt of a node.
func (store *Store) RecordReceipt(ctx context.Context, receipt edgesignertrust.Receipt) error {
	nodeID, err := uuid.Parse(receipt.NodeID)
	if err != nil || !edgesignertrust.ValidReceipt(receipt) {
		return errors.New("invalid edge signer trust receipt")
	}
	reported, err := time.Parse(time.RFC3339, receipt.ReportedAt)
	if err != nil {
		return errors.New("invalid edge signer trust receipt time")
	}
	digest, err := decodeHexDigest(receipt.BundleSHA256)
	if err != nil {
		return err
	}
	_, err = store.pool.Exec(ctx, `INSERT INTO edge_signer_trust_node_state(node_id,bundle_sha256,enforced_revision,
		result,reason,reported_at,recorded_at) SELECT $1,$2,$3,$4,$5,$6,$7 WHERE EXISTS (SELECT 1 FROM nodes WHERE id=$1)
		ON CONFLICT (node_id) DO UPDATE SET bundle_sha256=EXCLUDED.bundle_sha256,
		enforced_revision=EXCLUDED.enforced_revision, result=EXCLUDED.result, reason=EXCLUDED.reason,
		reported_at=EXCLUDED.reported_at, recorded_at=EXCLUDED.recorded_at`,
		nodeID, digest, int64(receipt.Revision), receipt.Result, receipt.Reason, reported, store.now().UTC())
	return err
}

// NodeTrustRevisions returns the signer trust revision each node enforces,
// also after it rejected a later bundle (it keeps the earlier document).
func (store *Store) NodeTrustRevisions(ctx context.Context) (map[string]uint64, error) {
	return store.revisions(ctx, `SELECT node_id,enforced_revision FROM edge_signer_trust_node_state
		WHERE enforced_revision > 0`)
}

// EnforcedRevisions returns the revision each node last reported applied.
func (store *Store) EnforcedRevisions(ctx context.Context) (map[string]uint64, error) {
	return store.revisions(ctx, `SELECT node_id,enforced_revision FROM edge_signer_trust_node_state
		WHERE result='applied'`)
}

func (store *Store) revisions(ctx context.Context, query string) (map[string]uint64, error) {
	rows, err := store.pool.Query(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := map[string]uint64{}
	for rows.Next() {
		var nodeID uuid.UUID
		var revision int64
		if err := rows.Scan(&nodeID, &revision); err != nil {
			return nil, err
		}
		result[nodeID.String()] = uint64(revision)
	}
	return result, rows.Err()
}

func decodeHexDigest(value string) ([]byte, error) {
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != sha256.Size || hex.EncodeToString(decoded) != value {
		return nil, errors.New("invalid bundle digest")
	}
	return decoded, nil
}
