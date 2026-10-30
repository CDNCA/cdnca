package nodeporttransition

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const portTransitionCommandSubjectPrefix = "cdnca.agent.commands.gateway-port"

type PostgresStore struct {
	pool *pgxpool.Pool
	now  func() time.Time
}

func NewPostgresStore(pool *pgxpool.Pool, now func() time.Time) *PostgresStore {
	return &PostgresStore{pool: pool, now: now}
}

func (s *PostgresStore) Create(ctx context.Context, value Transition, digest [32]byte) (Transition, error) {
	if s == nil || s.pool == nil || s.now == nil || ctx == nil {
		return Transition{}, ErrInvalidInput
	}
	for attempt := 0; attempt < 3; attempt++ {
		result, err := s.createAttempt(ctx, value, digest)
		if err == nil {
			return result, nil
		}
		if ctx.Err() != nil {
			return Transition{}, ctx.Err()
		}
		var databaseError *pgconn.PgError
		if !errors.As(err, &databaseError) {
			return Transition{}, err
		}
		switch databaseError.Code {
		case "40001":
		case "23505":
			return Transition{}, ErrConflict
		default:
			return Transition{}, err
		}
	}
	return Transition{}, ErrConflict
}

func (s *PostgresStore) createAttempt(ctx context.Context, value Transition, digest [32]byte) (Transition, error) {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return Transition{}, err
	}
	defer tx.Rollback(ctx)

	var existingID uuid.UUID
	var existingDigest []byte
	err = tx.QueryRow(ctx, `SELECT id,request_sha256 FROM node_gateway_port_transitions
		WHERE scope_id=$1 AND idempotency_key=$2 FOR UPDATE`, value.ScopeID, value.IdempotencyKey).Scan(&existingID, &existingDigest)
	if err == nil {
		if string(existingDigest) != string(digest[:]) {
			return Transition{}, ErrConflict
		}
		result, loadErr := getTransition(ctx, tx, existingID)
		if loadErr != nil {
			return Transition{}, loadErr
		}
		if err := tx.Commit(ctx); err != nil {
			return Transition{}, err
		}
		return result, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return Transition{}, err
	}

	var scopeID uuid.UUID
	var nodeRevision int64
	var certificateSHA string
	err = tx.QueryRow(ctx, `SELECT n.scope_id,n.revision,encode(c.leaf_der_sha256,'hex')
		FROM nodes n JOIN node_certificates c ON c.node_id=n.id
		WHERE n.id=$1 AND c.status='active' AND c.rotation_status='current'
		FOR UPDATE OF n,c`, value.NodeID).Scan(&scopeID, &nodeRevision, &certificateSHA)
	if errors.Is(err, pgx.ErrNoRows) {
		return Transition{}, ErrNotFound
	}
	if err != nil {
		return Transition{}, err
	}
	if scopeID != value.ScopeID || nodeRevision != value.ExpectedNodeRevision {
		return Transition{}, ErrConflict
	}
	if value.CertificateSHA256 != "" && value.CertificateSHA256 != certificateSHA {
		return Transition{}, ErrUnauthenticated
	}
	value.CertificateSHA256 = certificateSHA
	if err := tx.QueryRow(ctx, `SELECT COALESCE(max(revision),0)+1 FROM node_gateway_port_transitions WHERE node_id=$1`, value.NodeID).Scan(&value.Revision); err != nil {
		return Transition{}, err
	}
	value.CreatedAt = s.now().UTC()
	if value.CompatibilityDeadline.Before(value.CreatedAt.Add(minimumCompatibilityWindow)) ||
		value.CompatibilityDeadline.After(value.CreatedAt.Add(maximumCompatibilityWindow)) ||
		value.RollbackDeadline.After(value.CreatedAt.Add(maximumRollbackWindow)) {
		return Transition{}, ErrInvalidInput
	}
	value.UpdatedAt = value.CreatedAt
	_, err = tx.Exec(ctx, `INSERT INTO node_gateway_port_transitions(
		id,scope_id,node_id,revision,expected_node_revision,old_endpoint,new_endpoint,server_name,
		old_listen_address,new_listen_address,compatibility_deadline,rollback_deadline,certificate_sha256,
		state,status_revision,active_endpoint,error_code,request_id,idempotency_key,request_sha256,
		created_by_user_id,created_at,updated_at)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,0,$6,'',$15,$16,$17,$18,$19,$19)`,
		value.ID, value.ScopeID, value.NodeID, value.Revision, value.ExpectedNodeRevision, value.OldEndpoint.Address,
		value.NewEndpoint.Address, value.OldEndpoint.ServerName, value.OldEndpoint.ListenAddress, value.NewEndpoint.ListenAddress,
		value.CompatibilityDeadline, value.RollbackDeadline, value.CertificateSHA256, value.State, value.RequestID,
		value.IdempotencyKey, digest[:], value.CreatedByUserID, value.CreatedAt)
	if err != nil {
		return Transition{}, err
	}
	if err := insertCommandOutbox(ctx, tx, value, ActionSwitch, value.RequestID, value.IdempotencyKey, value.CreatedAt); err != nil {
		return Transition{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return Transition{}, err
	}
	return value, nil
}

func (s *PostgresStore) EnqueueAction(ctx context.Context, actor Actor, request ActionRequest, action CommandAction) (Transition, error) {
	if s == nil || s.pool == nil || s.now == nil || ctx == nil || actor.ScopeID == uuid.Nil || actor.UserID == uuid.Nil ||
		request.TransitionID == uuid.Nil || request.NodeID == uuid.Nil || action != ActionFinalize && action != ActionRollback {
		return Transition{}, ErrInvalidInput
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return Transition{}, err
	}
	defer tx.Rollback(ctx)
	current, err := getTransitionForUpdate(ctx, tx, request.TransitionID)
	if err != nil {
		return Transition{}, err
	}
	if current.ScopeID != actor.ScopeID || current.NodeID != request.NodeID {
		return Transition{}, ErrNotFound
	}
	var existingRequestID, existingKey string
	err = tx.QueryRow(ctx, `SELECT request_id,idempotency_key FROM node_gateway_port_transition_command_outbox
		WHERE transition_id=$1 AND action=$2`, current.ID, action).Scan(&existingRequestID, &existingKey)
	if err == nil {
		if existingRequestID != request.RequestID || existingKey != request.IdempotencyKey {
			return Transition{}, ErrConflict
		}
		if err := tx.Commit(ctx); err != nil {
			return Transition{}, err
		}
		return current, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return Transition{}, err
	}
	now := s.now().UTC()
	if action == ActionFinalize && current.State != StateSwitched ||
		action == ActionRollback && current.State != StateSwitching && current.State != StateSwitched && current.State != StateFailed ||
		now.After(current.RollbackDeadline) {
		return Transition{}, ErrConflict
	}
	if err := insertCommandOutbox(ctx, tx, current, action, request.RequestID, request.IdempotencyKey, now); err != nil {
		return Transition{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return Transition{}, err
	}
	return current, nil
}

func insertCommandOutbox(ctx context.Context, tx pgx.Tx, transition Transition, action CommandAction, requestID, key string, createdAt time.Time) error {
	eventID := uuid.NewSHA1(transition.ID, []byte("gateway-port-transition-command\x00"+string(action)))
	taskID := transition.ID.String()
	command := &agentv1.GatewayPortTransitionCommand{
		Event: &commonv1.EventMetadata{
			EventId: eventID.String(), RequestId: requestID, OccurredTime: timestamppb.New(createdAt.UTC()),
			CorrelationId: transition.ID.String(), TaskId: &taskID,
		},
		Schema:       agentv1.GatewayPortTransitionSchema_GATEWAY_PORT_TRANSITION_SCHEMA_V1,
		TransitionId: transition.ID.String(), NodeId: transition.NodeID.String(), Revision: transition.Revision,
		ExpectedNodeRevision: uint64(transition.ExpectedNodeRevision),
		OldEndpoint: &agentv1.GatewayEndpoint{Address: transition.OldEndpoint.Address, ServerName: transition.OldEndpoint.ServerName,
			ListenAddress: transition.OldEndpoint.ListenAddress},
		NewEndpoint: &agentv1.GatewayEndpoint{Address: transition.NewEndpoint.Address, ServerName: transition.NewEndpoint.ServerName,
			ListenAddress: transition.NewEndpoint.ListenAddress},
		CompatibilityDeadline: timestamppb.New(transition.CompatibilityDeadline), RollbackDeadline: timestamppb.New(transition.RollbackDeadline),
		CertificateSha256: transition.CertificateSHA256,
	}
	switch action {
	case ActionSwitch:
		command.Action = agentv1.GatewayPortTransitionAction_GATEWAY_PORT_TRANSITION_ACTION_SWITCH
	case ActionFinalize:
		command.Action = agentv1.GatewayPortTransitionAction_GATEWAY_PORT_TRANSITION_ACTION_FINALIZE
	case ActionRollback:
		command.Action = agentv1.GatewayPortTransitionAction_GATEWAY_PORT_TRANSITION_ACTION_ROLLBACK
	default:
		return ErrInvalidInput
	}
	payload, err := proto.MarshalOptions{Deterministic: true}.Marshal(command)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(payload)
	messageID := "node-port-transition-v1-" + eventID.String()
	_, err = tx.Exec(ctx, `INSERT INTO node_gateway_port_transition_command_outbox(
		id,event_id,transition_id,node_id,revision,action,subject,message_id,payload,payload_sha256,
		request_id,idempotency_key,state,created_at,updated_at)
		VALUES($1,$1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,'pending',$12,$12)`, eventID, transition.ID,
		transition.NodeID, transition.Revision, action, portTransitionCommandSubjectPrefix+"."+transition.NodeID.String(),
		messageID, payload, digest[:], requestID, key, createdAt.UTC())
	return err
}

func (s *PostgresStore) ClaimCommands(ctx context.Context, workerID uuid.UUID, limit int, lease time.Duration) ([]CommandOutbox, error) {
	if s == nil || s.pool == nil || s.now == nil || ctx == nil || workerID == uuid.Nil || limit < 1 || limit > 128 || lease <= 0 {
		return nil, ErrInvalidInput
	}
	rows, err := s.pool.Query(ctx, `WITH candidates AS (
		SELECT id FROM node_gateway_port_transition_command_outbox
		WHERE (state='pending' AND next_attempt_at<=$1) OR (state='publishing' AND claimed_until<=$1)
		ORDER BY created_at,id FOR UPDATE SKIP LOCKED LIMIT $2
	) UPDATE node_gateway_port_transition_command_outbox o
		SET state='publishing',claim_token=$3,claimed_until=$4,attempt_count=attempt_count+1,updated_at=$1
		FROM candidates WHERE o.id=candidates.id
		RETURNING o.id,o.transition_id,o.node_id,o.action,o.subject,o.message_id,o.payload,o.claim_token`,
		s.now().UTC(), limit, workerID, s.now().UTC().Add(lease))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var commands []CommandOutbox
	for rows.Next() {
		var command CommandOutbox
		if err := rows.Scan(&command.ID, &command.TransitionID, &command.NodeID, &command.Action, &command.Subject,
			&command.MessageID, &command.Payload, &command.ClaimToken); err != nil {
			return nil, err
		}
		commands = append(commands, command)
	}
	return commands, rows.Err()
}

func (s *PostgresStore) MarkCommandPublished(ctx context.Context, command CommandOutbox, stream string, sequence uint64) error {
	if s == nil || s.pool == nil || s.now == nil || ctx == nil || command.ID == uuid.Nil || command.ClaimToken == uuid.Nil ||
		stream == "" || sequence == 0 {
		return ErrInvalidInput
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	commandSHA := sha256.Sum256(command.Payload)
	tag, err := tx.Exec(ctx, `UPDATE node_gateway_port_transition_command_outbox SET state='published',
		puback_stream=$3,puback_sequence=$4,published_at=$5,claim_token=NULL,claimed_until=NULL,updated_at=$5
		WHERE id=$1 AND claim_token=$2 AND state='publishing' AND payload_sha256=$6`, command.ID, command.ClaimToken,
		stream, sequence, s.now().UTC(), commandSHA[:])
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return ErrConflict
	}
	if command.Action == ActionSwitch {
		tag, err = tx.Exec(ctx, `UPDATE node_gateway_port_transitions SET state='switching',updated_at=$2
			WHERE id=$1 AND state='preparing'`, command.TransitionID, s.now().UTC())
		if err == nil && tag.RowsAffected() != 1 {
			err = ErrConflict
		}
	}
	if err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *PostgresStore) ReleaseCommand(ctx context.Context, command CommandOutbox, retryAt time.Time, errorCode string) error {
	if s == nil || s.pool == nil || ctx == nil || command.ID == uuid.Nil || command.ClaimToken == uuid.Nil ||
		retryAt.IsZero() || !validErrorCode(errorCode) || errorCode == "" {
		return ErrInvalidInput
	}
	tag, err := s.pool.Exec(ctx, `UPDATE node_gateway_port_transition_command_outbox SET state='pending',
		claim_token=NULL,claimed_until=NULL,next_attempt_at=$3,last_error_code=$4,updated_at=$5
		WHERE id=$1 AND claim_token=$2 AND state='publishing'`, command.ID, command.ClaimToken, retryAt.UTC(), errorCode, s.now().UTC())
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return ErrConflict
	}
	return nil
}

func (s *PostgresStore) Get(ctx context.Context, id uuid.UUID) (Transition, error) {
	if s == nil || s.pool == nil || ctx == nil || id == uuid.Nil {
		return Transition{}, ErrInvalidInput
	}
	return getTransition(ctx, s.pool, id)
}

func (s *PostgresStore) ApplyStatus(ctx context.Context, report StatusReport) (Transition, error) {
	if s == nil || s.pool == nil || s.now == nil || ctx == nil || report.EventID == uuid.Nil || report.PubAckStream == "" || report.PubAckSequence == 0 || len(report.PayloadSHA256) != sha256.Size {
		return Transition{}, ErrInvalidInput
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return Transition{}, err
	}
	defer tx.Rollback(ctx)
	current, err := getTransitionForUpdate(ctx, tx, report.TransitionID)
	if err != nil {
		return Transition{}, err
	}
	if current.NodeID != report.NodeID || current.Revision != report.Revision || current.CertificateSHA256 != report.CertificateSHA256 {
		return Transition{}, ErrConflict
	}
	if report.StatusRevision <= current.StatusRevision {
		var payloadSHA []byte
		var eventID uuid.UUID
		var stream string
		err := tx.QueryRow(ctx, `SELECT payload_sha256,event_id,puback_stream
			FROM node_gateway_port_transition_status_events
			WHERE transition_id=$1 AND node_id=$2 AND revision=$3 AND status_revision=$4`,
			report.TransitionID, report.NodeID, report.Revision, report.StatusRevision).Scan(&payloadSHA, &eventID, &stream)
		if errors.Is(err, pgx.ErrNoRows) || err == nil && (len(payloadSHA) != sha256.Size ||
			!bytes.Equal(payloadSHA, report.PayloadSHA256) || eventID != report.EventID || stream != report.PubAckStream) {
			return Transition{}, ErrConflict
		}
		if err != nil {
			return Transition{}, err
		}
		// A byte-identical republish may have another stream sequence. Keep the first receipt
		// and return the latest projection without replaying its state transition.
		if err := tx.Commit(ctx); err != nil {
			return Transition{}, err
		}
		return current, nil
	}
	if !validTransition(current.State, report.State) {
		return Transition{}, ErrConflict
	}
	observed := report.ObservedAt.UTC()
	if observed.IsZero() {
		observed = s.now().UTC()
	}
	_, err = tx.Exec(ctx, `INSERT INTO node_gateway_port_transition_status_events(
		id,transition_id,node_id,revision,status_revision,state,active_endpoint,certificate_sha256,error_code,
		event_id,puback_stream,puback_sequence,observed_at,payload_sha256)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`, uuid.New(), report.TransitionID,
		report.NodeID, report.Revision, report.StatusRevision, report.State, report.ActiveEndpoint.Address,
		report.CertificateSHA256, report.ErrorCode, report.EventID, report.PubAckStream, report.PubAckSequence, observed, report.PayloadSHA256)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return Transition{}, ErrConflict
		}
		return Transition{}, err
	}
	_, err = tx.Exec(ctx, `UPDATE node_gateway_port_transitions SET state=$2,status_revision=$3,
		active_endpoint=$4,error_code=$5,updated_at=$6 WHERE id=$1`, report.TransitionID, report.State,
		report.StatusRevision, report.ActiveEndpoint.Address, report.ErrorCode, s.now().UTC())
	if err != nil {
		return Transition{}, err
	}
	result, err := getTransition(ctx, tx, report.TransitionID)
	if err != nil {
		return Transition{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return Transition{}, err
	}
	return result, nil
}

type transitionQuerier interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

func getTransition(ctx context.Context, query transitionQuerier, id uuid.UUID) (Transition, error) {
	return scanTransition(query.QueryRow(ctx, transitionSelect+` WHERE id=$1`, id))
}

func getTransitionForUpdate(ctx context.Context, query transitionQuerier, id uuid.UUID) (Transition, error) {
	return scanTransition(query.QueryRow(ctx, transitionSelect+` WHERE id=$1 FOR UPDATE`, id))
}

const transitionSelect = `SELECT id,scope_id,node_id,revision,expected_node_revision,old_endpoint,new_endpoint,
	server_name,old_listen_address,new_listen_address,compatibility_deadline,rollback_deadline,certificate_sha256,state,status_revision,active_endpoint,error_code,
	request_id,idempotency_key,created_by_user_id,created_at,updated_at FROM node_gateway_port_transitions`

func scanTransition(row pgx.Row) (Transition, error) {
	var value Transition
	var oldAddress, newAddress, serverName, oldListenAddress, newListenAddress, activeAddress string
	err := row.Scan(&value.ID, &value.ScopeID, &value.NodeID, &value.Revision, &value.ExpectedNodeRevision,
		&oldAddress, &newAddress, &serverName, &oldListenAddress, &newListenAddress, &value.CompatibilityDeadline, &value.RollbackDeadline, &value.CertificateSHA256,
		&value.State, &value.StatusRevision, &activeAddress, &value.ErrorCode, &value.RequestID, &value.IdempotencyKey, &value.CreatedByUserID,
		&value.CreatedAt, &value.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Transition{}, ErrNotFound
	}
	if err != nil {
		return Transition{}, err
	}
	value.OldEndpoint = Endpoint{Address: oldAddress, ServerName: serverName, ListenAddress: oldListenAddress}
	value.NewEndpoint = Endpoint{Address: newAddress, ServerName: serverName, ListenAddress: newListenAddress}
	value.ActiveEndpoint = value.OldEndpoint
	if activeAddress == newAddress {
		value.ActiveEndpoint = value.NewEndpoint
	}
	return value, nil
}

var _ Store = (*PostgresStore)(nil)
