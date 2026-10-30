package acmehttp01

import (
	"context"
	"errors"
	"fmt"
	"strings"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/cdnca/cdnca/services/control-api/internal/acmeedge"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nats-io/nats.go"
	"google.golang.org/protobuf/proto"
)

type StatusConsumer struct {
	pool         *pgxpool.Pool
	overlay      *acmeedge.Service
	subscription *nats.Subscription
	config       StatusConfig
}

func NewStatusConsumer(pool *pgxpool.Pool, overlay *acmeedge.Service, connection *nats.Conn, config StatusConfig) (*StatusConsumer, error) {
	if pool == nil || overlay == nil || connection == nil || connection.IsClosed() ||
		!validNATSName(config.Stream) || !validNATSName(config.Durable) || !validSubjectPrefix(config.SubjectPrefix) ||
		config.AckWait <= 3*config.OperationTimeout || config.FetchTimeout <= 0 || config.OperationTimeout <= 0 ||
		config.NakDelay <= 0 || config.MaxAckPending <= 0 || config.MaxWaiting <= 0 || config.MaxBytes <= 0 {
		return nil, ErrInvalidConfig
	}
	jetstream, err := connection.JetStream(nats.MaxWait(config.OperationTimeout))
	if err != nil {
		return nil, ErrInvalidConfig
	}
	operationCtx, cancel := context.WithTimeout(context.Background(), config.OperationTimeout)
	info, err := jetstream.ConsumerInfo(config.Stream, config.Durable, nats.Context(operationCtx))
	cancel()
	if err != nil || !sameOverlayStatusConsumer(info, config) {
		return nil, ErrInvalidConfig
	}
	subscription, err := jetstream.PullSubscribe(config.SubjectPrefix+".*", config.Durable, nats.Bind(config.Stream, config.Durable))
	if err != nil {
		return nil, ErrInvalidConfig
	}
	return &StatusConsumer{pool: pool, overlay: overlay, subscription: subscription, config: config}, nil
}

func (c *StatusConsumer) Run(ctx context.Context) error {
	if ctx == nil {
		return ErrInvalidConfig
	}
	for {
		fetchCtx, cancel := context.WithTimeout(ctx, c.config.FetchTimeout)
		messages, err := c.subscription.Fetch(1, nats.Context(fetchCtx))
		cancel()
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, nats.ErrTimeout) {
				continue
			}
			return err
		}
		if len(messages) != 1 {
			return fmt.Errorf("overlay status consumer returned an unexpected batch")
		}
		if err := c.process(ctx, messages[0]); err != nil && ctx.Err() != nil {
			return ctx.Err()
		}
	}
}

func (c *StatusConsumer) process(ctx context.Context, message *nats.Msg) error {
	status, nodeID, err := c.decode(message)
	if err != nil {
		return c.term(message)
	}
	if err := c.validateBinding(ctx, nodeID, status); err != nil {
		if errors.Is(err, ErrArtifactBinding) {
			return c.term(message)
		}
		return c.nak(message)
	}
	receiptState, failureCode, record := mapOverlayReceipt(status)
	if record {
		receiptID, _ := canonicalUUID(status.Event.EventId)
		deploymentID, _ := canonicalUUID(status.OverlayDeploymentId)
		operationCtx, cancel := context.WithTimeout(ctx, c.config.OperationTimeout)
		_, err = c.overlay.RecordReceipt(operationCtx, acmeedge.Receipt{
			DeploymentID: deploymentID, DeploymentAttempt: int(status.Attempt), ReceiptID: receiptID,
			State: receiptState, FailureCode: failureCode, OccurredAt: status.Event.OccurredTime.AsTime(),
		})
		cancel()
		if err != nil {
			if errors.Is(err, acmeedge.ErrInvalidInput) || errors.Is(err, acmeedge.ErrReceiptConflict) ||
				errors.Is(err, acmeedge.ErrInvalidTransition) || errors.Is(err, acmeedge.ErrStaleAttempt) ||
				errors.Is(err, acmeedge.ErrNotFound) {
				return c.term(message)
			}
			return c.nak(message)
		}
	}
	operationCtx, cancel := context.WithTimeout(context.Background(), c.config.OperationTimeout)
	err = message.AckSync(nats.Context(operationCtx))
	cancel()
	return err
}

func (c *StatusConsumer) decode(message *nats.Msg) (*agentv1.AcmeHTTP01OverlayStatus, uuid.UUID, error) {
	return decodeOverlayStatus(message, c.config)
}

// decodeOverlayStatus strictly decodes one agent overlay status and the node
// id its subject carries.
func decodeOverlayStatus(message *nats.Msg, config StatusConfig) (*agentv1.AcmeHTTP01OverlayStatus, uuid.UUID, error) {
	if message == nil || len(message.Data) == 0 || len(message.Data) > config.MaxBytes {
		return nil, uuid.Nil, ErrArtifactBinding
	}
	prefix := config.SubjectPrefix + "."
	if !strings.HasPrefix(message.Subject, prefix) {
		return nil, uuid.Nil, ErrArtifactBinding
	}
	nodeID, err := canonicalUUID(strings.TrimPrefix(message.Subject, prefix))
	if err != nil {
		return nil, uuid.Nil, ErrArtifactBinding
	}
	value := new(agentv1.AcmeHTTP01OverlayStatus)
	if err := (proto.UnmarshalOptions{DiscardUnknown: false}).Unmarshal(message.Data, value); err != nil ||
		len(value.ProtoReflect().GetUnknown()) != 0 || value.Event == nil || value.Event.OccurredTime == nil ||
		value.Event.OccurredTime.CheckValid() != nil || value.Attempt == 0 || value.OverlayRevision == 0 ||
		value.TransitionSequence == 0 || value.ResultCode == agentv1.AcmeHTTP01OverlayResultCode_ACME_HTTP01_OVERLAY_RESULT_CODE_UNSPECIFIED {
		return nil, uuid.Nil, ErrArtifactBinding
	}
	if _, err := canonicalUUID(value.Event.EventId); err != nil {
		return nil, uuid.Nil, ErrArtifactBinding
	}
	if _, err := canonicalUUID(value.Event.RequestId); err != nil {
		return nil, uuid.Nil, ErrArtifactBinding
	}
	if _, err := canonicalUUID(value.OverlayDeploymentId); err != nil {
		return nil, uuid.Nil, ErrArtifactBinding
	}
	if _, err := canonicalUUID(value.OverlayVersionId); err != nil {
		return nil, uuid.Nil, ErrArtifactBinding
	}
	if value.Event.CausationId == nil {
		return nil, uuid.Nil, ErrArtifactBinding
	}
	if _, err := canonicalUUID(value.Event.GetCausationId()); err != nil {
		return nil, uuid.Nil, ErrArtifactBinding
	}
	if _, known := agentv1.AcmeHTTP01OverlayState_name[int32(value.State)]; !known ||
		value.State == agentv1.AcmeHTTP01OverlayState_ACME_HTTP01_OVERLAY_STATE_UNSPECIFIED {
		return nil, uuid.Nil, ErrArtifactBinding
	}
	if _, known := agentv1.AcmeHTTP01OverlayResultCode_name[int32(value.ResultCode)]; !known {
		return nil, uuid.Nil, ErrArtifactBinding
	}
	if !validOverlayStateResult(value.State, value.ResultCode) {
		return nil, uuid.Nil, ErrArtifactBinding
	}
	if !validOverlayErrorPresence(value.State, value.Error != nil) {
		return nil, uuid.Nil, ErrArtifactBinding
	}
	return value, nodeID, nil
}

func validOverlayErrorPresence(state agentv1.AcmeHTTP01OverlayState, hasError bool) bool {
	switch state {
	case agentv1.AcmeHTTP01OverlayState_ACME_HTTP01_OVERLAY_STATE_DELIVERED,
		agentv1.AcmeHTTP01OverlayState_ACME_HTTP01_OVERLAY_STATE_STAGED,
		agentv1.AcmeHTTP01OverlayState_ACME_HTTP01_OVERLAY_STATE_PRECHECKED,
		agentv1.AcmeHTTP01OverlayState_ACME_HTTP01_OVERLAY_STATE_ACTIVATED,
		agentv1.AcmeHTTP01OverlayState_ACME_HTTP01_OVERLAY_STATE_HEALTHY:
		return !hasError
	case agentv1.AcmeHTTP01OverlayState_ACME_HTTP01_OVERLAY_STATE_FAILED,
		agentv1.AcmeHTTP01OverlayState_ACME_HTTP01_OVERLAY_STATE_ROLLBACK_FAILED:
		return hasError
	case agentv1.AcmeHTTP01OverlayState_ACME_HTTP01_OVERLAY_STATE_REVERTING,
		agentv1.AcmeHTTP01OverlayState_ACME_HTTP01_OVERLAY_STATE_REVERTED:
		return true
	default:
		return false
	}
}

func validOverlayStateResult(state agentv1.AcmeHTTP01OverlayState, result agentv1.AcmeHTTP01OverlayResultCode) bool {
	switch state {
	case agentv1.AcmeHTTP01OverlayState_ACME_HTTP01_OVERLAY_STATE_DELIVERED,
		agentv1.AcmeHTTP01OverlayState_ACME_HTTP01_OVERLAY_STATE_STAGED,
		agentv1.AcmeHTTP01OverlayState_ACME_HTTP01_OVERLAY_STATE_PRECHECKED,
		agentv1.AcmeHTTP01OverlayState_ACME_HTTP01_OVERLAY_STATE_ACTIVATED,
		agentv1.AcmeHTTP01OverlayState_ACME_HTTP01_OVERLAY_STATE_HEALTHY:
		return result == agentv1.AcmeHTTP01OverlayResultCode_ACME_HTTP01_OVERLAY_RESULT_CODE_OK
	case agentv1.AcmeHTTP01OverlayState_ACME_HTTP01_OVERLAY_STATE_REVERTING:
		return result == agentv1.AcmeHTTP01OverlayResultCode_ACME_HTTP01_OVERLAY_RESULT_CODE_HEALTH_FAILED
	case agentv1.AcmeHTTP01OverlayState_ACME_HTTP01_OVERLAY_STATE_REVERTED:
		return result == agentv1.AcmeHTTP01OverlayResultCode_ACME_HTTP01_OVERLAY_RESULT_CODE_ROLLED_BACK
	case agentv1.AcmeHTTP01OverlayState_ACME_HTTP01_OVERLAY_STATE_ROLLBACK_FAILED:
		return result == agentv1.AcmeHTTP01OverlayResultCode_ACME_HTTP01_OVERLAY_RESULT_CODE_ROLLBACK_FAILED
	case agentv1.AcmeHTTP01OverlayState_ACME_HTTP01_OVERLAY_STATE_FAILED:
		return result != agentv1.AcmeHTTP01OverlayResultCode_ACME_HTTP01_OVERLAY_RESULT_CODE_UNSPECIFIED &&
			result != agentv1.AcmeHTTP01OverlayResultCode_ACME_HTTP01_OVERLAY_RESULT_CODE_OK &&
			result != agentv1.AcmeHTTP01OverlayResultCode_ACME_HTTP01_OVERLAY_RESULT_CODE_ROLLED_BACK &&
			result != agentv1.AcmeHTTP01OverlayResultCode_ACME_HTTP01_OVERLAY_RESULT_CODE_ROLLBACK_FAILED
	default:
		return false
	}
}

func (c *StatusConsumer) validateBinding(ctx context.Context, nodeID uuid.UUID, status *agentv1.AcmeHTTP01OverlayStatus) error {
	deploymentID, _ := canonicalUUID(status.OverlayDeploymentId)
	var storedNodeID, versionID, publicationID, requestID uuid.UUID
	var revision int64
	err := c.pool.QueryRow(ctx, `
		SELECT deployment.node_id,deployment.version_id,deployment.revision,
		       publication.id,publication.request_id
		FROM acme_http01_overlay_deployments deployment
		JOIN acme_http01_overlay_versions version ON version.id=deployment.version_id
		JOIN acme_http01_overlay_publications publication ON publication.id=version.publication_id
		WHERE deployment.id=$1 AND deployment.attempt=$2`, deploymentID, status.Attempt).Scan(
		&storedNodeID, &versionID, &revision, &publicationID, &requestID,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrArtifactBinding
	}
	if err != nil {
		return err
	}
	if storedNodeID != nodeID || versionID.String() != status.OverlayVersionId || revision != int64(status.OverlayRevision) ||
		requestID.String() != status.Event.RequestId || publicationID.String() != status.Event.CorrelationId ||
		overlayCommandEventID(deploymentID, int(status.Attempt)).String() != status.Event.GetCausationId() {
		return ErrArtifactBinding
	}
	if status.State == agentv1.AcmeHTTP01OverlayState_ACME_HTTP01_OVERLAY_STATE_ACTIVATED ||
		status.State == agentv1.AcmeHTTP01OverlayState_ACME_HTTP01_OVERLAY_STATE_HEALTHY {
		if status.ActiveOverlayVersionId == nil || status.GetActiveOverlayVersionId() != status.OverlayVersionId ||
			status.ActiveOverlayRevision != status.OverlayRevision || status.ActiveOverlayUnchanged {
			return ErrArtifactBinding
		}
	}
	return nil
}

func mapOverlayReceipt(status *agentv1.AcmeHTTP01OverlayStatus) (string, string, bool) {
	switch status.State {
	case agentv1.AcmeHTTP01OverlayState_ACME_HTTP01_OVERLAY_STATE_ACTIVATED:
		return acmeedge.DeploymentApplied, "", true
	case agentv1.AcmeHTTP01OverlayState_ACME_HTTP01_OVERLAY_STATE_HEALTHY:
		return acmeedge.DeploymentHealthy, "", true
	case agentv1.AcmeHTTP01OverlayState_ACME_HTTP01_OVERLAY_STATE_FAILED,
		agentv1.AcmeHTTP01OverlayState_ACME_HTTP01_OVERLAY_STATE_REVERTED,
		agentv1.AcmeHTTP01OverlayState_ACME_HTTP01_OVERLAY_STATE_ROLLBACK_FAILED:
		return acmeedge.DeploymentFailed, overlayFailureCode(status.ResultCode), true
	default:
		return "", "", false
	}
}

func overlayFailureCode(code agentv1.AcmeHTTP01OverlayResultCode) string {
	switch code {
	case agentv1.AcmeHTTP01OverlayResultCode_ACME_HTTP01_OVERLAY_RESULT_CODE_INVALID_ARTIFACT:
		return "invalid_artifact"
	case agentv1.AcmeHTTP01OverlayResultCode_ACME_HTTP01_OVERLAY_RESULT_CODE_EXPIRED:
		return "expired"
	case agentv1.AcmeHTTP01OverlayResultCode_ACME_HTTP01_OVERLAY_RESULT_CODE_CONFLICT:
		return "conflict"
	case agentv1.AcmeHTTP01OverlayResultCode_ACME_HTTP01_OVERLAY_RESULT_CODE_STALE_ATTEMPT:
		return "stale_attempt"
	case agentv1.AcmeHTTP01OverlayResultCode_ACME_HTTP01_OVERLAY_RESULT_CODE_PRECHECK_FAILED:
		return "precheck_failed"
	case agentv1.AcmeHTTP01OverlayResultCode_ACME_HTTP01_OVERLAY_RESULT_CODE_ACTIVATION_FAILED:
		return "activation_failed"
	case agentv1.AcmeHTTP01OverlayResultCode_ACME_HTTP01_OVERLAY_RESULT_CODE_HEALTH_FAILED:
		return "health_failed"
	case agentv1.AcmeHTTP01OverlayResultCode_ACME_HTTP01_OVERLAY_RESULT_CODE_ROLLED_BACK:
		return "rolled_back"
	case agentv1.AcmeHTTP01OverlayResultCode_ACME_HTTP01_OVERLAY_RESULT_CODE_ROLLBACK_FAILED:
		return "rollback_failed"
	case agentv1.AcmeHTTP01OverlayResultCode_ACME_HTTP01_OVERLAY_RESULT_CODE_UNSUPPORTED:
		return "unsupported"
	default:
		return "overlay_failed"
	}
}

func (c *StatusConsumer) nak(message *nats.Msg) error {
	ctx, cancel := context.WithTimeout(context.Background(), c.config.OperationTimeout)
	defer cancel()
	return message.NakWithDelay(c.config.NakDelay, nats.Context(ctx))
}

func (c *StatusConsumer) term(message *nats.Msg) error {
	ctx, cancel := context.WithTimeout(context.Background(), c.config.OperationTimeout)
	defer cancel()
	return message.Term(nats.Context(ctx))
}

func (c *StatusConsumer) Close() error {
	if c == nil || c.subscription == nil {
		return nil
	}
	return c.subscription.Unsubscribe()
}

func sameOverlayStatusConsumer(info *nats.ConsumerInfo, expected StatusConfig) bool {
	if info == nil {
		return false
	}
	actual := info.Config
	return actual.Durable == expected.Durable && actual.FilterSubject == expected.SubjectPrefix+".*" &&
		actual.DeliverPolicy == nats.DeliverAllPolicy && actual.AckPolicy == nats.AckExplicitPolicy &&
		actual.AckWait == expected.AckWait && actual.MaxDeliver == -1 && actual.ReplayPolicy == nats.ReplayInstantPolicy &&
		actual.MaxAckPending == expected.MaxAckPending && actual.MaxWaiting == expected.MaxWaiting &&
		actual.MaxRequestBatch == 1 && actual.MaxRequestExpires == expected.FetchTimeout
}
