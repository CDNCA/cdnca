package acmehttp01

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/acmeedge"
	"github.com/nats-io/nats.go"
	"google.golang.org/protobuf/proto"
)

type Dispatcher struct {
	overlay   *acmeedge.Service
	artifacts *ArtifactStore
	jetstream nats.JetStreamContext
	config    DispatcherConfig
}

func NewDispatcher(overlay *acmeedge.Service, artifacts *ArtifactStore, connection *nats.Conn, config DispatcherConfig) (*Dispatcher, error) {
	if overlay == nil || artifacts == nil || connection == nil || connection.IsClosed() || config.Clock == nil ||
		!validNATSName(config.Stream) || config.BatchSize < 1 || config.BatchSize > 256 ||
		config.LeaseDuration < time.Second || config.LeaseDuration > 5*time.Minute ||
		config.PollInterval <= 0 || config.OperationTimeout <= 0 || config.RetryDelay <= 0 ||
		config.AttemptTimeout <= 0 || config.AttemptTimeout > time.Hour ||
		config.LeaseDuration <= 3*config.OperationTimeout {
		return nil, ErrInvalidConfig
	}
	jetstream, err := connection.JetStream(nats.MaxWait(config.OperationTimeout))
	if err != nil {
		return nil, ErrInvalidConfig
	}
	return &Dispatcher{overlay: overlay, artifacts: artifacts, jetstream: jetstream, config: config}, nil
}

func (d *Dispatcher) PublishBatch(ctx context.Context) (int, error) {
	if ctx == nil {
		return 0, ErrInvalidConfig
	}
	reconcileCtx, reconcileCancel := context.WithTimeout(ctx, d.config.OperationTimeout)
	_, err := d.overlay.ReconcileDeployments(reconcileCtx, acmeedge.ReconcileRequest{
		Now: d.config.Clock(), AttemptTimeout: d.config.AttemptTimeout, Limit: d.config.BatchSize,
	})
	reconcileCancel()
	if err != nil {
		return 0, err
	}
	claimCtx, cancel := context.WithTimeout(ctx, d.config.OperationTimeout)
	deliveries, err := d.overlay.ClaimDeliveries(claimCtx, acmeedge.ClaimRequest{
		Limit: d.config.BatchSize, LeaseDuration: d.config.LeaseDuration,
	})
	cancel()
	if err != nil {
		return 0, err
	}
	published := 0
	for _, delivery := range deliveries {
		if err := d.publishOne(ctx, delivery); err != nil {
			return published, err
		}
		published++
	}
	return published, nil
}

func (d *Dispatcher) publishOne(ctx context.Context, delivery acmeedge.SealedDelivery) error {
	command, artifact, err := d.artifacts.BuildCommand(ctx, delivery)
	if err != nil {
		if ctx.Err() != nil || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return err
		}
		if errors.Is(err, ErrArtifactBinding) || errors.Is(err, ErrArtifactIntegrity) {
			return d.completeFailure(delivery, false, "artifact_integrity")
		}
		return d.completeFailure(delivery, true, "artifact_unavailable")
	}
	clear(artifact)
	payload, err := proto.MarshalOptions{Deterministic: true}.Marshal(command)
	if err != nil {
		return d.completeFailure(delivery, false, "command_encoding")
	}
	defer clear(payload)
	wantSubject := commandSubjectPrefix + "." + delivery.NodeID.String()
	if delivery.Subject != wantSubject {
		return d.completeFailure(delivery, false, "subject_binding")
	}
	message := nats.NewMsg(delivery.Subject)
	message.Data = payload
	message.Header.Set(nats.MsgIdHdr, command.Event.EventId)
	publishCtx, cancel := context.WithTimeout(ctx, d.config.OperationTimeout)
	acknowledgement, publishErr := d.jetstream.PublishMsg(message, nats.Context(publishCtx), nats.ExpectStream(d.config.Stream))
	cancel()
	if publishErr != nil {
		code := "publish_unavailable"
		if errors.Is(publishErr, context.DeadlineExceeded) || errors.Is(publishErr, nats.ErrTimeout) {
			code = "publish_timeout"
		}
		return d.completeFailure(delivery, true, code)
	}
	if acknowledgement == nil || acknowledgement.Stream != d.config.Stream {
		return d.completeFailure(delivery, false, "puback_stream_mismatch")
	}
	finalizeCtx, finalizeCancel := context.WithTimeout(context.Background(), d.config.OperationTimeout)
	err = d.overlay.CompleteDelivery(finalizeCtx, acmeedge.CompleteDeliveryRequest{
		OutboxID: delivery.OutboxID, LeaseToken: delivery.LeaseToken, Published: true,
	})
	finalizeCancel()
	return err
}

func (d *Dispatcher) completeFailure(delivery acmeedge.SealedDelivery, retryable bool, code string) error {
	ctx, cancel := context.WithTimeout(context.Background(), d.config.OperationTimeout)
	defer cancel()
	return d.overlay.CompleteDelivery(ctx, acmeedge.CompleteDeliveryRequest{
		OutboxID: delivery.OutboxID, LeaseToken: delivery.LeaseToken,
		Retryable: retryable, FailureCode: code, RetryAfter: d.config.RetryDelay,
	})
}

func (d *Dispatcher) Run(ctx context.Context) error {
	if ctx == nil {
		return ErrInvalidConfig
	}
	for {
		count, err := d.PublishBatch(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return err
		}
		if count > 0 {
			continue
		}
		timer := time.NewTimer(d.config.PollInterval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

func validNATSName(value string) bool {
	if value == "" {
		return false
	}
	for _, character := range value {
		if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' ||
			character >= '0' && character <= '9' || character == '-' || character == '_' {
			continue
		}
		return false
	}
	return true
}

func validSubjectPrefix(value string) bool {
	if value == "" || strings.HasPrefix(value, ".") || strings.HasSuffix(value, ".") {
		return false
	}
	for _, token := range strings.Split(value, ".") {
		if !validNATSName(token) {
			return false
		}
	}
	return true
}
