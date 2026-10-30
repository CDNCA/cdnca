package nodemetrics

import (
	"context"
	"errors"
	"time"
)

type Processor struct {
	decoder          *Decoder
	store            Store
	ccAutoSwitch     CCAutoSwitchRecorder
	nakDelay         time.Duration
	operationTimeout time.Duration
}

func NewProcessor(decoder *Decoder, store Store, nakDelay, operationTimeout time.Duration) (*Processor, error) {
	if decoder == nil || store == nil || nakDelay <= 0 || operationTimeout <= 0 {
		return nil, ErrInvalidConfiguration
	}
	return &Processor{decoder: decoder, store: store, nakDelay: nakDelay, operationTimeout: operationTimeout}, nil
}

// WithCCAutoSwitchRecorder routes CC auto switch engagements (FX65) to
// recorder instead of node_metric_samples. Without one they are terminated.
func (processor *Processor) WithCCAutoSwitchRecorder(recorder CCAutoSwitchRecorder) *Processor {
	processor.ccAutoSwitch = recorder
	return processor
}

func (processor *Processor) Process(ctx context.Context, delivery Delivery) (string, error) {
	if ctx == nil || delivery == nil {
		return "", ErrInvalidDelivery
	}
	sample, skip, err := processor.decoder.Decode(delivery)
	if err != nil {
		return processor.term(ctx, delivery)
	}
	if !skip {
		operationCtx, cancel := context.WithTimeout(ctx, processor.operationTimeout)
		permanent := false
		if sample.Kind != RecordCCAutoSwitch {
			_, err = processor.store.Put(operationCtx, sample)
			permanent = errors.Is(err, ErrConflict)
		} else if processor.ccAutoSwitch == nil {
			err, permanent = ErrInvalidConfiguration, true
		} else {
			err = processor.ccAutoSwitch.RecordCCAutoSwitch(operationCtx, sample)
			permanent = errors.Is(err, ErrInvalidSample)
		}
		cancel()
		if err != nil {
			if permanent {
				return processor.term(ctx, delivery)
			}
			return processor.nak(ctx, delivery)
		}
	}
	operationCtx, cancel := context.WithTimeout(ctx, processor.operationTimeout)
	err = delivery.Ack(operationCtx)
	cancel()
	if err != nil {
		return DispositionAck, err
	}
	return DispositionAck, nil
}

func (processor *Processor) nak(ctx context.Context, delivery Delivery) (string, error) {
	operationCtx, cancel := context.WithTimeout(ctx, processor.operationTimeout)
	err := delivery.Nak(operationCtx, processor.nakDelay)
	cancel()
	return DispositionNak, err
}

func (processor *Processor) term(ctx context.Context, delivery Delivery) (string, error) {
	operationCtx, cancel := context.WithTimeout(ctx, processor.operationTimeout)
	err := delivery.Term(operationCtx)
	cancel()
	return DispositionTerm, err
}
