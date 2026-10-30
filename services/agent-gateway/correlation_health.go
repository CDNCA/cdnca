package gateway

import "sync/atomic"

const (
	CorrelationResultOK                  = "CORRELATION_OK"
	CorrelationResultReplayed            = "CORRELATION_REPLAYED"
	CorrelationResultMetadataRejected    = "CORRELATION_METADATA_REJECTED"
	CorrelationResultPublishFailed       = "CORRELATION_PUBLISH_FAILED"
	CorrelationResultActivationSucceeded = "EDGE_ACTIVATION_SUCCEEDED"
	CorrelationResultActivationFailed    = "EDGE_ACTIVATION_FAILED"
)

const (
	correlationResultOK uint32 = iota
	correlationResultReplayed
	correlationResultMetadataRejected
	correlationResultPublishFailed
	correlationResultActivationSucceeded
	correlationResultActivationFailed
)

type CorrelationHealthSnapshot struct {
	Accepted          uint64 `json:"accepted"`
	Replayed          uint64 `json:"replayed"`
	Rejected          uint64 `json:"rejected"`
	PublishFailed     uint64 `json:"publish_failed"`
	TerminalSucceeded uint64 `json:"terminal_succeeded"`
	TerminalFailed    uint64 `json:"terminal_failed"`
	LastResultCode    string `json:"last_result_code"`
}

type CorrelationHealth struct {
	accepted          atomic.Uint64
	replayed          atomic.Uint64
	rejected          atomic.Uint64
	publishFailed     atomic.Uint64
	terminalSucceeded atomic.Uint64
	terminalFailed    atomic.Uint64
	lastResult        atomic.Uint32
}

func NewCorrelationHealth() *CorrelationHealth { return &CorrelationHealth{} }

func (health *CorrelationHealth) RecordAccepted() {
	if health != nil {
		health.accepted.Add(1)
		health.lastResult.Store(correlationResultOK)
	}
}

func (health *CorrelationHealth) RecordReplayed() {
	if health != nil {
		health.replayed.Add(1)
		health.lastResult.Store(correlationResultReplayed)
	}
}

func (health *CorrelationHealth) RecordRejected() {
	if health != nil {
		health.rejected.Add(1)
		health.lastResult.Store(correlationResultMetadataRejected)
	}
}

func (health *CorrelationHealth) RecordPublishFailed() {
	if health != nil {
		health.publishFailed.Add(1)
		health.lastResult.Store(correlationResultPublishFailed)
	}
}

func (health *CorrelationHealth) RecordTerminalSucceeded() {
	if health != nil {
		health.terminalSucceeded.Add(1)
		health.lastResult.Store(correlationResultActivationSucceeded)
	}
}

func (health *CorrelationHealth) RecordTerminalFailed() {
	if health != nil {
		health.terminalFailed.Add(1)
		health.lastResult.Store(correlationResultActivationFailed)
	}
}

func (health *CorrelationHealth) Snapshot() CorrelationHealthSnapshot {
	if health == nil {
		return CorrelationHealthSnapshot{}
	}
	return CorrelationHealthSnapshot{
		Accepted: health.accepted.Load(), Replayed: health.replayed.Load(),
		Rejected: health.rejected.Load(), PublishFailed: health.publishFailed.Load(),
		TerminalSucceeded: health.terminalSucceeded.Load(), TerminalFailed: health.terminalFailed.Load(),
		LastResultCode: correlationResultCode(health.lastResult.Load()),
	}
}

func correlationResultCode(value uint32) string {
	switch value {
	case correlationResultReplayed:
		return CorrelationResultReplayed
	case correlationResultMetadataRejected:
		return CorrelationResultMetadataRejected
	case correlationResultPublishFailed:
		return CorrelationResultPublishFailed
	case correlationResultActivationSucceeded:
		return CorrelationResultActivationSucceeded
	case correlationResultActivationFailed:
		return CorrelationResultActivationFailed
	default:
		return CorrelationResultOK
	}
}
