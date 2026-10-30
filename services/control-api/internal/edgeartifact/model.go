package edgeartifact

import (
	"errors"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	controlv1 "github.com/cdnca/cdnca/proto/gen/go/controlinternal/v1"
)

var (
	ErrInvalidConfig        = errors.New("invalid artifact fetch configuration")
	ErrInvalidRequest       = errors.New("invalid artifact fetch request")
	ErrIdempotencyConflict  = errors.New("artifact fetch idempotency conflict")
	ErrRequestInProgress    = errors.New("artifact fetch request is already in progress")
	ErrRequestFailed        = errors.New("artifact fetch request previously failed")
	ErrBindingConflict      = errors.New("artifact fetch binding conflict")
	ErrDeploymentIneligible = errors.New("artifact deployment is not eligible for fetching")
	ErrArtifactIntegrity    = errors.New("stored artifact integrity failure")
	ErrOffsetOutOfRange     = errors.New("artifact fetch offset is out of range")
	ErrStorage              = errors.New("artifact fetch storage failure")
)

// FetchResult contains either one non-empty response chunk or an explicit EOF.
// Descriptor is returned separately because the frozen ControlInternal response
// carries only ArtifactChunk; callers can still verify the complete identity.
type FetchResult struct {
	Response   *controlv1.FetchArtifactResponse
	Descriptor *agentv1.ArtifactDescriptor
	EOF        bool
	Replayed   bool
}
