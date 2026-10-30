package jobstate

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"
)

const (
	maxIdempotencyKeyBytes = 128
	maxItemIDRunes         = 256
	maxSubjectRunes        = 512
	maxRequestIDRunes      = 128
	maxTraceIDRunes        = 512
	maxItems               = 100_000
	maxPayloadBytes        = 4 << 20
	maxRetries             = 1_000
)

var (
	idempotencyKeyPattern   = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)
	stableIdentifierPattern = regexp.MustCompile(`^[a-z][a-z0-9._-]{0,127}$`)
)

type registryEntry struct {
	digest RequestDigest
	job    *Job
}

type Registry struct {
	mu      sync.Mutex
	clock   Clock
	entries map[string]registryEntry
}

func NewRegistry(clock Clock) *Registry {
	if clock == nil {
		clock = time.Now
	}
	return &Registry{clock: clock, entries: make(map[string]registryEntry)}
}

func (registry *Registry) Submit(request Request) (*Job, bool, error) {
	digest, err := Digest(request)
	if err != nil {
		return nil, false, err
	}

	registry.mu.Lock()
	defer registry.mu.Unlock()
	if existing, ok := registry.entries[request.IdempotencyKey]; ok {
		if existing.digest != digest {
			return nil, false, ErrIdempotencyConflict
		}
		return existing.job, true, nil
	}

	job := newJob(request, digest, registry.clock)
	registry.entries[request.IdempotencyKey] = registryEntry{digest: digest, job: job}
	return job, false, nil
}

func Digest(request Request) (RequestDigest, error) {
	if err := validateRequest(request); err != nil {
		return RequestDigest{}, err
	}
	encoded, err := json.Marshal(struct {
		Version    uint8    `json:"version"`
		Payload    []byte   `json:"payload"`
		ItemIDs    []string `json:"item_ids"`
		MaxRetries uint32   `json:"max_retries"`
	}{Version: 1, Payload: request.Payload, ItemIDs: request.ItemIDs, MaxRetries: request.MaxRetries})
	if err != nil {
		return RequestDigest{}, fmt.Errorf("%w: encode digest", ErrInvalidRequest)
	}
	return sha256.Sum256(encoded), nil
}

func validateRequest(request Request) error {
	if !validIdempotencyKey(request.IdempotencyKey) ||
		len(request.Payload) > maxPayloadBytes || len(request.ItemIDs) == 0 ||
		len(request.ItemIDs) > maxItems || request.MaxRetries > maxRetries {
		return ErrInvalidRequest
	}
	seen := make(map[string]struct{}, len(request.ItemIDs))
	for _, itemID := range request.ItemIDs {
		if !validSafeText(itemID, maxItemIDRunes, false) {
			return ErrInvalidRequest
		}
		if _, exists := seen[itemID]; exists {
			return ErrInvalidRequest
		}
		seen[itemID] = struct{}{}
	}
	return nil
}

func validIdempotencyKey(value string) bool {
	return len(value) <= maxIdempotencyKeyBytes && idempotencyKeyPattern.MatchString(value)
}

func validStableIdentifier(value string) bool {
	return stableIdentifierPattern.MatchString(value)
}

func validSafeText(value string, limit int, allowEmpty bool) bool {
	if !utf8.ValidString(value) || (!allowEmpty && value == "") || utf8.RuneCountInString(value) > limit ||
		strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) || character == '\u2028' || character == '\u2029' {
			return false
		}
	}
	return true
}
