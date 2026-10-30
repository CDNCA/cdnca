package analytics

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	defaultRealtimeCoveragePollInterval = 30 * time.Second
	defaultRealtimeCoverageGrace        = 2 * time.Minute
	defaultRealtimeCoverageWindows      = 64
	maximumRealtimeCoverageWindows      = 1000
)

var (
	ErrRealtimeCoverageUnavailable = errors.New("analytics realtime coverage dependency unavailable")
	ErrRealtimeCoverageConflict    = errors.New("analytics realtime coverage conflict")
)

type RealtimeCoverageCandidateV1 struct {
	ScopeID     string
	TenantID    string
	SiteID      string
	Host        string
	ListenPort  uint16
	WindowStart time.Time
	WindowEnd   time.Time
}

type RealtimeCoverageSourceV1 struct {
	NodeID                 string
	ConfigVersionID        string
	AccessPresent          bool
	AccessSourceWatermark  uint64
	AccessFinalizedThrough time.Time
	AccessEvidenceSHA256   [sha256.Size]byte
	AccessRecordedAt       time.Time
}

type RealtimeCoverageSnapshotV1 struct {
	Candidate RealtimeCoverageCandidateV1
	Sources   []RealtimeCoverageSourceV1
}

type RealtimeConnectionEvidenceV1 struct {
	ConfigVersionID  string
	NodeID           string
	SourceWatermark  uint64
	FinalizedThrough time.Time
	EvidenceSHA256   [sha256.Size]byte
	RecordedAt       time.Time
}

type RealtimeCoverageFactV1 struct {
	Candidate                  RealtimeCoverageCandidateV1
	AccessSourcesExpected      int
	AccessSourcesFinalized     int
	ConnectionSourcesExpected  int
	ConnectionSourcesFinalized int
	AccessSourceWatermark      time.Time
	AccessFinalizedThrough     time.Time
	ConnectionSourceWatermark  time.Time
	ConnectionFinalizedThrough time.Time
	EvidenceSHA256             [sha256.Size]byte
	RecordedAt                 time.Time
}

type RealtimeCoverageFinalizerConfig struct {
	Now               func() time.Time
	PollInterval      time.Duration
	FinalizationGrace time.Duration
	MaximumWindows    int
}

type realtimeCoverageStoreV1 interface {
	PendingRealtimeCoverage(context.Context, time.Time, int) ([]RealtimeCoverageCandidateV1, error)
	LoadRealtimeCoverage(context.Context, RealtimeCoverageCandidateV1) (RealtimeCoverageSnapshotV1, error)
	CommitRealtimeCoverage(context.Context, RealtimeCoverageSnapshotV1, RealtimeCoverageFactV1) (bool, error)
}

type realtimeConnectionEvidenceReaderV1 interface {
	RealtimeConnectionEvidence(context.Context, RealtimeCoverageCandidateV1) ([]RealtimeConnectionEvidenceV1, error)
}

type RealtimeCoverageFinalizer struct {
	store       realtimeCoverageStoreV1
	connections realtimeConnectionEvidenceReaderV1
	config      RealtimeCoverageFinalizerConfig
}

func NewRealtimeCoverageFinalizer(
	store realtimeCoverageStoreV1,
	connections realtimeConnectionEvidenceReaderV1,
	config RealtimeCoverageFinalizerConfig,
) (*RealtimeCoverageFinalizer, error) {
	return newRealtimeCoverageFinalizer(store, connections, config)
}

func newRealtimeCoverageFinalizer(
	store realtimeCoverageStoreV1,
	connections realtimeConnectionEvidenceReaderV1,
	config RealtimeCoverageFinalizerConfig,
) (*RealtimeCoverageFinalizer, error) {
	if config.Now == nil {
		config.Now = time.Now
	}
	if config.PollInterval == 0 {
		config.PollInterval = defaultRealtimeCoveragePollInterval
	}
	if config.FinalizationGrace == 0 {
		config.FinalizationGrace = defaultRealtimeCoverageGrace
	}
	if config.MaximumWindows == 0 {
		config.MaximumWindows = defaultRealtimeCoverageWindows
	}
	if store == nil || connections == nil || config.Now == nil || config.PollInterval <= 0 ||
		config.PollInterval > time.Hour || config.FinalizationGrace <= 0 || config.FinalizationGrace > time.Hour ||
		config.MaximumWindows < 1 || config.MaximumWindows > maximumRealtimeCoverageWindows {
		return nil, ErrInvalidServiceConfig
	}
	return &RealtimeCoverageFinalizer{store: store, connections: connections, config: config}, nil
}

func (finalizer *RealtimeCoverageFinalizer) Run(ctx context.Context) error {
	if finalizer == nil || ctx == nil {
		return ErrInvalidServiceConfig
	}
	for {
		if _, err := finalizer.FinalizeOnce(ctx); err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return err
		}
		timer := time.NewTimer(finalizer.config.PollInterval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

func (finalizer *RealtimeCoverageFinalizer) FinalizeOnce(ctx context.Context) (int, error) {
	if finalizer == nil || finalizer.store == nil || finalizer.connections == nil || ctx == nil {
		return 0, ErrInvalidServiceConfig
	}
	now := finalizer.config.Now().UTC()
	if now.IsZero() {
		return 0, ErrInvalidServiceConfig
	}
	candidates, err := finalizer.store.PendingRealtimeCoverage(
		ctx, now.Add(-finalizer.config.FinalizationGrace), finalizer.config.MaximumWindows,
	)
	if err != nil {
		return 0, mapRealtimeCoverageError(ctx, err)
	}
	if len(candidates) > finalizer.config.MaximumWindows {
		return 0, ErrRealtimeCoverageConflict
	}
	committed := 0
	for _, candidate := range candidates {
		if !validRealtimeCoverageCandidate(candidate) || candidate.WindowEnd.After(now.Add(-finalizer.config.FinalizationGrace)) {
			return committed, ErrRealtimeCoverageConflict
		}
		snapshot, err := finalizer.store.LoadRealtimeCoverage(ctx, candidate)
		if err != nil {
			return committed, mapRealtimeCoverageError(ctx, err)
		}
		connections, err := finalizer.connections.RealtimeConnectionEvidence(ctx, candidate)
		if err != nil {
			return committed, mapRealtimeCoverageError(ctx, err)
		}
		fact, complete, err := buildRealtimeCoverageFact(snapshot, connections, now)
		if err != nil {
			return committed, err
		}
		if !complete {
			continue
		}
		inserted, err := finalizer.store.CommitRealtimeCoverage(ctx, snapshot, fact)
		if err != nil {
			return committed, mapRealtimeCoverageError(ctx, err)
		}
		if inserted {
			committed++
		}
	}
	return committed, nil
}

func buildRealtimeCoverageFact(
	snapshot RealtimeCoverageSnapshotV1,
	connectionEvidence []RealtimeConnectionEvidenceV1,
	now time.Time,
) (RealtimeCoverageFactV1, bool, error) {
	if !validRealtimeCoverageCandidate(snapshot.Candidate) || len(snapshot.Sources) == 0 ||
		len(snapshot.Sources) > 1_000_000 || now.Location() != time.UTC {
		return RealtimeCoverageFactV1{}, false, ErrRealtimeCoverageConflict
	}
	sources := append([]RealtimeCoverageSourceV1(nil), snapshot.Sources...)
	sort.Slice(sources, func(i, j int) bool { return sources[i].NodeID < sources[j].NodeID })
	connections := append([]RealtimeConnectionEvidenceV1(nil), connectionEvidence...)
	sort.Slice(connections, func(i, j int) bool { return connections[i].NodeID < connections[j].NodeID })
	connectionByNode := make(map[string]RealtimeConnectionEvidenceV1, len(connections))
	for _, evidence := range connections {
		if _, duplicate := connectionByNode[evidence.NodeID]; duplicate || !validRealtimeConnectionCoverage(evidence, snapshot.Candidate) {
			return RealtimeCoverageFactV1{}, false, ErrRealtimeCoverageConflict
		}
		connectionByNode[evidence.NodeID] = evidence
	}
	fact := RealtimeCoverageFactV1{
		Candidate: snapshot.Candidate, AccessSourcesExpected: len(sources),
		ConnectionSourcesExpected: len(sources),
	}
	seenNodes := make(map[string]struct{}, len(sources))
	for _, source := range sources {
		if _, duplicate := seenNodes[source.NodeID]; duplicate || !validRealtimeCoverageSource(source, snapshot.Candidate) {
			return RealtimeCoverageFactV1{}, false, ErrRealtimeCoverageConflict
		}
		seenNodes[source.NodeID] = struct{}{}
		if !source.AccessPresent {
			return RealtimeCoverageFactV1{}, false, nil
		}
		connection, present := connectionByNode[source.NodeID]
		if !present {
			return RealtimeCoverageFactV1{}, false, nil
		}
		if connection.ConfigVersionID != "" && connection.ConfigVersionID != source.ConfigVersionID {
			return RealtimeCoverageFactV1{}, false, ErrRealtimeCoverageConflict
		}
		fact.AccessSourcesFinalized++
		fact.ConnectionSourcesFinalized++
		fact.AccessSourceWatermark = earliestCoverageTime(fact.AccessSourceWatermark, source.AccessRecordedAt)
		fact.AccessFinalizedThrough = earliestCoverageTime(fact.AccessFinalizedThrough, source.AccessFinalizedThrough)
		fact.ConnectionSourceWatermark = earliestCoverageTime(fact.ConnectionSourceWatermark, connection.RecordedAt)
		fact.ConnectionFinalizedThrough = earliestCoverageTime(fact.ConnectionFinalizedThrough, connection.FinalizedThrough)
		fact.RecordedAt = latestCoverageTime(fact.RecordedAt, source.AccessRecordedAt)
		fact.RecordedAt = latestCoverageTime(fact.RecordedAt, connection.RecordedAt)
	}
	if len(connectionByNode) != len(seenNodes) {
		return RealtimeCoverageFactV1{}, false, ErrRealtimeCoverageConflict
	}
	if fact.AccessFinalizedThrough.Before(snapshot.Candidate.WindowEnd) ||
		fact.ConnectionFinalizedThrough.Before(snapshot.Candidate.WindowEnd) ||
		fact.AccessSourceWatermark.Before(snapshot.Candidate.WindowEnd) ||
		fact.ConnectionSourceWatermark.Before(snapshot.Candidate.WindowEnd) ||
		now.Before(fact.AccessSourceWatermark) || now.Before(fact.ConnectionSourceWatermark) {
		return RealtimeCoverageFactV1{}, false, ErrRealtimeCoverageConflict
	}
	fact.EvidenceSHA256 = realtimeCoverageEvidenceDigest(snapshot.Candidate, sources, connectionByNode)
	return fact, true, nil
}

func validRealtimeCoverageCandidate(candidate RealtimeCoverageCandidateV1) bool {
	return validUUID(candidate.ScopeID) && validUUID(candidate.TenantID) && validUUID(candidate.SiteID) &&
		strings.ToLower(candidate.ScopeID) == candidate.ScopeID && strings.ToLower(candidate.TenantID) == candidate.TenantID &&
		strings.ToLower(candidate.SiteID) == candidate.SiteID && validConnectionDomain(candidate.Host) && candidate.ListenPort > 0 &&
		candidate.WindowStart.Location() == time.UTC && candidate.WindowStart.Equal(candidate.WindowStart.Truncate(time.Hour)) &&
		candidate.WindowEnd.Equal(candidate.WindowStart.Add(time.Hour))
}

func validRealtimeCoverageSource(source RealtimeCoverageSourceV1, candidate RealtimeCoverageCandidateV1) bool {
	if !validUUID(source.NodeID) || !validUUID(source.ConfigVersionID) || strings.ToLower(source.NodeID) != source.NodeID ||
		strings.ToLower(source.ConfigVersionID) != source.ConfigVersionID {
		return false
	}
	if !source.AccessPresent {
		return source.AccessSourceWatermark == 0 && source.AccessFinalizedThrough.IsZero() &&
			source.AccessEvidenceSHA256 == ([sha256.Size]byte{}) && source.AccessRecordedAt.IsZero()
	}
	return source.AccessSourceWatermark > 0 && source.AccessEvidenceSHA256 != ([sha256.Size]byte{}) &&
		source.AccessFinalizedThrough.Location() == time.UTC && source.AccessRecordedAt.Location() == time.UTC &&
		!source.AccessFinalizedThrough.Before(candidate.WindowEnd) && !source.AccessRecordedAt.Before(candidate.WindowEnd)
}

func validRealtimeConnectionCoverage(evidence RealtimeConnectionEvidenceV1, candidate RealtimeCoverageCandidateV1) bool {
	return validUUID(evidence.NodeID) && strings.ToLower(evidence.NodeID) == evidence.NodeID && evidence.SourceWatermark > 0 &&
		evidence.EvidenceSHA256 != ([sha256.Size]byte{}) && evidence.FinalizedThrough.Location() == time.UTC &&
		evidence.RecordedAt.Location() == time.UTC && !evidence.FinalizedThrough.Before(candidate.WindowEnd) &&
		!evidence.RecordedAt.Before(candidate.WindowEnd)
}

func earliestCoverageTime(current, candidate time.Time) time.Time {
	if current.IsZero() || candidate.Before(current) {
		return candidate
	}
	return current
}

func latestCoverageTime(current, candidate time.Time) time.Time {
	if current.IsZero() || candidate.After(current) {
		return candidate
	}
	return current
}

func realtimeCoverageEvidenceDigest(
	candidate RealtimeCoverageCandidateV1,
	sources []RealtimeCoverageSourceV1,
	connections map[string]RealtimeConnectionEvidenceV1,
) [sha256.Size]byte {
	hash := sha256.New()
	_, _ = hash.Write([]byte("cdnca.analytics.realtime-coverage.v1\x00"))
	for _, value := range []string{
		candidate.ScopeID, candidate.TenantID, candidate.SiteID, candidate.Host,
		strconv.FormatUint(uint64(candidate.ListenPort), 10), candidate.WindowStart.Format(time.RFC3339Nano),
		candidate.WindowEnd.Format(time.RFC3339Nano),
	} {
		writeRealtimeCoverageDigestPart(hash, value)
	}
	for _, source := range sources {
		connection := connections[source.NodeID]
		for _, value := range []string{
			source.NodeID, source.ConfigVersionID, strconv.FormatUint(source.AccessSourceWatermark, 10),
			source.AccessFinalizedThrough.Format(time.RFC3339Nano), source.AccessRecordedAt.Format(time.RFC3339Nano),
			hex.EncodeToString(source.AccessEvidenceSHA256[:]), strconv.FormatUint(connection.SourceWatermark, 10),
			connection.FinalizedThrough.Format(time.RFC3339Nano), connection.RecordedAt.Format(time.RFC3339Nano),
			hex.EncodeToString(connection.EvidenceSHA256[:]),
		} {
			writeRealtimeCoverageDigestPart(hash, value)
		}
	}
	var digest [sha256.Size]byte
	copy(digest[:], hash.Sum(nil))
	return digest
}

func writeRealtimeCoverageDigestPart(hash interface{ Write([]byte) (int, error) }, value string) {
	_, _ = hash.Write([]byte(value))
	_, _ = hash.Write([]byte{0})
}

func mapRealtimeCoverageError(ctx context.Context, err error) error {
	if ctx != nil && ctx.Err() != nil {
		return ctx.Err()
	}
	if errors.Is(err, ErrRealtimeCoverageConflict) || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	return ErrRealtimeCoverageUnavailable
}
