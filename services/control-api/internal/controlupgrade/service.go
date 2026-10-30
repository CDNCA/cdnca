package controlupgrade

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"regexp"
	"strings"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/entitlementguard"
	"github.com/cdnca/cdnca/services/control-api/internal/platformpolicy"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/mod/semver"
)

var (
	codePattern          = regexp.MustCompile(`^[a-z][a-z0-9._-]{0,95}$`)
	writeMetadataPattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)
)

type Service struct {
	store   *Store
	rollout *RolloutRuntime
}

func NewService(pool *pgxpool.Pool, trust *entitlementguard.TrustStore, policy *platformpolicy.State, now func() time.Time) *Service {
	if policy == nil {
		policy = platformpolicy.NewState(now)
	}
	return &Service{store: NewStore(pool, entitlementguard.NewGuard(pool, now, trust), policy, now)}
}

func (s *Service) Check(ctx context.Context, actor Actor, request CheckRequest) (CheckResponse, error) {
	if actor.UserID == uuid.Nil || actor.ScopeID == uuid.Nil || actor.ScopeKind != "platform" {
		return CheckResponse{}, ErrPermissionDenied
	}
	if !codePattern.MatchString(request.Component) || !codePattern.MatchString(request.Channel) ||
		!validCanonicalVersion(request.CurrentVersion) ||
		!writeMetadataPattern.MatchString(request.IdempotencyKey) || !writeMetadataPattern.MatchString(request.RequestID) {
		return CheckResponse{}, ErrInvalidInput
	}
	digest, err := checkDigest(request)
	if err != nil {
		return CheckResponse{}, err
	}
	return s.store.Check(ctx, actor, request, digest)
}

func validCanonicalVersion(version string) bool {
	if version == "" || strings.Contains(version, "+") {
		return false
	}
	prefixed := "v" + version
	return semver.IsValid(prefixed) && semver.Canonical(prefixed) == prefixed
}

func checkDigest(request CheckRequest) ([sha256.Size]byte, error) {
	payload, err := json.Marshal(struct {
		Component      string `json:"component"`
		CurrentVersion string `json:"current_version"`
		Channel        string `json:"channel"`
	}{request.Component, request.CurrentVersion, request.Channel})
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	return sha256.Sum256(payload), nil
}

func validateCreateRolloutRequest(request CreateRolloutRequest) error {
	if request.Schema != "cdnca.control-upgrade-rollout.create/v1" || len(request.NodeIDs) == 0 ||
		len(request.NodeIDs) > 1000 || len(request.CanaryNodeIDs) == 0 || len(request.CanaryNodeIDs) > 2 ||
		request.BatchSize < 1 || request.BatchSize > 100 || !request.AutomaticRollback ||
		!writeMetadataPattern.MatchString(request.IdempotencyKey) ||
		!writeMetadataPattern.MatchString(request.RequestID) || !strictCanonicalUUIDs(request.NodeIDs) ||
		!strictCanonicalUUIDs(request.CanaryNodeIDs) {
		return ErrInvalidInput
	}
	nodes := make(map[string]struct{}, len(request.NodeIDs))
	for _, nodeID := range request.NodeIDs {
		nodes[nodeID] = struct{}{}
	}
	for _, nodeID := range request.CanaryNodeIDs {
		if _, ok := nodes[nodeID]; !ok {
			return ErrInvalidInput
		}
	}
	return nil
}

func strictCanonicalUUIDs(values []string) bool {
	for index, value := range values {
		parsed, err := uuid.Parse(value)
		if err != nil || parsed == uuid.Nil || parsed.String() != value ||
			index > 0 && values[index-1] >= value {
			return false
		}
	}
	return true
}

func rolloutRequestDigest(actor Actor, installationID uuid.UUID, operation, planID string,
	body any) ([sha256.Size]byte, []byte, error) {
	if actor.ScopeID == uuid.Nil || actor.UserID == uuid.Nil || installationID == uuid.Nil ||
		actor.ScopeKind != "platform" || operation == "" ||
		(planID != "" && !validCanonicalPlanUUID(planID)) {
		return [sha256.Size]byte{}, nil, ErrInvalidInput
	}
	document := struct {
		Domain         string `json:"domain"`
		Operation      string `json:"operation"`
		ActorScopeID   string `json:"actor_scope_id"`
		ActorUserID    string `json:"actor_user_id"`
		InstallationID string `json:"installation_id"`
		PlanID         string `json:"plan_id"`
		Body           any    `json:"body"`
	}{"cdnca.control-upgrade-rollout.request/v1", operation, actor.ScopeID.String(), actor.UserID.String(),
		installationID.String(), planID, body}
	encoded, err := json.Marshal(document)
	if err != nil {
		return [sha256.Size]byte{}, nil, ErrInvalidInput
	}
	return sha256.Sum256(encoded), encoded, nil
}
