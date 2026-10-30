package ccreference

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

var metadataPattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)
var typePattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)

type Service struct {
	store *Store
}

func NewService(store *Store) *Service { return &Service{store: store} }

func NewStore(pool *pgxpool.Pool, now func() time.Time) *Store { return NewStoreWithClock(pool, now) }

func (s *Service) List(ctx context.Context, actor Actor, kind Kind, filter ListFilter) (ListResult, error) {
	filter.Name = strings.TrimSpace(filter.Name)
	filter.Owner = strings.TrimSpace(filter.Owner)
	filter.Status = strings.TrimSpace(filter.Status)
	filter.Type = strings.TrimSpace(filter.Type)
	if !validActor(actor) || !validKind(kind) || filter.Page < 1 || filter.Page > 1_000_000 || filter.Limit < 1 || filter.Limit > 100 ||
		(filter.Status != "" && filter.Status != "enabled" && filter.Status != "disabled") ||
		utf8.RuneCountInString(filter.Name) > 128 || utf8.RuneCountInString(filter.Owner) > 128 ||
		(filter.Type != "" && !typePattern.MatchString(filter.Type)) {
		return ListResult{}, ErrInvalidInput
	}
	if actor.ScopeKind == "tenant" && filter.Owner != "" {
		return ListResult{}, ErrPermissionDenied
	}
	return s.store.List(ctx, actor, kind, filter)
}

func (s *Service) Get(ctx context.Context, actor Actor, kind Kind, id uuid.UUID) (Item, error) {
	if !validActor(actor) || !validKind(kind) || id == uuid.Nil {
		return Item{}, ErrInvalidInput
	}
	return s.store.Get(ctx, actor, kind, id)
}

func (s *Service) Create(ctx context.Context, actor Actor, request CreateRequest) (WriteResult, error) {
	if !validActor(actor) || !validKind(request.Kind) || !validMetadata(request.IdempotencyKey, request.RequestID) {
		return WriteResult{}, ErrInvalidInput
	}
	if err := normalizeTarget(actor, &request.TargetScopeID, &request.OwnerUserID); err != nil {
		return WriteResult{}, err
	}
	if err := normalizeFields(request.Kind, &request.Matcher, &request.Filter); err != nil {
		return WriteResult{}, err
	}
	digest, err := requestDigest(struct {
		Kind    Kind          `json:"kind"`
		Scope   uuid.UUID     `json:"scope"`
		Owner   uuid.UUID     `json:"owner"`
		Matcher MatcherFields `json:"matcher"`
		Filter  FilterFields  `json:"filter"`
	}{request.Kind, request.TargetScopeID, request.OwnerUserID, request.Matcher, request.Filter})
	if err != nil {
		return WriteResult{}, err
	}
	return s.store.Create(ctx, actor, request, digest)
}

func (s *Service) Update(ctx context.Context, actor Actor, request UpdateRequest) (WriteResult, error) {
	if !validActor(actor) || !validKind(request.Kind) || request.ID == uuid.Nil || request.ExpectedRevision < 1 ||
		!validMetadata(request.IdempotencyKey, request.RequestID) {
		return WriteResult{}, ErrInvalidInput
	}
	if err := normalizeFields(request.Kind, &request.Matcher, &request.Filter); err != nil {
		return WriteResult{}, err
	}
	digest, err := requestDigest(struct {
		Kind     Kind          `json:"kind"`
		ID       uuid.UUID     `json:"id"`
		Revision int64         `json:"revision"`
		Matcher  MatcherFields `json:"matcher"`
		Filter   FilterFields  `json:"filter"`
	}{request.Kind, request.ID, request.ExpectedRevision, request.Matcher, request.Filter})
	if err != nil {
		return WriteResult{}, err
	}
	return s.store.Update(ctx, actor, request, digest)
}

func (s *Service) Delete(ctx context.Context, actor Actor, request DeleteRequest) (DeleteResult, error) {
	if !validActor(actor) || !validKind(request.Kind) || request.ID == uuid.Nil || request.ExpectedRevision < 1 ||
		!validMetadata(request.IdempotencyKey, request.RequestID) {
		return DeleteResult{}, ErrInvalidInput
	}
	digest, err := requestDigest(struct {
		Kind     Kind      `json:"kind"`
		ID       uuid.UUID `json:"id"`
		Revision int64     `json:"revision"`
	}{request.Kind, request.ID, request.ExpectedRevision})
	if err != nil {
		return DeleteResult{}, err
	}
	return s.store.Delete(ctx, actor, request, digest)
}

func (s *Service) SetEnabled(ctx context.Context, actor Actor, kind Kind, id uuid.UUID, expectedRevision int64, enabled bool, key, requestID string) (WriteResult, error) {
	item, err := s.Get(ctx, actor, kind, id)
	if err != nil {
		return WriteResult{}, err
	}
	if item.Revision != expectedRevision {
		return WriteResult{}, ErrRevisionConflict
	}
	request := UpdateRequest{Kind: kind, ID: id, ExpectedRevision: expectedRevision, IdempotencyKey: key, RequestID: requestID, SystemStateOnly: true}
	if kind == KindMatcher {
		request.Matcher = MatcherFields{Name: item.Name, Description: item.Description, Enabled: enabled, Field: item.Field, Operator: item.Operator, Key: item.Key, Values: item.Values}
	} else {
		request.Filter = FilterFields{Name: item.Name, Description: item.Description, Enabled: enabled, Type: item.Type, Parameters: item.Parameters}
	}
	return s.Update(ctx, actor, request)
}

func validActor(actor Actor) bool {
	return actor.UserID != uuid.Nil && actor.ScopeID != uuid.Nil && (actor.ScopeKind == "platform" || actor.ScopeKind == "tenant")
}

func validKind(kind Kind) bool { return kind == KindMatcher || kind == KindFilter }

func validMetadata(key, requestID string) bool {
	return metadataPattern.MatchString(strings.TrimSpace(key)) && metadataPattern.MatchString(strings.TrimSpace(requestID))
}

func normalizeTarget(actor Actor, scopeID, ownerID *uuid.UUID) error {
	if actor.ScopeKind == "tenant" {
		if (*scopeID != uuid.Nil && *scopeID != actor.ScopeID) || (*ownerID != uuid.Nil && *ownerID != actor.UserID) {
			return ErrPermissionDenied
		}
		*scopeID, *ownerID = actor.ScopeID, actor.UserID
		return nil
	}
	if *scopeID == uuid.Nil || *ownerID == uuid.Nil {
		return ErrInvalidInput
	}
	return nil
}

func normalizeFields(kind Kind, matcher *MatcherFields, filter *FilterFields) error {
	if kind == KindMatcher {
		matcher.Name = strings.TrimSpace(matcher.Name)
		matcher.Description = strings.TrimSpace(matcher.Description)
		matcher.Field = strings.TrimSpace(matcher.Field)
		matcher.Operator = strings.TrimSpace(matcher.Operator)
		matcher.Key = strings.TrimSpace(matcher.Key)
		if utf8.RuneCountInString(matcher.Name) < 1 || utf8.RuneCountInString(matcher.Name) > 128 || utf8.RuneCountInString(matcher.Description) > 1000 ||
			utf8.RuneCountInString(matcher.Field) < 1 || utf8.RuneCountInString(matcher.Field) > 128 || utf8.RuneCountInString(matcher.Operator) < 1 || utf8.RuneCountInString(matcher.Operator) > 128 || utf8.RuneCountInString(matcher.Key) > 128 || len(matcher.Values) > 100 {
			return ErrInvalidInput
		}
		for _, value := range matcher.Values {
			if !utf8.ValidString(value) || utf8.RuneCountInString(value) > 4096 {
				return ErrInvalidInput
			}
		}
		return nil
	}
	filter.Name = strings.TrimSpace(filter.Name)
	filter.Description = strings.TrimSpace(filter.Description)
	filter.Type = strings.TrimSpace(filter.Type)
	if utf8.RuneCountInString(filter.Name) < 1 || utf8.RuneCountInString(filter.Name) > 128 || utf8.RuneCountInString(filter.Description) > 1000 ||
		!typePattern.MatchString(filter.Type) {
		return ErrInvalidInput
	}
	if len(filter.Parameters) == 0 {
		filter.Parameters = json.RawMessage(`{}`)
	}
	var object map[string]any
	if json.Unmarshal(filter.Parameters, &object) != nil || object == nil {
		return ErrInvalidInput
	}
	return nil
}

func requestDigest(value any) ([32]byte, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(encoded), nil
}
