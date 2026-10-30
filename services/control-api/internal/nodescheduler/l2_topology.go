package nodescheduler

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

const (
	L2ModeCache  = "cache"
	L2ModeGlobal = "global"

	L2LoadRoundRobin = "rr"
	L2LoadURLHash    = "url_hash"

	operationL2ConfigCreate    = "node_scheduling.l2_config.create"
	operationL2ConfigUpdate    = "node_scheduling.l2_config.update"
	operationL2ConfigDelete    = "node_scheduling.l2_config.delete"
	operationL2ConditionCreate = "node_scheduling.l2_condition.create"
	operationL2ConditionUpdate = "node_scheduling.l2_condition.update"
	operationL2ConditionDelete = "node_scheduling.l2_condition.delete"
	operationL2NodeAdd         = "node_scheduling.l2_node.add"
	operationL2NodeUpdate      = "node_scheduling.l2_node.update"
	operationL2NodeDelete      = "node_scheduling.l2_node.delete"
)

var (
	l2RuleFields = []string{
		"host", "request_uri", "uri", "node_country", "node_isp", "node_province", "node_city", "node_id", "protocol",
	}
	l2RuleOperators = []string{"eq", "neq", "contains", "not_contains", "prefix", "suffix", "regex", "not_regex"}
)

type L2Config struct {
	ID            uuid.UUID `json:"id"`
	DisplayID     string    `json:"display_id"`
	TenantScopeID uuid.UUID `json:"tenant_scope_id"`
	Revision      int64     `json:"revision"`
	Name          string    `json:"name"`
	Region        string    `json:"region"`
	Remark        string    `json:"remark"`
	Mode          string    `json:"mode"`
	LoadMethod    string    `json:"load_method"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

type L2ConfigWriteRequest struct {
	ConfigID         uuid.UUID
	ExpectedRevision int64
	Name             string
	Region           string
	Remark           string
	Mode             string
	LoadMethod       string
	IdempotencyKey   string
	RequestID        string
}

type L2ConfigWriteResult struct {
	Config   L2Config `json:"config"`
	Replayed bool     `json:"-"`
}

type L2Rule struct {
	Field    string `json:"field"`
	Operator string `json:"operator"`
	Value    string `json:"value"`
}

type L2Condition struct {
	ID            uuid.UUID `json:"id"`
	DisplayID     string    `json:"display_id"`
	TenantScopeID uuid.UUID `json:"tenant_scope_id"`
	Revision      int64     `json:"revision"`
	Name          string    `json:"name"`
	Remark        string    `json:"remark"`
	Rules         []L2Rule  `json:"rules"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

type L2ConditionWriteRequest struct {
	ConditionID      uuid.UUID
	ExpectedRevision int64
	Name             string
	Remark           string
	Rules            []L2Rule
	IdempotencyKey   string
	RequestID        string
}

type L2ConditionWriteResult struct {
	Condition L2Condition `json:"condition"`
	Replayed  bool        `json:"-"`
}

type L2Node struct {
	ID            uuid.UUID  `json:"id"`
	DisplayID     string     `json:"display_id"`
	TenantScopeID uuid.UUID  `json:"tenant_scope_id"`
	ConfigID      uuid.UUID  `json:"config_id"`
	NodeID        uuid.UUID  `json:"node_id"`
	ConditionID   *uuid.UUID `json:"condition_id"`
	ConditionName *string    `json:"condition_name"`
	Revision      int64      `json:"revision"`
	Name          string     `json:"name"`
	IPAddress     string     `json:"ip_address"`
	AdminState    string     `json:"admin_state"`
	OnlineStatus  string     `json:"online_status"`
	Enabled       bool       `json:"enabled"`
	Weight        int        `json:"weight"`
	Sort          int        `json:"sort"`
}

type L2NodeCandidate struct {
	NodeID       uuid.UUID `json:"node_id"`
	DisplayID    string    `json:"display_id"`
	Name         string    `json:"name"`
	IPAddress    string    `json:"ip_address"`
	AdminState   string    `json:"admin_state"`
	OnlineStatus string    `json:"online_status"`
}

type L2NodeAddRequest struct {
	ConfigID         uuid.UUID
	NodeIDs          []uuid.UUID
	ConditionID      *uuid.UUID
	ExpectedRevision int64
	IdempotencyKey   string
	RequestID        string
}

type L2NodeAddResult struct {
	Items    []L2Node `json:"items"`
	Replayed bool     `json:"-"`
}

type L2NodeWriteRequest struct {
	MembershipID     uuid.UUID
	ConditionID      *uuid.UUID
	ExpectedRevision int64
	Enabled          bool
	Weight           int
	Sort             int
	IdempotencyKey   string
	RequestID        string
}

type L2NodeWriteResult struct {
	Node     L2Node `json:"node"`
	Replayed bool   `json:"-"`
}

type L2DeleteResult struct {
	ID        uuid.UUID `json:"id"`
	Revision  int64     `json:"revision"`
	DeletedAt time.Time `json:"deleted_at"`
	Replayed  bool      `json:"-"`
}

func normalizeL2ConfigWrite(request L2ConfigWriteRequest) (L2ConfigWriteRequest, error) {
	if request.Region != "" && strings.TrimSpace(request.Region) == "" {
		return L2ConfigWriteRequest{}, ErrInvalidInput
	}
	request.Name = strings.TrimSpace(request.Name)
	request.Region = strings.TrimSpace(request.Region)
	request.Remark = strings.TrimSpace(request.Remark)
	if request.ExpectedRevision < 0 || !validL2Text(request.Name, 1, 128) ||
		!validL2Text(request.Region, 0, 64) || !validL2Text(request.Remark, 0, 1024) ||
		request.Mode != L2ModeCache && request.Mode != L2ModeGlobal ||
		request.LoadMethod != L2LoadRoundRobin && request.LoadMethod != L2LoadURLHash ||
		!writeMetadataPattern.MatchString(request.IdempotencyKey) || !writeMetadataPattern.MatchString(request.RequestID) {
		return L2ConfigWriteRequest{}, ErrInvalidInput
	}
	return request, nil
}

// L2RuleRegexError refuses an L2 condition whose rule Index (0-based) is a
// regex or not_regex rule the node cannot compile. It is ErrInvalidInput.
type L2RuleRegexError struct{ Index int }

func (e *L2RuleRegexError) Error() string {
	return fmt.Sprintf("%s: rule %d is not a valid regular expression", ErrInvalidInput, e.Index+1)
}

func (e *L2RuleRegexError) Unwrap() error { return ErrInvalidInput }

func normalizeL2ConditionWrite(request L2ConditionWriteRequest) (L2ConditionWriteRequest, error) {
	request.Name = strings.TrimSpace(request.Name)
	request.Remark = strings.TrimSpace(request.Remark)
	if request.ExpectedRevision < 0 || !validL2Text(request.Name, 1, 128) ||
		!validL2Text(request.Remark, 0, 1024) || len(request.Rules) < 1 || len(request.Rules) > 32 ||
		!writeMetadataPattern.MatchString(request.IdempotencyKey) || !writeMetadataPattern.MatchString(request.RequestID) {
		return L2ConditionWriteRequest{}, ErrInvalidInput
	}
	rules := make([]L2Rule, len(request.Rules))
	for index, rule := range request.Rules {
		rule.Value = strings.TrimSpace(rule.Value)
		if !slices.Contains(l2RuleFields, rule.Field) || !slices.Contains(l2RuleOperators, rule.Operator) ||
			!validL2Text(rule.Value, 1, 1024) {
			return L2ConditionWriteRequest{}, ErrInvalidInput
		}
		// The node matches with ngx.re (PCRE); an RE2 pattern (no
		// backreferences or lookaround) in printable ASCII means the same
		// there, as httppolicycontrol.normalizeRegexPattern (edgesite
		// ValidateL2Conditions refuses anything else).
		if rule.Operator == "regex" || rule.Operator == "not_regex" {
			if _, err := regexp.Compile(rule.Value); err != nil || !printableASCII(rule.Value) {
				return L2ConditionWriteRequest{}, &L2RuleRegexError{Index: index}
			}
		}
		rules[index] = rule
	}
	request.Rules = rules
	return request, nil
}

func normalizeL2NodeAdd(request L2NodeAddRequest) (L2NodeAddRequest, error) {
	if request.ConfigID == uuid.Nil || request.ExpectedRevision != 0 || len(request.NodeIDs) < 1 || len(request.NodeIDs) > 512 ||
		request.ConditionID != nil && *request.ConditionID == uuid.Nil ||
		!writeMetadataPattern.MatchString(request.IdempotencyKey) || !writeMetadataPattern.MatchString(request.RequestID) {
		return L2NodeAddRequest{}, ErrInvalidInput
	}
	seen := make(map[uuid.UUID]struct{}, len(request.NodeIDs))
	for _, nodeID := range request.NodeIDs {
		if nodeID == uuid.Nil {
			return L2NodeAddRequest{}, ErrInvalidInput
		}
		if _, exists := seen[nodeID]; exists {
			return L2NodeAddRequest{}, ErrInvalidInput
		}
		seen[nodeID] = struct{}{}
	}
	slices.SortFunc(request.NodeIDs, func(left, right uuid.UUID) int { return strings.Compare(left.String(), right.String()) })
	return request, nil
}

func normalizeL2NodeWrite(request L2NodeWriteRequest) (L2NodeWriteRequest, error) {
	if request.MembershipID == uuid.Nil || request.ExpectedRevision < 1 || request.Weight < 1 || request.Weight > 100 ||
		request.Sort < 0 || request.Sort > 999999 || request.ConditionID != nil && *request.ConditionID == uuid.Nil ||
		!writeMetadataPattern.MatchString(request.IdempotencyKey) || !writeMetadataPattern.MatchString(request.RequestID) {
		return L2NodeWriteRequest{}, ErrInvalidInput
	}
	return request, nil
}

func validL2Text(value string, minimum, maximum int) bool {
	length := utf8.RuneCountInString(value)
	return utf8.ValidString(value) && length >= minimum && length <= maximum && strings.IndexFunc(value, unicode.IsControl) < 0
}

func (s *Service) ListL2Configs(ctx context.Context, actor Actor) ([]L2Config, error) {
	if !validL2Actor(ctx, actor) {
		return nil, ErrInvalidInput
	}
	result := []L2Config{}
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if err := s.authorizeTx(ctx, tx, actor, permissionRead, false); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `SELECT id,display_id::text,tenant_scope_id,revision,name,region,remark,mode,load_method,created_at,updated_at
			FROM l2_topology_configs WHERE tenant_scope_id=$1 AND deleted_at IS NULL ORDER BY display_id`, actor.ResourceScopeID())
		if err != nil {
			return fmt.Errorf("list L2 configs: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var item L2Config
			if err := rows.Scan(&item.ID, &item.DisplayID, &item.TenantScopeID, &item.Revision, &item.Name, &item.Region,
				&item.Remark, &item.Mode, &item.LoadMethod, &item.CreatedAt, &item.UpdatedAt); err != nil {
				return fmt.Errorf("scan L2 config: %w", err)
			}
			result = append(result, item)
		}
		return rows.Err()
	})
	return result, err
}

func (s *Service) GetL2Config(ctx context.Context, actor Actor, configID uuid.UUID) (L2Config, error) {
	if !validL2Actor(ctx, actor) || configID == uuid.Nil {
		return L2Config{}, ErrInvalidInput
	}
	var result L2Config
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if err := s.authorizeTx(ctx, tx, actor, permissionRead, false); err != nil {
			return err
		}
		return scanL2Config(tx.QueryRow(ctx, `SELECT id,display_id::text,tenant_scope_id,revision,name,region,remark,mode,load_method,created_at,updated_at
			FROM l2_topology_configs WHERE tenant_scope_id=$1 AND id=$2 AND deleted_at IS NULL`, actor.ResourceScopeID(), configID), &result)
	})
	return result, err
}

func (s *Service) PutL2Config(ctx context.Context, actor Actor, request L2ConfigWriteRequest) (L2ConfigWriteResult, error) {
	if !validL2Actor(ctx, actor) {
		return L2ConfigWriteResult{}, ErrInvalidInput
	}
	normalized, err := normalizeL2ConfigWrite(request)
	if err != nil {
		return L2ConfigWriteResult{}, err
	}
	create := normalized.ConfigID == uuid.Nil
	if create != (normalized.ExpectedRevision == 0) {
		return L2ConfigWriteResult{}, ErrInvalidInput
	}
	operation := operationL2ConfigUpdate
	if create {
		operation = operationL2ConfigCreate
	}
	digest := l2Digest(struct {
		ScopeID    uuid.UUID
		ConfigID   uuid.UUID
		Revision   int64
		Name       string
		Region     string
		Remark     string
		Mode       string
		LoadMethod string
	}{actor.ResourceScopeID(), normalized.ConfigID, normalized.ExpectedRevision, normalized.Name, normalized.Region, normalized.Remark, normalized.Mode, normalized.LoadMethod})
	now := s.now().UTC().Truncate(time.Microsecond)
	var result L2ConfigWriteResult
	err = pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if err := s.authorizeTx(ctx, tx, actor, permissionManage, true); err != nil {
			return err
		}
		stored, replayed, err := claimL2Write(ctx, tx, actor, operation, normalized.IdempotencyKey, digest, now)
		if err != nil {
			return err
		}
		if replayed {
			if err := json.Unmarshal(stored, &result); err != nil {
				return fmt.Errorf("decode L2 config replay: %w", err)
			}
			result.Replayed = true
			return nil
		}
		if create {
			normalized.ConfigID, err = uuid.NewV7()
			if err != nil {
				return err
			}
			err = scanL2Config(tx.QueryRow(ctx, `INSERT INTO l2_topology_configs(
				id,tenant_scope_id,name,region,remark,mode,load_method,revision,created_by_user_id,updated_by_user_id,created_at,updated_at)
				VALUES($1,$2,$3,$4,$5,$6,$7,1,$8,$8,$9,$9)
				RETURNING id,display_id::text,tenant_scope_id,revision,name,region,remark,mode,load_method,created_at,updated_at`,
				normalized.ConfigID, actor.ResourceScopeID(), normalized.Name, normalized.Region, normalized.Remark,
				normalized.Mode, normalized.LoadMethod, actor.UserID, now), &result.Config)
		} else {
			err = scanL2Config(tx.QueryRow(ctx, `UPDATE l2_topology_configs SET name=$4,region=$5,remark=$6,mode=$7,load_method=$8,
				revision=revision+1,updated_by_user_id=$9,updated_at=$10
				WHERE tenant_scope_id=$1 AND id=$2 AND revision=$3 AND deleted_at IS NULL
				RETURNING id,display_id::text,tenant_scope_id,revision,name,region,remark,mode,load_method,created_at,updated_at`,
				actor.ResourceScopeID(), normalized.ConfigID, normalized.ExpectedRevision, normalized.Name, normalized.Region,
				normalized.Remark, normalized.Mode, normalized.LoadMethod, actor.UserID, now), &result.Config)
		}
		if !create && errors.Is(err, ErrNotFound) {
			return l2MissingOrConflict(ctx, tx, "l2_topology_configs", actor.ResourceScopeID(), normalized.ConfigID)
		}
		if err != nil {
			return classifyL2WriteError(err, !create)
		}
		if err := s.appendL2Audit(ctx, tx, actor, operation, "l2_config", result.Config.ID, result.Config.Revision, normalized.RequestID); err != nil {
			return err
		}
		if err := s.publishL2WriteTx(ctx, tx, actor, result.Config.ID, normalized.RequestID); err != nil {
			return err
		}
		return completeL2Write(ctx, tx, actor, operation, normalized.IdempotencyKey, result, now)
	})
	if err != nil {
		return L2ConfigWriteResult{}, fmt.Errorf("put L2 config: %w", err)
	}
	return result, nil
}

func (s *Service) DeleteL2Config(ctx context.Context, actor Actor, configID uuid.UUID, revision int64, key, requestID string) (L2DeleteResult, error) {
	return s.deleteL2Resource(ctx, actor, "l2_topology_configs", "l2_topology_nodes", "config_id", "l2_config",
		operationL2ConfigDelete, configID, revision, key, requestID)
}

func (s *Service) ListL2Conditions(ctx context.Context, actor Actor) ([]L2Condition, error) {
	if !validL2Actor(ctx, actor) {
		return nil, ErrInvalidInput
	}
	result := []L2Condition{}
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if err := s.authorizeTx(ctx, tx, actor, permissionRead, false); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `SELECT id,display_id::text,tenant_scope_id,revision,name,remark,rules,created_at,updated_at
			FROM l2_topology_conditions WHERE tenant_scope_id=$1 AND deleted_at IS NULL ORDER BY display_id`, actor.ResourceScopeID())
		if err != nil {
			return fmt.Errorf("list L2 conditions: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var item L2Condition
			var rules []byte
			if err := rows.Scan(&item.ID, &item.DisplayID, &item.TenantScopeID, &item.Revision, &item.Name, &item.Remark,
				&rules, &item.CreatedAt, &item.UpdatedAt); err != nil {
				return fmt.Errorf("scan L2 condition: %w", err)
			}
			if err := json.Unmarshal(rules, &item.Rules); err != nil {
				return fmt.Errorf("decode L2 condition rules: %w", err)
			}
			result = append(result, item)
		}
		return rows.Err()
	})
	return result, err
}

func (s *Service) PutL2Condition(ctx context.Context, actor Actor, request L2ConditionWriteRequest) (L2ConditionWriteResult, error) {
	if !validL2Actor(ctx, actor) {
		return L2ConditionWriteResult{}, ErrInvalidInput
	}
	normalized, err := normalizeL2ConditionWrite(request)
	if err != nil {
		return L2ConditionWriteResult{}, err
	}
	create := normalized.ConditionID == uuid.Nil
	if create != (normalized.ExpectedRevision == 0) {
		return L2ConditionWriteResult{}, ErrInvalidInput
	}
	operation := operationL2ConditionUpdate
	if create {
		operation = operationL2ConditionCreate
	}
	digest := l2Digest(struct {
		ScopeID     uuid.UUID
		ConditionID uuid.UUID
		Revision    int64
		Name        string
		Remark      string
		Rules       []L2Rule
	}{actor.ResourceScopeID(), normalized.ConditionID, normalized.ExpectedRevision, normalized.Name, normalized.Remark, normalized.Rules})
	rules, _ := json.Marshal(normalized.Rules)
	now := s.now().UTC().Truncate(time.Microsecond)
	var result L2ConditionWriteResult
	err = pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if err := s.authorizeTx(ctx, tx, actor, permissionManage, true); err != nil {
			return err
		}
		stored, replayed, err := claimL2Write(ctx, tx, actor, operation, normalized.IdempotencyKey, digest, now)
		if err != nil {
			return err
		}
		if replayed {
			if err := json.Unmarshal(stored, &result); err != nil {
				return fmt.Errorf("decode L2 condition replay: %w", err)
			}
			result.Replayed = true
			return nil
		}
		if create {
			normalized.ConditionID, err = uuid.NewV7()
			if err != nil {
				return err
			}
			err = scanL2Condition(tx.QueryRow(ctx, `INSERT INTO l2_topology_conditions(
				id,tenant_scope_id,name,remark,rules,revision,created_by_user_id,updated_by_user_id,created_at,updated_at)
				VALUES($1,$2,$3,$4,$5,1,$6,$6,$7,$7)
				RETURNING id,display_id::text,tenant_scope_id,revision,name,remark,rules,created_at,updated_at`,
				normalized.ConditionID, actor.ResourceScopeID(), normalized.Name, normalized.Remark, rules, actor.UserID, now), &result.Condition)
		} else {
			err = scanL2Condition(tx.QueryRow(ctx, `UPDATE l2_topology_conditions SET name=$4,remark=$5,rules=$6,
				revision=revision+1,updated_by_user_id=$7,updated_at=$8
				WHERE tenant_scope_id=$1 AND id=$2 AND revision=$3 AND deleted_at IS NULL
				RETURNING id,display_id::text,tenant_scope_id,revision,name,remark,rules,created_at,updated_at`,
				actor.ResourceScopeID(), normalized.ConditionID, normalized.ExpectedRevision, normalized.Name,
				normalized.Remark, rules, actor.UserID, now), &result.Condition)
		}
		if err != nil {
			return classifyL2WriteError(err, !create)
		}
		if err := s.appendL2Audit(ctx, tx, actor, operation, "l2_condition", result.Condition.ID, result.Condition.Revision, normalized.RequestID); err != nil {
			return err
		}
		if err := s.publishL2WriteTx(ctx, tx, actor, result.Condition.ID, normalized.RequestID); err != nil {
			return err
		}
		return completeL2Write(ctx, tx, actor, operation, normalized.IdempotencyKey, result, now)
	})
	if err != nil {
		return L2ConditionWriteResult{}, fmt.Errorf("put L2 condition: %w", err)
	}
	return result, nil
}

func (s *Service) DeleteL2Condition(ctx context.Context, actor Actor, conditionID uuid.UUID, revision int64, key, requestID string) (L2DeleteResult, error) {
	return s.deleteL2Resource(ctx, actor, "l2_topology_conditions", "l2_topology_nodes", "condition_id", "l2_condition",
		operationL2ConditionDelete, conditionID, revision, key, requestID)
}

func (s *Service) ListL2Nodes(ctx context.Context, actor Actor, configID uuid.UUID) ([]L2Node, error) {
	if !validL2Actor(ctx, actor) || configID == uuid.Nil {
		return nil, ErrInvalidInput
	}
	result := []L2Node{}
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if err := s.authorizeTx(ctx, tx, actor, permissionRead, false); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `SELECT membership.id,membership.display_id::text,membership.tenant_scope_id,membership.config_id,
			membership.node_id,membership.condition_id,condition.name,membership.revision,node.name,
			COALESCE(host(node.ipv4),host(node.ipv6),''),node.admin_state,COALESCE(presence.status,'unknown'),
			membership.enabled,membership.weight,membership.sort_order
			FROM l2_topology_nodes membership JOIN nodes node ON node.scope_id=membership.tenant_scope_id AND node.id=membership.node_id
			LEFT JOIN node_presence presence ON presence.node_id=node.id
			LEFT JOIN l2_topology_conditions condition ON condition.tenant_scope_id=membership.tenant_scope_id
			 AND condition.id=membership.condition_id AND condition.deleted_at IS NULL
			WHERE membership.tenant_scope_id=$1 AND membership.config_id=$2 AND membership.deleted_at IS NULL
			ORDER BY membership.sort_order,membership.display_id`, actor.ResourceScopeID(), configID)
		if err != nil {
			return fmt.Errorf("list L2 nodes: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var item L2Node
			if err := scanL2Node(rows, &item); err != nil {
				return err
			}
			result = append(result, item)
		}
		return rows.Err()
	})
	return result, err
}

func (s *Service) ListAvailableL2Nodes(ctx context.Context, actor Actor, configID uuid.UUID) ([]L2NodeCandidate, error) {
	if !validL2Actor(ctx, actor) || configID == uuid.Nil {
		return nil, ErrInvalidInput
	}
	result := []L2NodeCandidate{}
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if err := s.authorizeTx(ctx, tx, actor, permissionRead, false); err != nil {
			return err
		}
		var exists bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM l2_topology_configs
			WHERE tenant_scope_id=$1 AND id=$2 AND deleted_at IS NULL)`, actor.ResourceScopeID(), configID).Scan(&exists); err != nil {
			return err
		}
		if !exists {
			return ErrNotFound
		}
		rows, err := tx.Query(ctx, `SELECT node.id,node.display_id::text,node.name,COALESCE(host(node.ipv4),host(node.ipv6),''),
			node.admin_state,COALESCE(presence.status,'unknown') FROM nodes node
			LEFT JOIN node_presence presence ON presence.node_id=node.id
			WHERE node.scope_id=$1 AND node.admin_state<>'retired' AND NOT EXISTS(
				SELECT 1 FROM l2_topology_nodes membership WHERE membership.tenant_scope_id=$1
				AND membership.node_id=node.id AND membership.deleted_at IS NULL)
			ORDER BY node.display_id`, actor.ResourceScopeID())
		if err != nil {
			return fmt.Errorf("list available L2 nodes: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var item L2NodeCandidate
			if err := rows.Scan(&item.NodeID, &item.DisplayID, &item.Name, &item.IPAddress, &item.AdminState, &item.OnlineStatus); err != nil {
				return fmt.Errorf("scan available L2 node: %w", err)
			}
			result = append(result, item)
		}
		return rows.Err()
	})
	return result, err
}

func (s *Service) AddL2Nodes(ctx context.Context, actor Actor, request L2NodeAddRequest) (L2NodeAddResult, error) {
	if !validL2Actor(ctx, actor) {
		return L2NodeAddResult{}, ErrInvalidInput
	}
	normalized, err := normalizeL2NodeAdd(request)
	if err != nil {
		return L2NodeAddResult{}, err
	}
	digest := l2Digest(struct {
		ScopeID     uuid.UUID
		ConfigID    uuid.UUID
		NodeIDs     []uuid.UUID
		ConditionID *uuid.UUID
	}{actor.ResourceScopeID(), normalized.ConfigID, normalized.NodeIDs, normalized.ConditionID})
	now := s.now().UTC().Truncate(time.Microsecond)
	result := L2NodeAddResult{Items: []L2Node{}}
	err = pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if err := s.authorizeTx(ctx, tx, actor, permissionManage, true); err != nil {
			return err
		}
		stored, replayed, err := claimL2Write(ctx, tx, actor, operationL2NodeAdd, normalized.IdempotencyKey, digest, now)
		if err != nil {
			return err
		}
		if replayed {
			if err := json.Unmarshal(stored, &result); err != nil {
				return fmt.Errorf("decode L2 node add replay: %w", err)
			}
			result.Replayed = true
			return nil
		}
		if err := validateL2References(ctx, tx, actor.ResourceScopeID(), normalized.ConfigID, normalized.ConditionID); err != nil {
			return err
		}
		for index, nodeID := range normalized.NodeIDs {
			membershipID, err := uuid.NewV7()
			if err != nil {
				return err
			}
			var nodeExists bool
			if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM nodes WHERE scope_id=$1 AND id=$2 AND admin_state<>'retired')`,
				actor.ResourceScopeID(), nodeID).Scan(&nodeExists); err != nil {
				return err
			}
			if !nodeExists {
				return ErrInvalidInput
			}
			if _, err := tx.Exec(ctx, `INSERT INTO l2_topology_nodes(
				id,tenant_scope_id,config_id,node_id,condition_id,revision,enabled,weight,sort_order,
				created_by_user_id,updated_by_user_id,created_at,updated_at)
				VALUES($1,$2,$3,$4,$5,1,true,100,$6,$7,$7,$8,$8)`, membershipID, actor.ResourceScopeID(),
				normalized.ConfigID, nodeID, normalized.ConditionID, index*10, actor.UserID, now); err != nil {
				return classifyL2WriteError(err, false)
			}
			item, err := loadL2Node(ctx, tx, actor.ResourceScopeID(), membershipID)
			if err != nil {
				return err
			}
			result.Items = append(result.Items, item)
		}
		if err := s.appendL2Audit(ctx, tx, actor, operationL2NodeAdd, "l2_config", normalized.ConfigID, 0, normalized.RequestID); err != nil {
			return err
		}
		if err := s.publishL2WriteTx(ctx, tx, actor, normalized.ConfigID, normalized.RequestID); err != nil {
			return err
		}
		return completeL2Write(ctx, tx, actor, operationL2NodeAdd, normalized.IdempotencyKey, result, now)
	})
	if err != nil {
		return L2NodeAddResult{}, fmt.Errorf("add L2 nodes: %w", err)
	}
	return result, nil
}

func (s *Service) PutL2Node(ctx context.Context, actor Actor, request L2NodeWriteRequest) (L2NodeWriteResult, error) {
	if !validL2Actor(ctx, actor) {
		return L2NodeWriteResult{}, ErrInvalidInput
	}
	normalized, err := normalizeL2NodeWrite(request)
	if err != nil {
		return L2NodeWriteResult{}, err
	}
	digest := l2Digest(struct {
		ScopeID      uuid.UUID
		MembershipID uuid.UUID
		Revision     int64
		ConditionID  *uuid.UUID
		Enabled      bool
		Weight       int
		Sort         int
	}{actor.ResourceScopeID(), normalized.MembershipID, normalized.ExpectedRevision, normalized.ConditionID,
		normalized.Enabled, normalized.Weight, normalized.Sort})
	now := s.now().UTC().Truncate(time.Microsecond)
	var result L2NodeWriteResult
	err = pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if err := s.authorizeTx(ctx, tx, actor, permissionManage, true); err != nil {
			return err
		}
		stored, replayed, err := claimL2Write(ctx, tx, actor, operationL2NodeUpdate, normalized.IdempotencyKey, digest, now)
		if err != nil {
			return err
		}
		if replayed {
			if err := json.Unmarshal(stored, &result); err != nil {
				return fmt.Errorf("decode L2 node replay: %w", err)
			}
			result.Replayed = true
			return nil
		}
		if normalized.ConditionID != nil {
			if err := validateL2Condition(ctx, tx, actor.ResourceScopeID(), normalized.ConditionID); err != nil {
				return err
			}
		}
		command, err := tx.Exec(ctx, `UPDATE l2_topology_nodes SET condition_id=$4,enabled=$5,weight=$6,sort_order=$7,
			revision=revision+1,updated_by_user_id=$8,updated_at=$9
			WHERE tenant_scope_id=$1 AND id=$2 AND revision=$3 AND deleted_at IS NULL`, actor.ResourceScopeID(),
			normalized.MembershipID, normalized.ExpectedRevision, normalized.ConditionID, normalized.Enabled,
			normalized.Weight, normalized.Sort, actor.UserID, now)
		if err != nil {
			return classifyL2WriteError(err, true)
		}
		if command.RowsAffected() != 1 {
			return l2MissingOrConflict(ctx, tx, "l2_topology_nodes", actor.ResourceScopeID(), normalized.MembershipID)
		}
		result.Node, err = loadL2Node(ctx, tx, actor.ResourceScopeID(), normalized.MembershipID)
		if err != nil {
			return err
		}
		if err := s.appendL2Audit(ctx, tx, actor, operationL2NodeUpdate, "l2_node", result.Node.ID, result.Node.Revision, normalized.RequestID); err != nil {
			return err
		}
		if err := s.publishL2WriteTx(ctx, tx, actor, result.Node.ID, normalized.RequestID); err != nil {
			return err
		}
		return completeL2Write(ctx, tx, actor, operationL2NodeUpdate, normalized.IdempotencyKey, result, now)
	})
	if err != nil {
		return L2NodeWriteResult{}, fmt.Errorf("put L2 node: %w", err)
	}
	return result, nil
}

func (s *Service) DeleteL2Node(ctx context.Context, actor Actor, membershipID uuid.UUID, revision int64, key, requestID string) (L2DeleteResult, error) {
	return s.deleteL2Resource(ctx, actor, "l2_topology_nodes", "", "", "l2_node",
		operationL2NodeDelete, membershipID, revision, key, requestID)
}

func (s *Service) deleteL2Resource(
	ctx context.Context,
	actor Actor,
	table, referenceTable, referenceColumn, resourceType, operation string,
	id uuid.UUID,
	revision int64,
	key, requestID string,
) (L2DeleteResult, error) {
	if !validL2Actor(ctx, actor) || id == uuid.Nil || revision < 1 ||
		!writeMetadataPattern.MatchString(key) || !writeMetadataPattern.MatchString(requestID) {
		return L2DeleteResult{}, ErrInvalidInput
	}
	digest := l2Digest(struct {
		ScopeID  uuid.UUID
		ID       uuid.UUID
		Revision int64
	}{actor.ResourceScopeID(), id, revision})
	now := s.now().UTC().Truncate(time.Microsecond)
	var result L2DeleteResult
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if err := s.authorizeTx(ctx, tx, actor, permissionManage, true); err != nil {
			return err
		}
		stored, replayed, err := claimL2Write(ctx, tx, actor, operation, key, digest, now)
		if err != nil {
			return err
		}
		if replayed {
			if err := json.Unmarshal(stored, &result); err != nil {
				return fmt.Errorf("decode L2 delete replay: %w", err)
			}
			result.Replayed = true
			return nil
		}
		if referenceTable != "" {
			var referenced bool
			query := fmt.Sprintf(`SELECT EXISTS(SELECT 1 FROM %s WHERE tenant_scope_id=$1 AND %s=$2 AND deleted_at IS NULL)`,
				referenceTable, referenceColumn)
			if err := tx.QueryRow(ctx, query, actor.ResourceScopeID(), id).Scan(&referenced); err != nil {
				return err
			}
			if referenced {
				return ErrReferenceConflict
			}
		}
		query := fmt.Sprintf(`UPDATE %s SET deleted_at=$4,deleted_by_user_id=$5,updated_by_user_id=$5,updated_at=$4
			WHERE tenant_scope_id=$1 AND id=$2 AND revision=$3 AND deleted_at IS NULL`, table)
		command, err := tx.Exec(ctx, query, actor.ResourceScopeID(), id, revision, now, actor.UserID)
		if err != nil {
			return classifyL2WriteError(err, true)
		}
		if command.RowsAffected() != 1 {
			return l2MissingOrConflict(ctx, tx, table, actor.ResourceScopeID(), id)
		}
		result = L2DeleteResult{ID: id, Revision: revision, DeletedAt: now}
		if err := s.appendL2Audit(ctx, tx, actor, operation, resourceType, id, revision, requestID); err != nil {
			return err
		}
		if err := s.publishL2WriteTx(ctx, tx, actor, id, requestID); err != nil {
			return err
		}
		return completeL2Write(ctx, tx, actor, operation, key, result, now)
	})
	if err != nil {
		return L2DeleteResult{}, fmt.Errorf("delete %s: %w", resourceType, err)
	}
	return result, nil
}

func validL2Actor(ctx context.Context, actor Actor) bool {
	return ctx != nil && actor.UserID != uuid.Nil && actor.ScopeID != uuid.Nil && actor.ResourceScopeID() != uuid.Nil
}

func validateL2References(ctx context.Context, tx pgx.Tx, scopeID, configID uuid.UUID, conditionID *uuid.UUID) error {
	var exists bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM l2_topology_configs
		WHERE tenant_scope_id=$1 AND id=$2 AND deleted_at IS NULL)`, scopeID, configID).Scan(&exists); err != nil {
		return err
	}
	if !exists {
		return ErrInvalidInput
	}
	return validateL2Condition(ctx, tx, scopeID, conditionID)
}

func validateL2Condition(ctx context.Context, tx pgx.Tx, scopeID uuid.UUID, conditionID *uuid.UUID) error {
	if conditionID == nil {
		return nil
	}
	var exists bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM l2_topology_conditions
		WHERE tenant_scope_id=$1 AND id=$2 AND deleted_at IS NULL)`, scopeID, *conditionID).Scan(&exists); err != nil {
		return err
	}
	if !exists {
		return ErrInvalidInput
	}
	return nil
}

func loadL2Node(ctx context.Context, tx pgx.Tx, scopeID, membershipID uuid.UUID) (L2Node, error) {
	var result L2Node
	err := scanL2Node(tx.QueryRow(ctx, `SELECT membership.id,membership.display_id::text,membership.tenant_scope_id,membership.config_id,
		membership.node_id,membership.condition_id,condition.name,membership.revision,node.name,
		COALESCE(host(node.ipv4),host(node.ipv6),''),node.admin_state,COALESCE(presence.status,'unknown'),
		membership.enabled,membership.weight,membership.sort_order
		FROM l2_topology_nodes membership JOIN nodes node ON node.scope_id=membership.tenant_scope_id AND node.id=membership.node_id
		LEFT JOIN node_presence presence ON presence.node_id=node.id
		LEFT JOIN l2_topology_conditions condition ON condition.tenant_scope_id=membership.tenant_scope_id
		 AND condition.id=membership.condition_id AND condition.deleted_at IS NULL
		WHERE membership.tenant_scope_id=$1 AND membership.id=$2 AND membership.deleted_at IS NULL`, scopeID, membershipID), &result)
	if errors.Is(err, pgx.ErrNoRows) {
		return L2Node{}, ErrNotFound
	}
	return result, err
}

type l2Scanner interface{ Scan(...any) error }

func scanL2Config(row l2Scanner, target *L2Config) error {
	err := row.Scan(&target.ID, &target.DisplayID, &target.TenantScopeID, &target.Revision, &target.Name, &target.Region,
		&target.Remark, &target.Mode, &target.LoadMethod, &target.CreatedAt, &target.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	return err
}

func scanL2Condition(row l2Scanner, target *L2Condition) error {
	var rules []byte
	err := row.Scan(&target.ID, &target.DisplayID, &target.TenantScopeID, &target.Revision, &target.Name,
		&target.Remark, &rules, &target.CreatedAt, &target.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	return json.Unmarshal(rules, &target.Rules)
}

func scanL2Node(row l2Scanner, target *L2Node) error {
	err := row.Scan(&target.ID, &target.DisplayID, &target.TenantScopeID, &target.ConfigID, &target.NodeID,
		&target.ConditionID, &target.ConditionName, &target.Revision, &target.Name, &target.IPAddress,
		&target.AdminState, &target.OnlineStatus, &target.Enabled, &target.Weight, &target.Sort)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("scan L2 node: %w", err)
	}
	return nil
}

func (s *Service) appendL2Audit(
	ctx context.Context,
	tx pgx.Tx,
	actor Actor,
	action, resourceType string,
	resourceID uuid.UUID,
	revision int64,
	requestID string,
) error {
	return s.auditor.Append(ctx, tx, audit.Event{
		ScopeID: actor.ResourceScopeID(), ActorUserID: &actor.UserID, Action: action,
		ResourceType: resourceType, ResourceID: resourceID.String(), RequestID: requestID,
		Result: "success", Payload: map[string]any{"revision": revision},
	})
}

func l2Digest(value any) [32]byte {
	payload, _ := json.Marshal(value)
	return sha256.Sum256(payload)
}

func claimL2Write(
	ctx context.Context,
	tx pgx.Tx,
	actor Actor,
	operation, key string,
	digest [32]byte,
	now time.Time,
) ([]byte, bool, error) {
	writeID, err := uuid.NewV7()
	if err != nil {
		return nil, false, err
	}
	command, err := tx.Exec(ctx, `INSERT INTO l2_topology_write_requests(
		id,tenant_scope_id,actor_scope_id,actor_user_id,operation,idempotency_key,request_digest,created_at)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8)
		ON CONFLICT(tenant_scope_id,actor_user_id,operation,idempotency_key) DO NOTHING`,
		writeID, actor.ResourceScopeID(), actor.ScopeID, actor.UserID, operation, key, digest[:], now)
	if err != nil {
		return nil, false, err
	}
	if command.RowsAffected() == 1 {
		return nil, false, nil
	}
	var existingDigest, response []byte
	var completedAt *time.Time
	if err := tx.QueryRow(ctx, `SELECT request_digest,response_body,completed_at FROM l2_topology_write_requests
		WHERE tenant_scope_id=$1 AND actor_user_id=$2 AND operation=$3 AND idempotency_key=$4`,
		actor.ResourceScopeID(), actor.UserID, operation, key).Scan(&existingDigest, &response, &completedAt); err != nil {
		return nil, false, err
	}
	if completedAt == nil || len(response) == 0 || !slices.Equal(existingDigest, digest[:]) {
		return nil, false, ErrIdempotencyConflict
	}
	return response, true, nil
}

func completeL2Write(
	ctx context.Context,
	tx pgx.Tx,
	actor Actor,
	operation, key string,
	result any,
	now time.Time,
) error {
	encoded, err := json.Marshal(result)
	if err != nil {
		return err
	}
	command, err := tx.Exec(ctx, `UPDATE l2_topology_write_requests SET response_body=$5,completed_at=$6
		WHERE tenant_scope_id=$1 AND actor_user_id=$2 AND operation=$3 AND idempotency_key=$4 AND completed_at IS NULL`,
		actor.ResourceScopeID(), actor.UserID, operation, key, encoded, now)
	if err != nil {
		return err
	}
	if command.RowsAffected() != 1 {
		return ErrIdempotencyConflict
	}
	return nil
}

func l2MissingOrConflict(ctx context.Context, tx pgx.Tx, table string, scopeID, id uuid.UUID) error {
	var exists bool
	query := fmt.Sprintf(`SELECT EXISTS(SELECT 1 FROM %s WHERE tenant_scope_id=$1 AND id=$2 AND deleted_at IS NULL)`, table)
	if err := tx.QueryRow(ctx, query, scopeID, id).Scan(&exists); err != nil {
		return err
	}
	if exists {
		return ErrRevisionConflict
	}
	return ErrNotFound
}

func classifyL2WriteError(err error, updating bool) error {
	if errors.Is(err, pgx.ErrNoRows) {
		if updating {
			return ErrRevisionConflict
		}
		return ErrNotFound
	}
	var databaseError *pgconn.PgError
	if errors.As(err, &databaseError) {
		switch databaseError.Code {
		case "23505":
			if strings.Contains(databaseError.ConstraintName, "name") {
				return ErrNameConflict
			}
			return ErrReferenceConflict
		case "23503", "23514":
			return ErrInvalidInput
		case "P5044":
			// migration 504: a line group or a site uses the configuration
			return ErrReferenceConflict
		}
	}
	return err
}

func printableASCII(value string) bool {
	for index := 0; index < len(value); index++ {
		if value[index] < 0x20 || value[index] > 0x7e {
			return false
		}
	}
	return true
}
