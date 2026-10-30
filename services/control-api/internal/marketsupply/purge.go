package marketsupply

import (
	"context"
	"errors"
	"strconv"
	"strings"

	"github.com/cdnca/cdnca/libs/marketproto/siteconf"
	"github.com/cdnca/cdnca/services/control-api/internal/cachecontrol"
	"github.com/google/uuid"
)

// maxPurgeTargets is cachecontrol's per-operation target limit; a longer
// list becomes several operations.
const maxPurgeTargets = 500

// CacheOperations is the subset of cachecontrol.Store a leaf purge drives.
type CacheOperations interface {
	CreateOperation(ctx context.Context, actor cachecontrol.Actor, request cachecontrol.CreateOperationRequest) (cachecontrol.OperationWriteResult, error)
}

var ErrNoCarryingNode = errors.New("market supply: no node carries the site yet")

// WithPurge lets a subscriber purge its leaf site's cache (OpPurge); without
// it the operation is not supported.
func (s *Service) WithPurge(operations CacheOperations) *Service {
	s.purge = operations
	return s
}

// purgeSite purges as the tenant owner on every node the tenant's current
// configuration is on. URLs are exact; dirs are prefixes; neither purges the
// whole site. A bare path is taken on the site's primary domain.
func (s *Service) purgeSite(ctx context.Context, tenant tenantRef, current siteRef, req siteconf.PurgeRequest,
	messageID uuid.UUID,
) ([]uuid.UUID, error) {
	if s.purge == nil {
		return nil, ErrUnsupportedOp
	}
	var nodes []uuid.UUID
	if err := s.pool.QueryRow(ctx, `SELECT COALESCE(array_agg(state.node_id ORDER BY state.node_id), '{}')
		FROM node_config_state state JOIN nodes node ON node.id=state.node_id AND node.admin_state='active'
		WHERE state.configuration_scope_id=$1 AND state.current_config_version_id IS NOT NULL`,
		tenant.scopeID).Scan(&nodes); err != nil {
		return nil, err
	}
	if len(nodes) == 0 {
		return nil, ErrNoCarryingNode
	}
	type batch struct {
		kind    cachecontrol.TargetType
		targets []string
	}
	var batches []batch
	for _, group := range []struct {
		kind  cachecontrol.TargetType
		items []string
	}{{cachecontrol.TargetExactURL, req.URLs}, {cachecontrol.TargetDirectoryPrefix, req.Dirs}} {
		for start := 0; start < len(group.items); start += maxPurgeTargets {
			end := min(start+maxPurgeTargets, len(group.items))
			targets := make([]string, 0, end-start)
			for _, item := range group.items[start:end] {
				targets = append(targets, current.absolute(item))
			}
			batches = append(batches, batch{group.kind, targets})
		}
	}
	if len(batches) == 0 {
		batches = []batch{{kind: cachecontrol.TargetWholeSite}}
	}
	actor := cachecontrol.Actor{UserID: tenant.userID, ScopeID: tenant.scopeID, ActorScopeID: tenant.scopeID}
	operations := make([]uuid.UUID, 0, len(batches))
	for index, b := range batches {
		key := "market-purge-" + messageID.String() + "-" + strconv.Itoa(index)
		result, err := s.purge.CreateOperation(ctx, actor, cachecontrol.CreateOperationRequest{
			SiteID: current.id, Action: cachecontrol.ActionPurge, TargetType: b.kind, Targets: b.targets,
			NodeIDs: nodes, MaxRetries: 3, IdempotencyKey: key, RequestID: key,
		})
		if err != nil {
			return operations, err
		}
		operations = append(operations, result.Operation.ID)
	}
	return operations, nil
}

// siteRef is what a purge needs of the leaf site.
type siteRef struct {
	id     uuid.UUID
	domain string
	https  bool
}

// absolute turns a bare path into a URL on the site's primary domain, using
// https only for a site that serves nothing over http.
func (r siteRef) absolute(target string) string {
	if strings.Contains(target, "://") {
		return target
	}
	scheme := "http"
	if r.https {
		scheme = "https"
	}
	if !strings.HasPrefix(target, "/") {
		target = "/" + target
	}
	return scheme + "://" + r.domain + target
}
