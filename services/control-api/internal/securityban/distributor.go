package securityban

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"sync"
	"time"

	contract "github.com/cdnca/cdnca/libs/edgeconfig/securityban"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/protobuf/proto"
)

// Transport carries snapshots to agent-gateway and receipts back.
type Transport interface {
	PublishList(ctx context.Context, nodeID string, revision uint64, encoded []byte) error
	// NextReceipt waits up to the transport's poll timeout; (nil, nil) when nothing arrived.
	NextReceipt(ctx context.Context) (ReceiptDelivery, error)
}

type ReceiptDelivery interface {
	Status() *agentv1.SecurityBanStatus
	Ack(context.Context) error
	Nak(context.Context) error
}

type DistributorConfig struct {
	Pool      *pgxpool.Pool
	Transport Transport
	KeyID     string
	Sign      func(context.Context, []byte) ([]byte, error)
	Interval  time.Duration
	// RetryAfter delays republishing an unanswered snapshot (default 5 minutes).
	RetryAfter time.Duration
	Logger     *slog.Logger
	Now        func() time.Time
	// Alerts receives list truncation alerts (nil: logged only).
	Alerts AlertEnqueuer
}

// Distributor publishes to each node serving a site with bans or recent
// releases the snapshot of those sites, a new revision whenever its content
// changes (a ban added, extended, released or expired), and records the
// node's receipt. A node whose sites lose every entry gets an empty snapshot
// once. The gateway keeps the newest snapshot per node, so an offline node
// converges when it connects.
type Distributor struct {
	config    DistributorConfig
	wake      chan struct{}
	mu        sync.Mutex
	published map[uuid.UUID]published
	lastError string
}

type published struct {
	revision int64
	at       time.Time
}

func NewDistributor(config DistributorConfig) (*Distributor, error) {
	if config.Pool == nil || config.Transport == nil || config.KeyID == "" || config.Sign == nil || config.Interval <= 0 {
		return nil, errors.New("security ban distributor configuration is incomplete")
	}
	if config.RetryAfter <= 0 {
		config.RetryAfter = 5 * time.Minute
	}
	if config.Logger == nil {
		config.Logger = slog.Default()
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	return &Distributor{config: config, wake: make(chan struct{}, 1), published: map[uuid.UUID]published{}}, nil
}

// Wake runs a publication pass soon (the list changed).
func (distributor *Distributor) Wake() {
	select {
	case distributor.wake <- struct{}{}:
	default:
	}
}

func (distributor *Distributor) Run(ctx context.Context) error {
	done := make(chan struct{})
	go func() {
		defer close(done)
		distributor.consumeReceipts(ctx)
	}()
	ticker := time.NewTicker(distributor.config.Interval)
	defer ticker.Stop()
	for {
		distributor.report(distributor.PublishOnce(ctx))
		select {
		case <-ctx.Done():
			<-done
			return ctx.Err()
		case <-ticker.C:
		case <-distributor.wake:
		}
	}
}

type nodeState struct {
	revision        int64
	content         []byte
	appliedRevision int64
}

// content is what one node should hold.
type content struct {
	Bans     []contract.Ban     `json:"bans"`
	Releases []contract.Release `json:"releases"`
	// created: newest creation per (site, client), the truncation tie-break.
	created map[[2]string]time.Time
}

// PublishOnce computes every node's content and publishes the changed ones
// (and unanswered ones after RetryAfter).
func (distributor *Distributor) PublishOnce(ctx context.Context) error {
	now := distributor.config.Now().UTC()
	contents, err := distributor.contents(ctx, now)
	if err != nil {
		return err
	}
	states, err := distributor.states(ctx)
	if err != nil {
		return err
	}
	for nodeID := range states {
		if _, ok := contents[nodeID]; !ok {
			contents[nodeID] = &content{Bans: []contract.Ban{}, Releases: []contract.Release{}}
		}
	}
	var failure error
	for nodeID, value := range contents {
		total := len(value.Bans) + len(value.Releases)
		bans, cut := Truncate(value.Bans, value.Releases, value.created)
		list := contract.List{Bans: bans, Releases: value.Releases}
		list.Canonical()
		encodedContent, err := json.Marshal(content{Bans: list.Bans, Releases: list.Releases})
		if err != nil {
			return err
		}
		digest := sha256.Sum256(encodedContent)
		state, known := states[nodeID]
		if !known && len(list.Bans)+len(list.Releases) == 0 {
			continue
		}
		revision := int64(1)
		if known {
			if bytes.Equal(state.content, digest[:]) {
				if state.appliedRevision >= state.revision {
					continue
				}
				distributor.mu.Lock()
				previous, sent := distributor.published[nodeID]
				distributor.mu.Unlock()
				if sent && previous.revision == state.revision && now.Before(previous.at.Add(distributor.config.RetryAfter)) {
					continue
				}
				revision = state.revision
			} else {
				revision = state.revision + 1
			}
		}
		if err := distributor.publish(ctx, nodeID, revision, digest[:], list, cut, now); err != nil {
			failure = errors.Join(failure, fmt.Errorf("publish security ban list to %s: %w", nodeID, err))
		} else if cut > 0 {
			AlertListTruncated(ctx, distributor.config.Pool, distributor.config.Alerts, TruncationAlert{Kind: ListKindSecurityBan,
				NodeID: nodeID, Total: total, Limit: contract.MaxEntries, Cut: cut, At: now})
		}
	}
	return failure
}

func (distributor *Distributor) publish(ctx context.Context, nodeID uuid.UUID, revision int64, contentDigest []byte,
	list contract.List, cut int, now time.Time) error {
	if entries := len(list.Bans) + len(list.Releases); entries > contract.MaxEntries {
		// Only releases are left and they alone exceed the limit (Truncate
		// never drops a release): nothing can be signed.
		return fmt.Errorf("node holds %d releases, more than %d entries", len(list.Releases), contract.MaxEntries)
	}
	warning := ""
	if cut > 0 {
		warning = WarningListTruncated
	}
	list.Schema, list.NodeID, list.Revision, list.IssuedAt = contract.Schema, nodeID.String(), uint64(revision), now.Unix()
	list.Algorithm, list.KeyID = contract.Algorithm, distributor.config.KeyID
	payload, err := contract.SigningPayload(list)
	if err != nil {
		return err
	}
	signature, err := distributor.config.Sign(ctx, payload)
	if err != nil {
		return fmt.Errorf("sign security ban list: %w", err)
	}
	encoded, err := contract.Seal(list, signature)
	if err != nil {
		return err
	}
	// Record first: a snapshot published without its state would be
	// published again under the same revision with other bytes.
	if _, err := distributor.config.Pool.Exec(ctx, `INSERT INTO security_ban_node_state(node_id,revision,content_sha256,
		list_sha256,published_at,warning_code,truncated_entries) VALUES($1,$2,$3,$4,$5,$6,$7)
		ON CONFLICT(node_id) DO UPDATE SET revision=EXCLUDED.revision,content_sha256=EXCLUDED.content_sha256,
			list_sha256=EXCLUDED.list_sha256,published_at=EXCLUDED.published_at,
			warning_code=EXCLUDED.warning_code,truncated_entries=EXCLUDED.truncated_entries
		WHERE security_ban_node_state.revision <= EXCLUDED.revision`,
		nodeID, revision, contentDigest, contract.Digest(encoded), now, warning, cut); err != nil {
		return fmt.Errorf("record security ban node state: %w", err)
	}
	if err := distributor.config.Transport.PublishList(ctx, nodeID.String(), uint64(revision), encoded); err != nil {
		return err
	}
	distributor.mu.Lock()
	distributor.published[nodeID] = published{revision: revision, at: now}
	distributor.mu.Unlock()
	distributor.config.Logger.Info("security ban list published", "node_id", nodeID, "revision", revision,
		"bans", len(list.Bans), "releases", len(list.Releases))
	return nil
}

// contents maps each active node serving a site with active bans or recent
// releases to its entries.
func (distributor *Distributor) contents(ctx context.Context, now time.Time) (map[uuid.UUID]*content, error) {
	type item struct {
		site     uuid.UUID
		client   netip.Prefix
		source   string
		until    time.Time
		released *time.Time
		created  time.Time
	}
	result := map[uuid.UUID]*content{}
	err := pgx.BeginTxFunc(ctx, distributor.config.Pool, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly}, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT entry.site_id,entry.client_ip,entry.source,entry.banned_until,entry.released_at,
			entry.banned_at FROM security_ban_entries entry JOIN sites site ON site.id=entry.site_id AND site.deleted_at IS NULL
			WHERE (entry.released_at IS NULL AND entry.banned_until > $1) OR entry.released_at > $2`,
			now, now.Add(-contract.ReleaseWindow))
		if err != nil {
			return err
		}
		items, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (item, error) {
			var value item
			return value, row.Scan(&value.site, &value.client, &value.source, &value.until, &value.released, &value.created)
		})
		if err != nil || len(items) == 0 {
			return err
		}
		sites := []uuid.UUID{}
		seen := map[uuid.UUID]bool{}
		for _, value := range items {
			if !seen[value.site] {
				seen[value.site] = true
				sites = append(sites, value.site)
			}
		}
		serving, err := servingNodes(ctx, tx, sites)
		if err != nil {
			return err
		}
		// One ban and one release per (site, client): the latest ends wins
		// for bans, the latest release for releases.
		bans := map[[2]string]contract.Ban{}
		releases := map[[2]string]contract.Release{}
		created := map[[2]string]time.Time{}
		for _, value := range items {
			key := [2]string{value.site.String(), clientText(value.client)}
			if value.released == nil && value.created.After(created[key]) {
				created[key] = value.created
			}
			if value.released != nil {
				if current, ok := releases[key]; !ok || value.released.Unix() > current.ReleasedAt {
					releases[key] = contract.Release{SiteID: key[0], Client: key[1], ReleasedAt: max(1, value.released.Unix())}
				}
				continue
			}
			if current, ok := bans[key]; !ok || value.until.Unix() > current.Until {
				bans[key] = contract.Ban{SiteID: key[0], Client: key[1], Until: value.until.Unix(), Source: value.source}
			}
		}
		capable, err := banCIDRNodes(ctx, tx, mapKeys(serving))
		if err != nil {
			return err
		}
		for nodeID, nodeSites := range serving {
			value := &content{Bans: []contract.Ban{}, Releases: []contract.Release{}, created: created}
			// fix-cidrban: a node without BAN_CIDR refuses a list with a
			// network, so it gets the addresses only.
			networks := capable[nodeID]
			for _, site := range nodeSites {
				for key, ban := range bans {
					if key[0] == site.String() && (networks || !contract.IsNetwork(key[1])) {
						value.Bans = append(value.Bans, ban)
					}
				}
				for key, release := range releases {
					if key[0] == site.String() && (networks || !contract.IsNetwork(key[1])) {
						value.Releases = append(value.Releases, release)
					}
				}
			}
			result[nodeID] = value
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("read security ban list: %w", err)
	}
	return result, nil
}

func mapKeys[V any](values map[uuid.UUID]V) []uuid.UUID {
	keys := make([]uuid.UUID, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	return keys
}

// banCIDRNodes: the nodes whose latest session declares BAN_CIDR v1
// (fix-cidrban).
func banCIDRNodes(ctx context.Context, tx pgx.Tx, nodeIDs []uuid.UUID) (map[uuid.UUID]bool, error) {
	rows, err := tx.Query(ctx, `SELECT node.id,(SELECT facts.capabilities_snapshot FROM node_session_capabilities facts
		WHERE facts.node_id=node.id ORDER BY facts.session_epoch DESC LIMIT 1) FROM unnest($1::uuid[]) AS node(id)`, nodeIDs)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := map[uuid.UUID]bool{}
	for rows.Next() {
		var nodeID uuid.UUID
		var snapshot []byte
		if err := rows.Scan(&nodeID, &snapshot); err != nil {
			return nil, err
		}
		result[nodeID] = declaresBanCIDR(snapshot)
	}
	return result, rows.Err()
}

func declaresBanCIDR(snapshot []byte) bool {
	var capabilities agentv1.AgentCapabilities
	if len(snapshot) == 0 || proto.Unmarshal(snapshot, &capabilities) != nil {
		return false
	}
	for _, capability := range capabilities.GetFeatures() {
		if capability.GetName() == agentv1.CapabilityName_CAPABILITY_NAME_BAN_CIDR &&
			capability.GetApiVersion() >= contract.CIDRAPIVersion {
			return true
		}
	}
	return false
}

// servingNodes: the active nodes of the current line groups each site uses
// (its own, its package's primary and backup), as site publication targets.
func servingNodes(ctx context.Context, tx pgx.Tx, sites []uuid.UUID) (map[uuid.UUID][]uuid.UUID, error) {
	rows, err := tx.Query(ctx, `SELECT DISTINCT endpoint.node_id, site.id FROM sites site
		LEFT JOIN package_subscriptions subscription ON subscription.tenant_scope_id=site.scope_id
		 AND subscription.id=site.package_subscription_id AND subscription.deleted_at IS NULL
		LEFT JOIN escalate_site_routes route ON route.tenant_scope_id=site.scope_id AND route.site_id=site.id
		JOIN node_line_groups line_group ON line_group.deleted_at IS NULL AND line_group.id IN (
		     site.node_group_id,
		     (subscription.product_snapshot->'spec'->>'node_group_id')::uuid,
		     (subscription.product_snapshot->'spec'->>'backup_node_group_id')::uuid,
		     route.line_group_id, route.next_group_id)
		JOIN node_line_endpoints endpoint ON endpoint.tenant_scope_id=line_group.tenant_scope_id
		 AND endpoint.line_group_id=line_group.id AND endpoint.config_revision=line_group.current_revision
		 AND endpoint.enabled AND endpoint.node_id IS NOT NULL
		JOIN nodes node ON node.id=endpoint.node_id AND node.admin_state='active'
		WHERE site.id=ANY($1) AND site.deleted_at IS NULL
		  AND line_group.tenant_scope_id IN (site.scope_id, node.scope_id)
		ORDER BY 1, 2`, sites)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := map[uuid.UUID][]uuid.UUID{}
	for rows.Next() {
		var nodeID, siteID uuid.UUID
		if err := rows.Scan(&nodeID, &siteID); err != nil {
			return nil, err
		}
		result[nodeID] = append(result[nodeID], siteID)
	}
	return result, rows.Err()
}

func (distributor *Distributor) states(ctx context.Context) (map[uuid.UUID]nodeState, error) {
	rows, err := distributor.config.Pool.Query(ctx, `SELECT node_id,revision,content_sha256,applied_revision FROM security_ban_node_state`)
	if err != nil {
		return nil, fmt.Errorf("read security ban node state: %w", err)
	}
	defer rows.Close()
	result := map[uuid.UUID]nodeState{}
	for rows.Next() {
		var nodeID uuid.UUID
		var state nodeState
		if err := rows.Scan(&nodeID, &state.revision, &state.content, &state.appliedRevision); err != nil {
			return nil, err
		}
		result[nodeID] = state
	}
	return result, rows.Err()
}

func (distributor *Distributor) consumeReceipts(ctx context.Context) {
	for ctx.Err() == nil {
		delivery, err := distributor.config.Transport.NextReceipt(ctx)
		if err != nil {
			if ctx.Err() == nil {
				distributor.config.Logger.Warn("security ban receipts unavailable", "error", err)
				select {
				case <-ctx.Done():
				case <-time.After(distributor.config.Interval):
				}
			}
			continue
		}
		if delivery != nil {
			distributor.HandleReceipt(ctx, delivery)
		}
	}
}

// HandleReceipt records a node's answer to the snapshot it answers (an
// answer to an older revision is dropped).
func (distributor *Distributor) HandleReceipt(ctx context.Context, delivery ReceiptDelivery) {
	report := delivery.Status()
	nodeID, err := uuid.Parse(report.GetNodeId())
	if err != nil || report.GetRevision() == 0 || len(report.GetListSha256()) != sha256.Size ||
		report.GetApplied() != (report.GetErrorCode() == "") || !validErrorCode(report.GetErrorCode()) {
		distributor.config.Logger.Warn("security ban receipt dropped", "node_id", report.GetNodeId())
		_ = delivery.Ack(ctx)
		return
	}
	applied := int64(0)
	if report.Applied {
		applied = int64(report.Revision)
	}
	command, err := distributor.config.Pool.Exec(ctx, `UPDATE security_ban_node_state SET
		applied_revision=greatest(applied_revision,$3),applied_sha256=CASE WHEN $4 THEN $5 ELSE applied_sha256 END,
		applied=$4,applied_bans=$6,applied_releases=$7,error_code=$8,reported_at=$9
		WHERE node_id=$1 AND revision=$2 AND list_sha256=$5`,
		nodeID, int64(report.Revision), applied, report.Applied, report.ListSha256, int64(report.Bans),
		int64(report.Releases), report.ErrorCode, distributor.config.Now().UTC())
	if err != nil {
		distributor.config.Logger.Warn("security ban receipt not recorded yet", "node_id", nodeID, "error", err)
		_ = delivery.Nak(ctx)
		return
	}
	level := slog.LevelInfo
	if !report.Applied {
		level = slog.LevelWarn
	}
	distributor.config.Logger.Log(ctx, level, "security ban receipt", "node_id", nodeID, "revision", report.Revision,
		"applied", report.Applied, "error_code", report.ErrorCode, "current", command.RowsAffected() == 1)
	_ = delivery.Ack(ctx)
}

func validErrorCode(code string) bool {
	if len(code) > 64 {
		return false
	}
	for index, char := range code {
		if !(char >= 'a' && char <= 'z' || index > 0 && (char >= '0' && char <= '9' || char == '_')) {
			return false
		}
	}
	return true
}

func (distributor *Distributor) report(err error) {
	message := ""
	if err != nil {
		message = err.Error()
	}
	if message != distributor.lastError {
		if err != nil {
			distributor.config.Logger.Warn("security ban publication pass failed", "error", err)
		} else if distributor.lastError != "" {
			distributor.config.Logger.Info("security ban publication recovered")
		}
		distributor.lastError = message
	}
}
