package l4lineswitch

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"reflect"
	"time"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/iamlock"
	"github.com/cdnca/cdnca/services/control-api/internal/l4drain"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const publishedConfigSnapshotSchema = "cdnca.edge.site-runtime/v2"

type PostgresDrainPlanSource struct {
	pool    *pgxpool.Pool
	iam     *iamlock.Authorizer
	auditor auditAppender
}

// publishedConfigSnapshot is the part of a published site runtime v2 document
// (edgepublish siteRuntimeV2Document) a drain plan reads: its identity and
// the scope's L4 streams.
type publishedConfigSnapshot struct {
	Schema               string                    `json:"schema"`
	ConfigurationScopeID string                    `json:"configuration_scope_id"`
	ConfigVersionID      string                    `json:"config_version_id"`
	SourceRevision       int64                     `json:"source_revision"`
	Streams              *edgeconfig.StreamRuntime `json:"streams,omitempty"`
}

// streams is the document's L4 v2 streams (nil without any).
func (snapshot publishedConfigSnapshot) streams() []edgeconfig.L4StreamRuntimeV2 {
	if snapshot.Streams == nil {
		return nil
	}
	return snapshot.Streams.StreamsV2
}

func NewPostgresDrainPlanSource(
	pool *pgxpool.Pool,
	iam *iamlock.Authorizer,
	auditor auditAppender,
) (*PostgresDrainPlanSource, error) {
	if pool == nil || iam == nil || !iam.Configured() {
		return nil, ErrInvalidInput
	}
	if auditor == nil {
		auditor = audit.New(pool)
	}
	return &PostgresDrainPlanSource{pool: pool, iam: iam, auditor: auditor}, nil
}

func (source *PostgresDrainPlanSource) Plans(
	ctx context.Context,
	actor Actor,
	value Switch,
) (map[uuid.UUID]l4drain.Plan, error) {
	if ctx == nil || source == nil || !validAuthority(actor) || value.ID == uuid.Nil ||
		value.ConfigurationScopeID == uuid.Nil || value.ExpectedSourceRevision < 1 {
		return nil, ErrInvalidInput
	}
	result := make(map[uuid.UUID]l4drain.Plan, len(value.RetiringNodes))
	err := pgx.BeginFunc(ctx, source.pool, func(tx pgx.Tx) error {
		if err := authorizeTx(ctx, tx, source.iam, actor, value.ConfigurationScopeID, value.ID, PermissionManage); err != nil {
			return err
		}
		var currentRevision int64
		if err := tx.QueryRow(ctx, `SELECT source_revision FROM edge_configuration_scopes
			WHERE scope_id=$1 FOR SHARE`, value.ConfigurationScopeID).Scan(&currentRevision); errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		} else if err != nil {
			return fmt.Errorf("%w: load configuration source revision", ErrPersistence)
		}
		if currentRevision != value.ExpectedSourceRevision {
			return ErrConflict
		}
		configVersionID, snapshot, err := loadPublishedConfigSnapshot(
			ctx, tx, value.ConfigurationScopeID, value.ExpectedSourceRevision,
		)
		if err != nil {
			return err
		}
		if len(snapshot.streams()) == 0 {
			return nil
		}
		if len(value.RetiringNodes) == 0 {
			return nil
		}
		var databaseNow time.Time
		if err := tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&databaseNow); err != nil {
			return fmt.Errorf("%w: read database clock", ErrPersistence)
		}
		for _, nodeID := range value.RetiringNodes {
			if nodeID == uuid.Nil {
				return ErrInvalidInput
			}
			plan, found, err := loadDrainPlan(
				ctx, tx, value.ConfigurationScopeID, value.ID, nodeID, value.ExpectedSourceRevision,
			)
			if err != nil {
				return err
			}
			if found {
				expected, expectedErr := planForNode(value, nodeID, configVersionID, snapshot, plan.Revision)
				if expectedErr != nil || !reflect.DeepEqual(plan, expected) {
					return ErrConflict
				}
				result[nodeID] = plan
				continue
			}
			var revision uint64
			if err := tx.QueryRow(ctx, `INSERT INTO l4_node_drain_counters(
				configuration_scope_id,node_id,revision,updated_at) VALUES($1,$2,1,$3)
				ON CONFLICT (configuration_scope_id,node_id) DO UPDATE SET
				revision=l4_node_drain_counters.revision+1,updated_at=EXCLUDED.updated_at
				RETURNING revision`, value.ConfigurationScopeID, nodeID, databaseNow).Scan(&revision); err != nil {
				return fmt.Errorf("%w: allocate drain plan revision", ErrPersistence)
			}
			plan, err = planForNode(value, nodeID, configVersionID, snapshot, revision)
			if err != nil {
				return err
			}
			encoded, err := json.Marshal(plan)
			if err != nil {
				return ErrInvalidInput
			}
			planID := uuid.MustParse(plan.PlanID)
			retiredVersionID := uuid.MustParse(plan.New.VersionID)
			if _, err := tx.Exec(ctx, `INSERT INTO l4_line_switch_drain_plans(
				configuration_scope_id,switch_id,node_id,plan_id,plan_revision,source_revision,
				config_version_id,retired_version_id,canonical_plan,plan_sha256,created_at)
				VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb,
				sha256(convert_to($9::jsonb::text,'UTF8')),$10)`,
				value.ConfigurationScopeID, value.ID, nodeID, planID, revision,
				value.ExpectedSourceRevision, configVersionID, retiredVersionID, encoded, databaseNow); err != nil {
				return fmt.Errorf("%w: persist drain plan", ErrPersistence)
			}
			if err := source.auditor.Append(ctx, tx, audit.Event{
				ScopeID: value.ConfigurationScopeID, ActorUserID: auditActorUserID(actor),
				Action: "l4_line_switch.drain_plan", ResourceType: "l4_line_switch",
				ResourceID: value.ID.String(), RequestID: value.RequestID.String(), Result: "success",
				Payload: map[string]any{
					"node_id": nodeID.String(), "plan_id": plan.PlanID,
					"plan_revision": revision, "source_revision": value.ExpectedSourceRevision,
				},
			}); err != nil {
				return fmt.Errorf("%w: append drain plan audit", ErrPersistence)
			}
			result[nodeID] = plan
		}
		return nil
	})
	return result, err
}

func loadPublishedConfigSnapshot(
	ctx context.Context,
	tx pgx.Tx,
	scopeID uuid.UUID,
	sourceRevision int64,
) (uuid.UUID, publishedConfigSnapshot, error) {
	var configVersionID uuid.UUID
	var encoded []byte
	err := tx.QueryRow(ctx, `SELECT config.id,config.canonical_snapshot
		FROM edge_config_publications publication
		JOIN config_versions config
		  ON config.configuration_scope_id=publication.configuration_scope_id
		 AND config.id=publication.config_version_id
		WHERE publication.configuration_scope_id=$1 AND publication.source_revision=$2
		  AND publication.contract_version=1 AND config.status IN ('releasable','superseded')
		  AND publication.canonical_snapshot_sha256=config.canonical_snapshot_sha256
		  AND config.canonical_snapshot_sha256=sha256(config.canonical_snapshot)
		FOR SHARE OF publication,config`, scopeID, sourceRevision).Scan(&configVersionID, &encoded)
	if errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, publishedConfigSnapshot{}, ErrNotFound
	}
	if err != nil {
		return uuid.Nil, publishedConfigSnapshot{}, fmt.Errorf("%w: load published configuration snapshot", ErrPersistence)
	}
	snapshot, err := decodePublishedConfigSnapshot(encoded)
	if err != nil || snapshot.Schema != publishedConfigSnapshotSchema ||
		snapshot.ConfigurationScopeID != scopeID.String() || snapshot.ConfigVersionID != configVersionID.String() ||
		snapshot.SourceRevision != sourceRevision {
		return uuid.Nil, publishedConfigSnapshot{}, ErrConflict
	}
	return configVersionID, snapshot, nil
}

// decodePublishedConfigSnapshot reads the drain-relevant part of a published
// document; the document itself was validated when it was published (and its
// digest is checked by the query), so other fields are not decoded here.
func decodePublishedConfigSnapshot(encoded []byte) (publishedConfigSnapshot, error) {
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	var snapshot publishedConfigSnapshot
	if err := decoder.Decode(&snapshot); err != nil {
		return publishedConfigSnapshot{}, ErrConflict
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return publishedConfigSnapshot{}, ErrConflict
	}
	return snapshot, nil
}

func loadDrainPlan(
	ctx context.Context,
	tx pgx.Tx,
	scopeID, switchID, nodeID uuid.UUID,
	expectedSourceRevision int64,
) (l4drain.Plan, bool, error) {
	var encoded []byte
	var sourceRevision int64
	err := tx.QueryRow(ctx, `SELECT canonical_plan::text,source_revision
		FROM l4_line_switch_drain_plans
		WHERE configuration_scope_id=$1 AND switch_id=$2 AND node_id=$3
		  AND plan_sha256=sha256(convert_to(canonical_plan::text,'UTF8'))
		FOR SHARE`, scopeID, switchID, nodeID).Scan(&encoded, &sourceRevision)
	if errors.Is(err, pgx.ErrNoRows) {
		return l4drain.Plan{}, false, nil
	}
	if err != nil {
		return l4drain.Plan{}, false, fmt.Errorf("%w: load drain plan", ErrPersistence)
	}
	if sourceRevision != expectedSourceRevision {
		return l4drain.Plan{}, false, ErrConflict
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var plan l4drain.Plan
	if err := decoder.Decode(&plan); err != nil {
		return l4drain.Plan{}, false, ErrConflict
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return l4drain.Plan{}, false, ErrConflict
	}
	return plan, true, nil
}

func planForNode(
	value Switch,
	nodeID, configVersionID uuid.UUID,
	snapshot publishedConfigSnapshot,
	revision uint64,
) (l4drain.Plan, error) {
	streams := snapshot.streams()
	if revision == 0 || configVersionID == uuid.Nil || nodeID == uuid.Nil ||
		len(streams) == 0 || len(streams) > 1000 {
		return l4drain.Plan{}, ErrConflict
	}
	listeners := make([]l4drain.Listener, 0, len(streams)*2)
	seen := make(map[string]struct{}, len(streams))
	for _, stream := range streams {
		// The drain runtime retires plain TCP sockets toward one literal
		// upstream: anything else (UDP, port ranges, extra listeners,
		// follow-port or DNS endpoints, SNI passthrough) fails closed.
		if stream.Listener.Protocol != "tcp" || stream.StreamID == "" || stream.Revision < 1 ||
			stream.Listener.Port < 1 || stream.Listener.Port > 65535 || stream.Listener.PortEnd != 0 ||
			len(stream.AdditionalListeners) != 0 || stream.Endpoint.FollowPort || stream.Endpoint.Host != "" ||
			stream.Endpoint.Port < 1 || stream.Endpoint.Port > 65535 || stream.TLSPassthrough {
			return l4drain.Plan{}, ErrConflict
		}
		if _, duplicate := seen[stream.StreamID]; duplicate {
			return l4drain.Plan{}, ErrConflict
		}
		seen[stream.StreamID] = struct{}{}
		upstream, err := netip.ParseAddr(stream.Endpoint.Address)
		if err != nil || upstream.Zone() != "" || upstream.Is4In6() || upstream.IsUnspecified() || upstream.IsMulticast() {
			return l4drain.Plan{}, ErrConflict
		}
		for _, binding := range []struct {
			suffix, address string
		}{{"v4", "0.0.0.0"}, {"v6", "::"}} {
			listeners = append(listeners, l4drain.Listener{
				ID: drainListenerID(stream.StreamID, binding.suffix), Protocol: "tcp", Address: binding.address,
				Port: stream.Listener.Port, UpstreamAddress: upstream.String(), UpstreamPort: stream.Endpoint.Port,
			})
		}
	}
	plan := l4drain.Plan{
		SchemaVersion: l4drain.SchemaVersionV1,
		PlanID:        uuid.NewSHA1(value.ID, []byte("drain:"+nodeID.String())).String(),
		Revision:      revision,
		Old:           l4drain.Version{VersionID: configVersionID.String(), Listeners: listeners},
		New: l4drain.Version{
			VersionID: uuid.NewSHA1(value.ID, []byte("retired:"+nodeID.String())).String(),
			Listeners: []l4drain.Listener{},
		},
		HealthTimeoutSeconds: durationSeconds(value.Drain.HealthTimeout),
		HealthChecks:         []l4drain.HealthCheck{},
		Drain: l4drain.DrainPolicy{
			MaxDrainSeconds: durationSeconds(value.Drain.MaxDrain), Force: "never",
		},
	}
	validationTime := time.Unix(1_700_000_000, 0).UTC()
	if _, err := l4drain.BuildCommand(l4drain.CommandInput{
		CommandID: uuid.NewSHA1(value.ID, []byte("validate-command:"+nodeID.String())).String(),
		NodeID:    nodeID.String(), RequestID: uuid.NewSHA1(value.ID, []byte("validate-request")).String(),
		OccurredAt: validationTime, Deadline: validationTime.Add(time.Hour), Plan: plan,
	}); err != nil {
		return l4drain.Plan{}, ErrConflict
	}
	return plan, nil
}

func durationSeconds(value time.Duration) int {
	return int((value + time.Second - 1) / time.Second)
}

// drainListenerID names one address family's socket of a stream in a plan.
func drainListenerID(streamID, family string) string { return streamID + "." + family }
