package observabilitylog

import (
	"context"
	"fmt"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Store struct {
	pool    *pgxpool.Pool
	auditor *audit.Log
}

func NewStore(pool *pgxpool.Pool) (*Store, error) {
	if pool == nil {
		return nil, ErrInvalidConfig
	}
	return &Store{pool: pool, auditor: audit.New(pool)}, nil
}

func (store *Store) AuditHead(ctx context.Context, scopeID uuid.UUID) (int64, error) {
	var head int64
	if err := store.pool.QueryRow(ctx, `SELECT COALESCE(max(stream_position),0) FROM audit_events WHERE scope_id=$1`, scopeID).Scan(&head); err != nil {
		return 0, fmt.Errorf("query observability audit head: %w", err)
	}
	return head, nil
}

func (store *Store) ListFacts(ctx context.Context, query StoreQuery) ([]Fact, error) {
	kinds := make([]string, len(query.Kinds))
	for index, kind := range query.Kinds {
		kinds[index] = string(kind)
	}
	results := append([]string{}, query.ResultCodes...)
	var beforeTime any
	if !query.BeforeTime.IsZero() {
		beforeTime = query.BeforeTime
	}
	rows, err := store.pool.Query(ctx, `
		WITH facts AS (
			SELECT audit_event.id::text AS event_id,audit_event.scope_id,audit_event.stream_position AS audit_position,
				CASE WHEN audit_event.action='auth.login' THEN 'login' WHEN audit_event.action LIKE 'frontend.%' THEN 'frontend'
					ELSE 'operation' END AS kind,
				audit_event.actor_user_id,
				COALESCE(actor_user.display_id::text,'') AS actor_user_display_id,
				CASE WHEN audit_event.resource_type='user' THEN audit_event.resource_id ELSE '' END AS subject_user_id,
				audit_event.action,
				CASE WHEN audit_event.action='auth.login' THEN COALESCE(NULLIF(audit_event.payload->>'reason_code',''),'credentials_accepted')
					WHEN audit_event.action LIKE 'frontend.%' THEN COALESCE(NULLIF(audit_event.payload->>'reason_code',''),'unknown') ELSE audit_event.action END AS reason_code,
				audit_event.result AS result_code,audit_event.resource_type,audit_event.resource_id,
				-- tp-b6b：其余审计行取 490 正式列 user_agent（写入时已清洗截断）；之前的行为空串。
				CASE WHEN audit_event.action='auth.login' THEN COALESCE(
					NULLIF(left(regexp_replace(session.user_agent,'[[:cntrl:]]','','g'),512),''),
					NULLIF(left(regexp_replace(audit_event.payload->>'user_agent','[[:cntrl:]]','','g'),512),''),
					NULLIF(audit_event.user_agent,''),'unknown') ELSE audit_event.user_agent END AS user_agent,
				COALESCE(CASE WHEN audit_event.action<>'auth.login' AND audit_event.action NOT LIKE 'frontend.%' THEN
					NULLIF(jsonb_strip_nulls(jsonb_build_object(
						'revision',audit_event.payload->'revision','previous_revision',audit_event.payload->'previous_revision',
						'expected_revision',audit_event.payload->'expected_revision','source_revision',audit_event.payload->'source_revision',
						'target_revision',audit_event.payload->'target_revision','active_revision',audit_event.payload->'active_revision',
						'enabled',audit_event.payload->'enabled','status',audit_event.payload->'status',
						'previous_status',audit_event.payload->'previous_status','mode',audit_event.payload->'mode',
						'channel',audit_event.payload->'channel','version',audit_event.payload->'version',
						'count',audit_event.payload->'count','limit',audit_event.payload->'limit',
						'reason_code',audit_event.payload->'reason_code','failure_code',audit_event.payload->'failure_code'
					))::text,'{}') ELSE '' END,'') AS change_summary,
				audit_event.request_id,
				-- B6：操作审计的来源 IP 在 361 正式列 source_ip 里（payload 不带），登录仍优先会话地址。
				COALESCE(host(session.source_ip),NULLIF(audit_event.payload->>'source_ip',''),NULLIF(audit_event.source_ip,''),'unknown') AS source_ip,
				COALESCE(NULLIF(audit_event.payload->>'geo_code',''),'unknown') AS geo_code,
				COALESCE(NULLIF(audit_event.payload->>'geo_region',''),'') AS geo_region,
				COALESCE(NULLIF(audit_event.payload->>'geo_city',''),'') AS geo_city,
				COALESCE(NULLIF(audit_event.payload->>'geo_resolution',''),'') AS geo_resolution,
				audit_event.occurred_at,audit_event.category
			FROM audit_events audit_event
			LEFT JOIN users actor_user ON actor_user.id=audit_event.actor_user_id
			LEFT JOIN auth_sessions session ON audit_event.action='auth.login' AND session.id::text=audit_event.payload->>'session_id'
			UNION ALL
			SELECT fact.outbox_id::text||':'||fact.sequence::text,fact.scope_id,NULL::bigint,'notification',fact.actor_user_id,
				COALESCE(notification_actor.display_id::text,''),
				COALESCE(event.recipient_user_id::text,''),'notification.'||fact.fact_kind,
				COALESCE(fact.failure_code,fact.fact_kind),fact.result_state,'notification',fact.outbox_id::text,
				'','',COALESCE(fact.request_id,''),'unknown','unknown','','','',fact.observed_at,''
			FROM notification_delivery_facts_108 fact
			LEFT JOIN users notification_actor ON notification_actor.id=fact.actor_user_id
			JOIN notification_outbox outbox ON outbox.scope_id=fact.scope_id AND outbox.id=fact.outbox_id
			JOIN notification_events event ON event.scope_id=outbox.scope_id AND event.id=outbox.event_id
			), filtered AS (
				SELECT facts.*,count(*) OVER() AS total_count FROM facts
			WHERE scope_id=$1 AND occurred_at >= $2 AND occurred_at <= $3 AND occurred_at <= $4
			  AND (cardinality($5::text[])=0 OR kind=ANY($5::text[]))
			  AND (cardinality($6::text[])=0 OR result_code=ANY($6::text[]))
			  AND ($7='' OR action=$7) AND ($8='' OR source_ip=$8)
			  AND ($9='' OR right(action,length($9)+1)='.'||$9)
			  AND ($10='' OR resource_type=$10)
			  AND ($11='' OR position(lower($11) in lower(resource_id))>0)
			  AND ($12='' OR position(lower($12) in lower(change_summary))>0)
			  AND ($13::uuid IS NULL OR actor_user_id=$13 OR subject_user_id=$13::text)
			  AND (NOT $14::boolean OR (audit_position>$15 AND audit_position<=$16))
			  AND ($17::uuid IS NULL OR actor_user_id=$17)
			  AND ($18='' OR actor_user_display_id=$18)
			  AND ($22='' OR category=$22)
			)
			SELECT event_id,scope_id,kind,actor_user_id,actor_user_display_id,subject_user_id,action,reason_code,result_code,
				resource_type,resource_id,user_agent,change_summary,request_id,source_ip,geo_code,geo_region,geo_city,geo_resolution,occurred_at,category,total_count
			FROM filtered
			WHERE ($19::timestamptz IS NULL OR (occurred_at,event_id)<($19,$20))
			ORDER BY occurred_at DESC,event_id DESC LIMIT $21`, query.ScopeID, query.From, query.To, query.SnapshotAt,
		kinds, results, query.Action, query.SourceIP, query.ActionVerb, query.ResourceType, query.ResourceID,
		query.Change, query.ActorUserID, query.AuditBound, query.AuditAfterPosition, query.AuditThroughPosition,
		query.ExactActorUserID, query.ActorUserDisplayID, beforeTime, query.BeforeID, query.Limit, query.Category)
	if err != nil {
		return nil, fmt.Errorf("query observability facts: %w", err)
	}
	defer rows.Close()
	result := make([]Fact, 0, query.Limit)
	for rows.Next() {
		var fact Fact
		if err := rows.Scan(&fact.ID, &fact.ScopeID, &fact.Kind, &fact.ActorUserID, &fact.ActorUserDisplayID, &fact.SubjectUserID, &fact.Action,
			&fact.ReasonCode, &fact.ResultCode, &fact.ResourceType, &fact.ResourceID, &fact.UserAgent, &fact.ChangeSummary,
			&fact.RequestID, &fact.SourceIP, &fact.GeoCode, &fact.GeoRegion, &fact.GeoCity, &fact.GeoResolution,
			&fact.OccurredAt, &fact.Category, &fact.TotalCount); err != nil {
			return nil, fmt.Errorf("scan observability fact: %w", err)
		}
		result = append(result, fact)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read observability facts: %w", err)
	}
	return result, nil
}

// resourceNameSQL answers, in one round trip, the display name of each
// (resource_type, id) the page references, only inside scopeID: a resource of
// another scope (or a soft-deleted one) has no answer, so the page shows it
// as deleted and never leaks another tenant's name. Every branch is a primary
// key (or (scope, id)) lookup.
const resourceNameSQL = `
	SELECT ref.resource_type, ref.id::text, CASE ref.resource_type
		WHEN 'site' THEN (SELECT domain FROM sites WHERE id=ref.id AND scope_id=$1 AND deleted_at IS NULL)
		WHEN 'node' THEN (SELECT name FROM nodes WHERE id=ref.id AND scope_id=$1)
		WHEN 'stream' THEN (SELECT name FROM l4_forwards WHERE id=ref.id AND scope_id=$1 AND deleted_at IS NULL)
		WHEN 'certificate_asset' THEN (SELECT name FROM certificate_assets
			WHERE tenant_scope_id=$1 AND id=ref.id AND deleted_at IS NULL)
		WHEN 'certificate_order' THEN (SELECT array_to_string(domains, ',') FROM certificate_orders WHERE id=ref.id AND scope_id=$1)
		WHEN 'dns_provider' THEN (SELECT name FROM dns_providers WHERE id=ref.id AND scope_id=$1)
		WHEN 'ticket' THEN (SELECT subject FROM tickets WHERE id=ref.id AND tenant_scope_id=$1)
		WHEN 'user' THEN (SELECT member.username FROM users member
			JOIN memberships membership ON membership.user_id=member.id AND membership.scope_id=$1 WHERE member.id=ref.id)
		END
	FROM (SELECT DISTINCT * FROM unnest($2::text[], $3::uuid[]) AS ref(resource_type, id)) ref`

// ResourceNames implements ResourceNamer.
func (store *Store) ResourceNames(ctx context.Context, scopeID uuid.UUID, refs []ResourceRef) (map[ResourceRef]string, error) {
	names := map[ResourceRef]string{}
	if len(refs) == 0 {
		return names, nil
	}
	types, ids := make([]string, len(refs)), make([]uuid.UUID, len(refs))
	for index, ref := range refs {
		types[index], ids[index] = ref.Type, ref.ID
	}
	rows, err := store.pool.Query(ctx, resourceNameSQL, scopeID, types, ids)
	if err != nil {
		return nil, fmt.Errorf("query observability resource names: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var ref ResourceRef
		var id string
		var name *string
		if err := rows.Scan(&ref.Type, &id, &name); err != nil {
			return nil, fmt.Errorf("scan observability resource name: %w", err)
		}
		if ref.ID, err = uuid.Parse(id); err != nil {
			return nil, fmt.Errorf("scan observability resource name: %w", err)
		}
		if name != nil && *name != "" {
			names[ref] = *name
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read observability resource names: %w", err)
	}
	return names, nil
}

func (store *Store) AppendFrontend(ctx context.Context, fact FrontendFact) error {
	return pgx.BeginFunc(ctx, store.pool, func(tx pgx.Tx) error {
		return store.auditor.Append(ctx, tx, audit.Event{ScopeID: fact.ScopeID, ActorUserID: &fact.ActorID,
			Action: "frontend." + fact.EventCode, ResourceType: "frontend_route", ResourceID: fact.Route,
			RequestID: fact.RequestID, Result: fact.ResultCode, Payload: map[string]any{"reason_code": fact.ReasonCode,
				"source_ip": fact.SourceIP, "geo_code": "unknown", "release": fact.Release}})
	})
}

var _ Repository = (*Store)(nil)
var _ ResourceNamer = (*Store)(nil)
