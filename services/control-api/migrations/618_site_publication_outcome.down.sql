-- 618 回退：site_sync_status_503 恢复 503 的定义（只看本站最新自动发布请求），删除 site_publication_outcome_618。
LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;

DO $migration_618_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 618 OR
       (SELECT max(version) FROM schema_migrations) <> 618 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=618 AND
        migration_id='618_site_publication_outcome' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 618 down requires the exact verified migration head' USING ERRCODE='P6181';
    END IF;
END;
$migration_618_down$;

CREATE OR REPLACE FUNCTION site_sync_status_503(scope_id uuid, site_id uuid) RETURNS text
LANGUAGE sql STABLE AS $$
    SELECT COALESCE((
        SELECT CASE state.state WHEN 'succeeded' THEN 'synced' WHEN 'failed' THEN 'failed' ELSE 'pending' END
        FROM edge_automatic_publication_requests request_row
        JOIN LATERAL (SELECT state FROM edge_automatic_publication_request_state_facts
            WHERE request_id=request_row.id ORDER BY sequence DESC LIMIT 1) state ON true
        WHERE request_row.target_scope_id=$1 AND request_row.source_kind='site' AND request_row.source_resource_id=$2
        ORDER BY request_row.created_at DESC, request_row.id DESC LIMIT 1
    ), 'synced')
$$;

DROP FUNCTION site_publication_outcome_618(uuid, uuid);
