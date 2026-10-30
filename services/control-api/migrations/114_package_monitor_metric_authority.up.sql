LOCK TABLE schema_migrations,
    sites,
    package_subscriptions,
    package_monitor_policy_versions,
    config_versions,
    node_certificates,
    analytics_ingest_watermarks_107
IN ACCESS EXCLUSIVE MODE;

DO $$
BEGIN
    -- REQUIRED_MIGRATION_113_INTEGRATION_SHA256=2d4243ed2fe303502f84f136e89cb7bdc7734c0dc3068a61f90664f8bee0ba3d
    IF (SELECT count(*) FROM schema_migrations) <> 113 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 113 OR EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE migration_id IS NULL OR checksum_sha256 IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$'
           OR down_checksum_sha256 IS NULL OR down_checksum_sha256 !~ '^[0-9a-f]{64}$'
           OR integrity_state IS DISTINCT FROM 'verified' OR metadata_recorded_at IS NULL OR applied_at IS NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version=113 AND migration_id='113_cname_authority'
          AND checksum_sha256='ac4716d79decdb1076dbc19a5bf9ac9400d997f198cd56a8639b3d1924c12ccb'
          AND down_checksum_sha256='0928a9f3a9d93df1917fe32b2a4c0b5c406cbb7fdb0f66fe84523404522fe5a5'
          AND integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
    ) THEN
        RAISE EXCEPTION 'migration 114 requires the exact verified 113 release head'
            USING ERRCODE='P1140';
    END IF;
END;
$$;

CREATE SEQUENCE package_monitor_metric_watermark_114_seq AS bigint MINVALUE 1 NO CYCLE;

ALTER TABLE package_monitor_policy_versions
    ADD CONSTRAINT package_monitor_policy_metric_identity_114_key
    UNIQUE (policy_id,revision,tenant_scope_id,subscription_id,metric);

CREATE FUNCTION package_monitor_site_binding_digest_114(
    p_tenant_scope_id uuid,
    p_site_id uuid,
    p_subscription_id uuid,
    p_config_version_id uuid,
    p_binding_revision bigint,
    p_valid_from timestamptz
) RETURNS bytea
LANGUAGE sql
IMMUTABLE
STRICT
AS $$
    SELECT sha256(convert_to(
        'package-monitor-site-binding-v1' || E'\n' ||
        p_tenant_scope_id::text || E'\n' || p_site_id::text || E'\n' ||
        p_subscription_id::text || E'\n' || p_config_version_id::text || E'\n' ||
        p_binding_revision::text || E'\n' || to_char(p_valid_from AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
        'UTF8'));
$$;

CREATE TABLE package_monitor_site_subscription_bindings_114 (
    tenant_scope_id uuid NOT NULL,
    site_id uuid NOT NULL,
    subscription_id uuid NOT NULL,
    config_version_id uuid NOT NULL,
    binding_revision bigint NOT NULL CHECK (binding_revision > 0),
    valid_from timestamptz NOT NULL CHECK (isfinite(valid_from)),
    valid_to timestamptz CHECK (valid_to IS NULL OR (isfinite(valid_to) AND valid_to > valid_from)),
    binding_digest bytea NOT NULL CHECK (octet_length(binding_digest)=32),
    created_at timestamptz NOT NULL CHECK (isfinite(created_at)),
    PRIMARY KEY (config_version_id,site_id),
    UNIQUE (tenant_scope_id,site_id,binding_revision),
    UNIQUE (tenant_scope_id,subscription_id,config_version_id,site_id),
    FOREIGN KEY (tenant_scope_id,site_id) REFERENCES sites(scope_id,id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_scope_id,subscription_id) REFERENCES package_subscriptions(tenant_scope_id,id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_scope_id,config_version_id) REFERENCES config_versions(configuration_scope_id,id) ON DELETE RESTRICT,
    CHECK (binding_digest=package_monitor_site_binding_digest_114(
        tenant_scope_id,site_id,subscription_id,config_version_id,binding_revision,valid_from))
);

CREATE INDEX package_monitor_site_subscription_period_114_idx
    ON package_monitor_site_subscription_bindings_114
       (tenant_scope_id,subscription_id,valid_from,valid_to,config_version_id);

CREATE TABLE package_monitor_config_installations_114 (
    tenant_scope_id uuid NOT NULL,
    config_version_id uuid NOT NULL,
    node_id uuid NOT NULL,
    installation_id text NOT NULL CHECK (
        installation_id=btrim(installation_id) AND octet_length(installation_id) BETWEEN 1 AND 128
        AND installation_id !~ '[[:cntrl:]]'
    ),
    valid_from timestamptz NOT NULL CHECK (isfinite(valid_from)),
    valid_to timestamptz CHECK (valid_to IS NULL OR (isfinite(valid_to) AND valid_to > valid_from)),
    PRIMARY KEY (config_version_id,node_id),
    FOREIGN KEY (tenant_scope_id,config_version_id) REFERENCES config_versions(configuration_scope_id,id) ON DELETE RESTRICT,
    FOREIGN KEY (node_id) REFERENCES nodes(id) ON DELETE RESTRICT,
    FOREIGN KEY (installation_id) REFERENCES control_installation_entitlement(installation_id) ON DELETE RESTRICT
);

CREATE INDEX package_monitor_config_installations_period_114_idx
    ON package_monitor_config_installations_114
       (tenant_scope_id,valid_from,valid_to,installation_id,config_version_id);

CREATE FUNCTION package_monitor_resolve_period_114(
    p_starts_at timestamptz,
    p_ends_at timestamptz,
    p_timezone text,
    p_cycle_kind text,
    p_custom_cycle_days integer,
    p_due_at timestamptz
) RETURNS TABLE(period_key text,period_start timestamptz,period_end timestamptz)
LANGUAGE plpgsql
STABLE
STRICT
AS $$
DECLARE
    local_due timestamp;
    local_start timestamp;
    candidate_start timestamptz;
    candidate_end timestamptz;
    cycle_seconds numeric;
    cycle_index bigint;
BEGIN
    IF NOT isfinite(p_starts_at) OR NOT isfinite(p_ends_at) OR NOT isfinite(p_due_at) OR
       p_ends_at<=p_starts_at OR p_due_at<=p_starts_at OR p_due_at>p_ends_at OR
       p_cycle_kind NOT IN ('daily','monthly','custom_days') OR
       (p_cycle_kind='custom_days' AND p_custom_cycle_days NOT BETWEEN 1 AND 366) THEN
        RAISE EXCEPTION 'invalid package monitor period authority' USING ERRCODE='P1141';
    END IF;
    local_due:=p_due_at AT TIME ZONE p_timezone;
    IF p_cycle_kind='daily' THEN
        local_start:=date_trunc('day',local_due-interval '1 microsecond');
        candidate_start:=local_start AT TIME ZONE p_timezone;
        candidate_end:=(local_start+interval '1 day') AT TIME ZONE p_timezone;
    ELSIF p_cycle_kind='monthly' THEN
        local_start:=date_trunc('month',local_due-interval '1 microsecond');
        candidate_start:=local_start AT TIME ZONE p_timezone;
        candidate_end:=(local_start+interval '1 month') AT TIME ZONE p_timezone;
    ELSE
        cycle_seconds:=p_custom_cycle_days::numeric*86400;
        cycle_index:=floor(extract(epoch FROM (p_due_at-p_starts_at)-interval '1 microsecond')/cycle_seconds);
        candidate_start:=p_starts_at+(cycle_index*p_custom_cycle_days)*interval '1 day';
        candidate_end:=candidate_start+p_custom_cycle_days*interval '1 day';
    END IF;
    candidate_start:=GREATEST(candidate_start,p_starts_at);
    candidate_end:=LEAST(candidate_end,p_ends_at);
    period_start:=candidate_start;
    period_end:=p_due_at;
    IF period_start>=period_end OR period_end>candidate_end THEN
        RAISE EXCEPTION 'package monitor job is outside its authoritative billing period' USING ERRCODE='P1141';
    END IF;
    period_key:=to_char(candidate_start AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') || '/' ||
                to_char(candidate_end AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"');
    RETURN NEXT;
END;
$$;

CREATE TABLE package_monitor_metric_observations_114 (
    tenant_scope_id uuid NOT NULL,
    subscription_id uuid NOT NULL,
    policy_id uuid NOT NULL,
    policy_revision bigint NOT NULL CHECK (policy_revision > 0),
    metric text NOT NULL CHECK (metric IN ('traffic_bytes','bandwidth_bps','connections','expiration')),
    period_key text NOT NULL CHECK (
        octet_length(period_key) BETWEEN 1 AND 256 AND period_key=btrim(period_key) AND period_key !~ '[[:cntrl:]]'
    ),
    observed_value numeric(20,0) NOT NULL CHECK (observed_value BETWEEN 0 AND 18446744073709551615),
    observed_at timestamptz NOT NULL CHECK (isfinite(observed_at)),
    finalized_through timestamptz NOT NULL CHECK (isfinite(finalized_through) AND finalized_through>=observed_at),
    source_watermark numeric(20,0) NOT NULL CHECK (source_watermark BETWEEN 1 AND 18446744073709551615),
    source_evidence_digest bytea NOT NULL CHECK (octet_length(source_evidence_digest)=32),
    deadline_revision bigint NOT NULL CHECK (
        (metric='expiration' AND deadline_revision>0) OR (metric<>'expiration' AND deadline_revision=0)
    ),
    committed_at timestamptz NOT NULL CHECK (isfinite(committed_at)),
    PRIMARY KEY (policy_id,policy_revision,period_key,source_evidence_digest),
    UNIQUE (source_watermark),
    FOREIGN KEY (policy_id,policy_revision,tenant_scope_id,subscription_id,metric)
        REFERENCES package_monitor_policy_versions(policy_id,revision,tenant_scope_id,subscription_id,metric)
        ON DELETE RESTRICT
);

CREATE FUNCTION package_monitor_commit_metric_observation_114(
    p_tenant_scope_id uuid,
    p_subscription_id uuid,
    p_policy_id uuid,
    p_policy_revision bigint,
    p_metric text,
    p_period_key text,
    p_observed_value numeric,
    p_observed_at timestamptz,
    p_finalized_through timestamptz,
    p_source_evidence_digest bytea,
    p_deadline_revision bigint,
    p_committed_at timestamptz
) RETURNS TABLE(source_watermark numeric)
LANGUAGE plpgsql
VOLATILE
STRICT
AS $$
DECLARE
    existing package_monitor_metric_observations_114%ROWTYPE;
    next_watermark bigint;
BEGIN
    IF p_tenant_scope_id IS NULL OR p_subscription_id IS NULL OR p_policy_id IS NULL OR
       p_policy_revision<=0 OR p_metric NOT IN ('traffic_bytes','bandwidth_bps','connections','expiration') OR
       octet_length(p_period_key) NOT BETWEEN 1 AND 256 OR p_period_key<>btrim(p_period_key) OR
       octet_length(p_source_evidence_digest)<>32 OR NOT isfinite(p_observed_at) OR
       NOT isfinite(p_finalized_through) OR p_finalized_through<p_observed_at OR
       NOT isfinite(p_committed_at) OR p_committed_at<p_finalized_through OR
       (p_metric='expiration')<>(p_deadline_revision>0) THEN
        RAISE EXCEPTION 'invalid package monitor metric observation' USING ERRCODE='P1142';
    END IF;
    PERFORM 1 FROM package_monitor_policy_versions
    WHERE policy_id=p_policy_id AND revision=p_policy_revision AND tenant_scope_id=p_tenant_scope_id
      AND subscription_id=p_subscription_id AND metric=p_metric AND enabled
    FOR KEY SHARE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'package monitor metric policy authority unavailable' USING ERRCODE='P1143';
    END IF;
    SELECT * INTO existing FROM package_monitor_metric_observations_114
    WHERE policy_id=p_policy_id AND policy_revision=p_policy_revision AND period_key=p_period_key
      AND source_evidence_digest=p_source_evidence_digest;
    IF FOUND THEN
        IF existing.tenant_scope_id<>p_tenant_scope_id OR existing.subscription_id<>p_subscription_id OR
           existing.metric<>p_metric OR existing.observed_value<>p_observed_value OR
           existing.observed_at<>p_observed_at OR existing.finalized_through<>p_finalized_through OR
           existing.deadline_revision<>p_deadline_revision THEN
            RAISE EXCEPTION 'package monitor metric evidence conflicts with durable observation'
                USING ERRCODE='P1144';
        END IF;
        source_watermark:=existing.source_watermark;
        RETURN NEXT;
        RETURN;
    END IF;
    next_watermark:=nextval('package_monitor_metric_watermark_114_seq');
    INSERT INTO package_monitor_metric_observations_114(
        tenant_scope_id,subscription_id,policy_id,policy_revision,metric,period_key,
        observed_value,observed_at,finalized_through,source_watermark,source_evidence_digest,
        deadline_revision,committed_at
    ) VALUES (
        p_tenant_scope_id,p_subscription_id,p_policy_id,p_policy_revision,p_metric,p_period_key,
        p_observed_value,p_observed_at,p_finalized_through,next_watermark,p_source_evidence_digest,
        p_deadline_revision,p_committed_at
    );
    source_watermark:=next_watermark;
    RETURN NEXT;
END;
$$;

CREATE FUNCTION guard_package_monitor_metric_authority_114()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP='TRUNCATE' THEN
        RAISE EXCEPTION 'package monitor metric authority cannot be truncated';
    END IF;
    IF TG_OP='DELETE' OR TG_OP='UPDATE' THEN
        IF TG_TABLE_NAME='package_monitor_site_subscription_bindings_114' AND TG_OP='UPDATE' AND
           OLD.valid_to IS NULL AND NEW.valid_to IS NOT NULL AND
           ROW(NEW.tenant_scope_id,NEW.site_id,NEW.subscription_id,NEW.config_version_id,
               NEW.binding_revision,NEW.valid_from,NEW.binding_digest,NEW.created_at)
           IS NOT DISTINCT FROM
           ROW(OLD.tenant_scope_id,OLD.site_id,OLD.subscription_id,OLD.config_version_id,
               OLD.binding_revision,OLD.valid_from,OLD.binding_digest,OLD.created_at) THEN
            RETURN NEW;
        END IF;
        IF TG_TABLE_NAME='package_monitor_config_installations_114' AND TG_OP='UPDATE' AND
           OLD.valid_to IS NULL AND NEW.valid_to IS NOT NULL AND
           ROW(NEW.tenant_scope_id,NEW.config_version_id,NEW.node_id,NEW.installation_id,NEW.valid_from)
           IS NOT DISTINCT FROM
           ROW(OLD.tenant_scope_id,OLD.config_version_id,OLD.node_id,OLD.installation_id,OLD.valid_from) THEN
            RETURN NEW;
        END IF;
        RAISE EXCEPTION 'package monitor metric authority facts are immutable';
    END IF;
    RETURN OLD;
END;
$$;

CREATE TRIGGER package_monitor_site_bindings_immutable_114
BEFORE UPDATE OR DELETE ON package_monitor_site_subscription_bindings_114
FOR EACH ROW EXECUTE FUNCTION guard_package_monitor_metric_authority_114();
CREATE TRIGGER package_monitor_site_bindings_no_truncate_114
BEFORE TRUNCATE ON package_monitor_site_subscription_bindings_114
FOR EACH STATEMENT EXECUTE FUNCTION guard_package_monitor_metric_authority_114();
CREATE TRIGGER package_monitor_config_installations_immutable_114
BEFORE UPDATE OR DELETE ON package_monitor_config_installations_114
FOR EACH ROW EXECUTE FUNCTION guard_package_monitor_metric_authority_114();
CREATE TRIGGER package_monitor_config_installations_no_truncate_114
BEFORE TRUNCATE ON package_monitor_config_installations_114
FOR EACH STATEMENT EXECUTE FUNCTION guard_package_monitor_metric_authority_114();
CREATE TRIGGER package_monitor_metric_observations_immutable_114
BEFORE UPDATE OR DELETE ON package_monitor_metric_observations_114
FOR EACH ROW EXECUTE FUNCTION guard_package_monitor_metric_authority_114();
CREATE TRIGGER prevent_package_monitor_metric_truncate_114
BEFORE TRUNCATE ON package_monitor_metric_observations_114
FOR EACH STATEMENT EXECUTE FUNCTION guard_package_monitor_metric_authority_114();

REVOKE ALL ON package_monitor_site_subscription_bindings_114,
    package_monitor_config_installations_114,
    package_monitor_metric_observations_114 FROM PUBLIC;
REVOKE ALL ON SEQUENCE package_monitor_metric_watermark_114_seq FROM PUBLIC;
REVOKE ALL ON FUNCTION package_monitor_site_binding_digest_114(uuid,uuid,uuid,uuid,bigint,timestamptz) FROM PUBLIC;
REVOKE ALL ON FUNCTION package_monitor_resolve_period_114(timestamptz,timestamptz,text,text,integer,timestamptz) FROM PUBLIC;
REVOKE ALL ON FUNCTION package_monitor_commit_metric_observation_114(uuid,uuid,uuid,bigint,text,text,numeric,timestamptz,timestamptz,bytea,bigint,timestamptz) FROM PUBLIC;
REVOKE ALL ON FUNCTION guard_package_monitor_metric_authority_114() FROM PUBLIC;
