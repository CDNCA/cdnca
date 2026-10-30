LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;

DO $migration_203$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 202 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 202 OR
       NOT EXISTS (SELECT 1 FROM schema_migrations WHERE version=202 AND migration_id='202_notification_delivery_policy_traffic_warning' AND integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL) THEN
        RAISE EXCEPTION 'migration 203 requires the verified 202 release head' USING ERRCODE='P2030';
    END IF;
END;
$migration_203$;

CREATE TABLE platform_brand_assets (
    platform_scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    slot text NOT NULL CHECK (slot IN ('favicon','logo','login_ad')),
    revision bigint NOT NULL CHECK (revision >= 0 AND revision < 9223372036854775807),
    reference text NOT NULL CHECK (reference ~ '^asset://brand/(favicon|logo|login_ad)/[0-9a-f]{64}$'),
    mime_type text NOT NULL CHECK (mime_type IN ('image/x-icon','image/vnd.microsoft.icon','image/png','image/jpeg')),
    size_bytes bigint NOT NULL CHECK (size_bytes > 0 AND size_bytes <= 2097152),
    sha256 bytea NOT NULL CHECK (octet_length(sha256)=32),
    object_key text NOT NULL CHECK (octet_length(object_key) BETWEEN 1 AND 512),
    immutable_token text NOT NULL CHECK (octet_length(immutable_token) BETWEEN 1 AND 512),
    updated_by_user_id uuid NOT NULL,
    updated_at timestamptz NOT NULL,
    PRIMARY KEY (platform_scope_id, slot),
    FOREIGN KEY (platform_scope_id, updated_by_user_id) REFERENCES memberships(scope_id,user_id) ON DELETE RESTRICT,
    CHECK ((slot='logo' AND mime_type='image/png') OR
           (slot='login_ad' AND mime_type='image/jpeg') OR
           (slot='favicon' AND mime_type IN ('image/x-icon','image/vnd.microsoft.icon','image/png')))
);

CREATE FUNCTION validate_platform_brand_assets_scope_203()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM access_scopes WHERE id=NEW.platform_scope_id AND kind='platform' AND tenant_id IS NULL) THEN
        RAISE EXCEPTION 'platform brand assets require a platform scope' USING ERRCODE='P2031';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER platform_brand_assets_scope_203
BEFORE INSERT OR UPDATE ON platform_brand_assets
FOR EACH ROW EXECUTE FUNCTION validate_platform_brand_assets_scope_203();

CREATE TABLE platform_brand_asset_write_requests (
    id uuid PRIMARY KEY,
    actor_user_id uuid NOT NULL,
    actor_scope_id uuid NOT NULL,
    target_scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    operation text NOT NULL CHECK (operation='platform_brand_asset.upload'),
    slot text NOT NULL CHECK (slot IN ('favicon','logo','login_ad')),
    idempotency_key text NOT NULL CHECK (octet_length(idempotency_key) BETWEEN 1 AND 128 AND idempotency_key ~ '^[A-Za-z0-9][A-Za-z0-9._:-]*$'),
    request_digest bytea NOT NULL CHECK (octet_length(request_digest)=32),
    response_body jsonb CHECK (response_body IS NULL OR jsonb_typeof(response_body)='object'),
    created_at timestamptz NOT NULL,
    completed_at timestamptz,
    UNIQUE(actor_user_id, operation, idempotency_key),
    FOREIGN KEY (actor_scope_id, actor_user_id) REFERENCES memberships(scope_id,user_id) ON DELETE RESTRICT,
    CHECK (actor_scope_id=target_scope_id),
    CHECK ((completed_at IS NULL AND response_body IS NULL) OR (completed_at IS NOT NULL AND response_body IS NOT NULL AND completed_at >= created_at))
);

CREATE INDEX platform_brand_asset_write_requests_scope_created_203
    ON platform_brand_asset_write_requests(target_scope_id, created_at DESC);

REVOKE ALL ON platform_brand_assets, platform_brand_asset_write_requests FROM PUBLIC;
REVOKE ALL ON FUNCTION validate_platform_brand_assets_scope_203() FROM PUBLIC;

