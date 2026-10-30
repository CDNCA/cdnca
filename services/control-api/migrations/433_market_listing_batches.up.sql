LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;

DO $migration_433_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 432 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 432 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=432 AND
        migration_id='432_market_supply_slot_states' AND
        checksum_sha256='9fcb259e63ba9c0f92b06b73d85a371863f56baeef28e5b3a8fbb174d213ceab' AND
        down_checksum_sha256='7125b0a99e4567d5ef9ddd24e60410fa9a86cccd168b0c695d3e931276eb3ef0' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR to_regclass(current_schema() || '.market_listing_templates') IS NOT NULL
         OR to_regclass(current_schema() || '.market_listing_batch_items') IS NOT NULL THEN
        RAISE EXCEPTION 'migration 433 requires the exact verified 432 release head' USING ERRCODE='P4330';
    END IF;
END;
$migration_433_up$;

-- 433（r136 ML-11b，用户 10-21 22:50 批量上架；merge-batch8 由 429 占位改号，守卫指向 432）。
-- 1. market_listing_templates: the seller's saved listing templates (pricing,
--    limits, prepaid action, tags, plugins), local to this controller. body is
--    the console form, opaque to the database (an object of at most 32 KiB).
-- 2. market_listing_batch_items: one row per batch item (one offer), keyed by
--    the digest of its node set and final offer body, so submitting the same
--    nodes with the same template again returns the offer already made instead
--    of listing it twice. group_id is the hidden supply group (ML-09) made
--    for the item, offer_id the market offer; lease_until keeps a concurrent
--    submission of the same item from creating it a second time.
--    The group is created under a key derived from the node set, so a failed
--    item retried with another template reuses it.
CREATE TABLE market_listing_templates (
    id uuid PRIMARY KEY,
    platform_scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    name text NOT NULL CHECK (name = btrim(name) AND char_length(name) BETWEEN 1 AND 64 AND name !~ '[[:cntrl:]]'),
    body jsonb NOT NULL CHECK (jsonb_typeof(body) = 'object' AND octet_length(body::text) <= 32768),
    revision bigint NOT NULL CHECK (revision > 0),
    updated_by_user_id uuid NOT NULL,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL CHECK (updated_at >= created_at)
);
CREATE UNIQUE INDEX market_listing_templates_name_433_idx ON market_listing_templates (platform_scope_id, lower(name));

CREATE TABLE market_listing_batch_items (
    platform_scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    digest bytea NOT NULL CHECK (octet_length(digest) = 32),
    group_id uuid,
    offer_id uuid,
    lease_until timestamptz NOT NULL,
    created_by_user_id uuid NOT NULL,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL CHECK (updated_at >= created_at),
    PRIMARY KEY (platform_scope_id, digest),
    CHECK (offer_id IS NULL OR group_id IS NOT NULL)
);

CREATE FUNCTION assert_market_listing_platform_scope_433()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM access_scopes WHERE id=NEW.platform_scope_id AND kind='platform') THEN
        RAISE EXCEPTION 'market listings belong to the platform scope' USING ERRCODE='P4331';
    END IF;
    RETURN NEW;
END;
$$;
REVOKE ALL ON FUNCTION assert_market_listing_platform_scope_433() FROM PUBLIC;

CREATE TRIGGER market_listing_templates_scope_433
BEFORE INSERT OR UPDATE ON market_listing_templates
FOR EACH ROW EXECUTE FUNCTION assert_market_listing_platform_scope_433();
CREATE TRIGGER market_listing_batch_items_scope_433
BEFORE INSERT OR UPDATE ON market_listing_batch_items
FOR EACH ROW EXECUTE FUNCTION assert_market_listing_platform_scope_433();

GRANT SELECT, INSERT, UPDATE, DELETE ON market_listing_templates TO cdnca_control_app, cdnca_control_runtime;
GRANT SELECT, INSERT, UPDATE ON market_listing_batch_items TO cdnca_control_app, cdnca_control_runtime;
