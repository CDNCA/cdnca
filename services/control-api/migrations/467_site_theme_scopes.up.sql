LOCK TABLE schema_migrations, theme_activations, site_theme_packages, site_theme_activations IN ACCESS EXCLUSIVE MODE;

DO $migration_467_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 466 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 466 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=466 AND
        migration_id='466_site_edge_options' AND
        checksum_sha256='44b2492ac321dc4b2108a10f456e4848fef06aafb7e8311657dcc56a192f043d' AND
        down_checksum_sha256='013db3a4cfcb4598f31251dc1e59fec54addb29e7800459ea1848ec932ec46fe' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR
       EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema=current_schema() AND table_name='theme_activations' AND column_name='slot') OR
       EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema=current_schema() AND table_name='site_theme_packages' AND column_name='schema') THEN
        RAISE EXCEPTION 'migration 467 requires the exact verified 466 release head' USING ERRCODE='P4670';
    END IF;
END;
$migration_467_up$;

-- 467 (site theme C: theme plugins with page bundles). Three activation
-- slots: admin (official themes only), user and site. user and site may
-- run different plugins; a user+site plugin may be active in one or both.
--
-- Console themes (theme_activations, migration 360) gain a slot. Every row
-- so far activated one theme for both consoles; it stays that: 'all'. A new
-- activation names admin, user or all, and the effective theme of a console
-- is the latest row of its slot or of 'all'. The admin slot (and 'all',
-- which includes admin) never takes a market theme: only official (built-in
-- or io.cdnca) themes may restyle the admin console; control-api enforces
-- the official publisher, the trigger refuses market themes as a backstop.
-- Existing rows are not rewritten (A4).
ALTER TABLE theme_activations ADD COLUMN slot text NOT NULL DEFAULT 'all'
    CHECK (slot IN ('all', 'admin', 'user'));
ALTER TABLE theme_activations ALTER COLUMN slot DROP DEFAULT;
CREATE INDEX theme_activations_slot_467 ON theme_activations(slot, revision DESC);

CREATE FUNCTION validate_theme_activation_slot_467()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.slot IN ('all', 'admin') AND EXISTS (
        SELECT 1 FROM theme_packages WHERE package_sha256 = NEW.package_sha256 AND source = 'market'
    ) AND NOT EXISTS (
        SELECT 1 FROM theme_packages WHERE package_sha256 = NEW.package_sha256 AND theme_id LIKE 'market.io.cdnca.%'
    ) THEN
        RAISE EXCEPTION 'only an official theme may be active on the admin console' USING ERRCODE = 'P4671';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER theme_activations_slot_467
BEFORE INSERT ON theme_activations
FOR EACH ROW EXECUTE FUNCTION validate_theme_activation_slot_467();

-- Website theme plugins of schema cdnca.site-theme/v2. A v1 plugin (the
-- built-in jidun/xmf, uploads, v1 market plugins) keeps its layout; a v2
-- plugin has no layout and brings a page bundle served by nginx from
-- ${DATA_DIR}/site-themes/<theme-id>/<version>/ (control-api writes it),
-- optionally a console theme registered as a user-slot console theme
-- (console_package_sha256), the sign-in page style and the content schema.
--   publisher        official (io.cdnca or built in) | third_party
--   applies_to       normalized admin,user,site subset the publisher may declare
--   bundle_sha256    digest of the bundle manifest control-api wrote to disk
-- publisher follows the id: built in, or a market plugin of the official
-- namespace io.cdnca (the market reserves it to the platform seller and the
-- license service verifies the publisher signature of every version).
ALTER TABLE site_theme_packages
    ADD COLUMN schema text NOT NULL DEFAULT 'cdnca.site-theme/v1'
        CHECK (schema IN ('cdnca.site-theme/v1', 'cdnca.site-theme/v2')),
    ADD COLUMN publisher text NOT NULL GENERATED ALWAYS AS (
        CASE WHEN source = 'builtin' OR theme_id LIKE 'market.io.cdnca.%' THEN 'official' ELSE 'third_party' END) STORED,
    ADD COLUMN applies_to text[] NOT NULL DEFAULT ARRAY['site']::text[],
    ADD COLUMN bundle_entry text CHECK (bundle_entry IS NULL OR bundle_entry ~ '^[A-Za-z0-9_-][A-Za-z0-9._/-]{0,255}\.html$'),
    ADD COLUMN bundle_sha256 bytea CHECK (bundle_sha256 IS NULL OR octet_length(bundle_sha256) = 32),
    ADD COLUMN console_package_sha256 bytea REFERENCES theme_packages(package_sha256) ON DELETE RESTRICT,
    ADD COLUMN auth_css text CHECK (auth_css IS NULL OR octet_length(auth_css) <= 262144),
    ADD COLUMN content_schema jsonb CHECK (content_schema IS NULL OR (jsonb_typeof(content_schema) = 'array' AND
        octet_length(content_schema::text) <= 262144));
-- Existing rows are v1 site themes and the column defaults describe them;
-- no row is rewritten (A4). New rows always name schema and applies_to.
ALTER TABLE site_theme_packages ALTER COLUMN schema DROP DEFAULT, ALTER COLUMN applies_to DROP DEFAULT;
ALTER TABLE site_theme_packages ALTER COLUMN layout DROP NOT NULL;
ALTER TABLE site_theme_packages ADD CONSTRAINT site_theme_packages_scopes_467 CHECK (
    applies_to IN (ARRAY['site'], ARRAY['user'], ARRAY['user','site'], ARRAY['admin'], ARRAY['admin','user'],
                   ARRAY['admin','user','site']) AND
    (publisher = 'official' OR NOT ('admin' = ANY(applies_to))));
ALTER TABLE site_theme_packages ADD CONSTRAINT site_theme_packages_shape_467 CHECK (
    (schema = 'cdnca.site-theme/v1' AND layout IS NOT NULL AND applies_to = ARRAY['site'] AND bundle_entry IS NULL AND
     bundle_sha256 IS NULL AND console_package_sha256 IS NULL AND auth_css IS NULL AND content_schema IS NULL) OR
    (schema = 'cdnca.site-theme/v2' AND layout IS NULL AND
     ('site' = ANY(applies_to)) = (bundle_entry IS NOT NULL) AND (bundle_entry IS NULL) = (bundle_sha256 IS NULL) AND
     (content_schema IS NULL OR 'site' = ANY(applies_to)) AND
     (('user' = ANY(applies_to) OR 'admin' = ANY(applies_to)) = (console_package_sha256 IS NOT NULL))));

-- The user and admin slots of a website theme plugin with a console theme
-- are console theme activations (theme_activations.slot) of its derived
-- package; the site slot is site_theme_activations (456). Only a plugin that
-- applies to the website (v1, or v2 with site) can take the site slot.
CREATE FUNCTION validate_site_theme_activation_467()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM site_theme_packages WHERE theme_id = NEW.theme_id AND 'site' = ANY(applies_to)) THEN
        RAISE EXCEPTION 'website theme plugin does not apply to the website' USING ERRCODE = 'P4672';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER site_theme_activations_scope_467
BEFORE INSERT OR UPDATE ON site_theme_activations
FOR EACH ROW EXECUTE FUNCTION validate_site_theme_activation_467();

REVOKE ALL ON FUNCTION validate_theme_activation_slot_467(), validate_site_theme_activation_467() FROM PUBLIC;
