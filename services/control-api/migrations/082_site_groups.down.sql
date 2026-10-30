LOCK TABLE sites, site_groups, site_group_write_requests IN ACCESS EXCLUSIVE MODE;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM site_group_write_requests) THEN
        RAISE EXCEPTION 'migration 082 rollback cannot represent site group write receipts'
            USING ERRCODE = 'P8210';
    END IF;
    IF EXISTS (
        SELECT 1 FROM site_groups group_resource
        WHERE NOT EXISTS (
            SELECT 1 FROM sites site
            WHERE site.scope_id = group_resource.scope_id
              AND site.group_id = group_resource.id
              AND site.group_name = group_resource.name
        )
    ) THEN
        RAISE EXCEPTION 'migration 082 rollback cannot represent unreferenced site groups'
            USING ERRCODE = 'P8211';
    END IF;
END;
$$;

DROP TRIGGER site_group_write_requests_immutable_082 ON site_group_write_requests;
DROP TRIGGER site_group_write_requests_prevent_truncate_082 ON site_group_write_requests;
DROP FUNCTION prevent_site_group_write_request_mutation_082();
DROP TABLE site_group_write_requests;

DROP TRIGGER sites_validate_group_reference_082 ON sites;
DROP FUNCTION validate_site_group_reference_082();
DROP TRIGGER site_groups_prevent_truncate_082 ON site_groups;
DROP FUNCTION prevent_site_group_truncate_082();
DROP TRIGGER site_groups_guard_mutation_082 ON site_groups;
DROP FUNCTION guard_site_group_mutation_082();
DROP TRIGGER site_groups_validate_scope_082 ON site_groups;
DROP FUNCTION validate_site_group_scope_082();

ALTER TABLE sites
    DROP CONSTRAINT sites_group_reference_active_082,
    DROP CONSTRAINT sites_group_reference_exact_082,
    DROP CONSTRAINT sites_group_reference_pair_082,
    DROP COLUMN group_active;

DROP TABLE site_groups;
DROP FUNCTION site_group_name_is_valid_082(text);
DROP FUNCTION site_group_trim_name_082(text);
