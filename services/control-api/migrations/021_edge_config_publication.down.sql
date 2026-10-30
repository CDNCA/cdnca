DROP TRIGGER IF EXISTS edge_config_publications_append_only ON edge_config_publications;
DROP FUNCTION IF EXISTS prevent_edge_config_publication_mutation();
DROP TABLE IF EXISTS edge_config_publications;

DROP TRIGGER IF EXISTS l4_forwards_bump_edge_configuration_revision ON l4_forwards;
DROP TRIGGER IF EXISTS sites_bump_edge_configuration_revision ON sites;
DROP TRIGGER IF EXISTS site_origins_bump_edge_configuration_revision ON site_origins;
DROP TRIGGER IF EXISTS site_origin_pools_bump_edge_configuration_revision ON site_origin_pools;
DROP FUNCTION IF EXISTS bump_edge_configuration_revision_for_site_child();
DROP FUNCTION IF EXISTS bump_edge_configuration_scope_revision();
DROP FUNCTION IF EXISTS advance_edge_configuration_scope_revision(uuid);
DROP TABLE IF EXISTS edge_configuration_scopes;
