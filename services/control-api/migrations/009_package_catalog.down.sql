DROP TABLE package_catalog_write_requests;
DROP TRIGGER package_product_versions_append_only ON package_product_versions;
DROP FUNCTION prevent_package_product_version_mutation();
DROP TABLE package_product_versions;
DROP TABLE package_products;
DROP TABLE package_groups;

DELETE FROM role_permissions WHERE permission_name = 'packages.manage';
DELETE FROM permissions WHERE name = 'packages.manage';
