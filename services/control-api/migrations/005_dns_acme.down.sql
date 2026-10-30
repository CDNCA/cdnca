DROP TABLE IF EXISTS dns_acme_write_requests;
DROP TABLE IF EXISTS dns_acme_outbox;
DROP TABLE IF EXISTS certificate_orders;
DROP TABLE IF EXISTS dns_records;
DROP TABLE IF EXISTS dns_zones;
DROP TABLE IF EXISTS dns_providers;
DELETE FROM role_permissions WHERE permission_name IN (
    'dns.read', 'dns.manage', 'certificates.read', 'certificates.manage'
);
DELETE FROM permissions WHERE name IN (
    'dns.read', 'dns.manage', 'certificates.read', 'certificates.manage'
);
