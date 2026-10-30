LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;

DO $migration_436_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 435 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 435 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=435 AND
        migration_id='435_admin_self_approval' AND
        checksum_sha256='be4c6888bfcf672c29a4a4a0b986d152285f6c946065bbfaf997737dbb11c0ac' AND
        down_checksum_sha256='d1a36297a2f979e16236409e532aa3e6544f6c83ec198211656734bf980b041b' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR to_regclass(current_schema() || '.control_installation_ban_state') IS NOT NULL OR
       to_regclass(current_schema() || '.installation_ban_node_state') IS NOT NULL THEN
        RAISE EXCEPTION 'migration 436 requires the exact verified 435 release head' USING ERRCODE='P4360';
    END IF;
END;
$migration_436_up$;

-- ADR 0014 LIC-BAN-04/05. control_installation_ban_state is the last
-- accepted installation state from the license service: the signed BanNotice
-- and ServiceTicket bytes exactly as received (control-api forwards them to
-- every node unchanged), with the fields the lock and the banner read. One
-- revision sequence per installation is shared by both documents; the Go
-- side refuses any lower revision (installationban.CheckRevision).
CREATE TABLE control_installation_ban_state (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    installation_id uuid NOT NULL,
    notice bytea CHECK (notice IS NULL OR octet_length(notice) BETWEEN 1 AND 16384),
    notice_revision bigint CHECK (notice_revision > 0),
    notice_sha256 bytea CHECK (notice_sha256 IS NULL OR octet_length(notice_sha256) = 32),
    notice_state text CHECK (notice_state IN ('banned', 'lifted')),
    ban_id uuid,
    reason_code text CHECK (reason_code ~ '^[a-z][a-z0-9_]{0,63}$'),
    reason_text text CHECK (char_length(reason_text) BETWEEN 1 AND 500),
    starts_at timestamptz,
    until timestamptz,
    ticket bytea CHECK (ticket IS NULL OR octet_length(ticket) BETWEEN 1 AND 16384),
    ticket_revision bigint CHECK (ticket_revision > 0),
    ticket_sha256 bytea CHECK (ticket_sha256 IS NULL OR octet_length(ticket_sha256) = 32),
    ticket_not_after timestamptz,
    received_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    CHECK ((notice IS NULL) = (notice_revision IS NULL) AND (notice IS NULL) = (notice_sha256 IS NULL) AND
           (notice IS NULL) = (notice_state IS NULL) AND (notice IS NULL) = (ban_id IS NULL) AND
           (notice IS NULL) = (reason_code IS NULL) AND (notice IS NULL) = (reason_text IS NULL) AND
           (notice IS NULL) = (starts_at IS NULL) AND (until IS NULL OR notice IS NOT NULL)),
    CHECK ((ticket IS NULL) = (ticket_revision IS NULL) AND (ticket IS NULL) = (ticket_sha256 IS NULL) AND
           (ticket IS NULL) = (ticket_not_after IS NULL))
);

-- installation_ban_node_state is each node's last InstallationBanReceipt:
-- the command revision it answered, what it enforces now and whether it
-- accepted the documents. The distributor republishes to a node until its
-- revision reaches the latest one.
CREATE TABLE installation_ban_node_state (
    node_id uuid PRIMARY KEY REFERENCES nodes(id) ON DELETE CASCADE,
    revision bigint NOT NULL CHECK (revision > 0),
    status text NOT NULL CHECK (status IN ('serving', 'banned', 'service_ticket_expired', 'no_ticket')),
    applied boolean NOT NULL,
    reason text NOT NULL DEFAULT '' CHECK (char_length(reason) <= 256),
    updated_at timestamptz NOT NULL
);
