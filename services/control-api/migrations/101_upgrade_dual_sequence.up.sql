LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;

DO $$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 100 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 100 OR EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE migration_id IS NULL
           OR checksum_sha256 IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$'
           OR down_checksum_sha256 IS NULL OR down_checksum_sha256 !~ '^[0-9a-f]{64}$'
           OR integrity_state IS DISTINCT FROM 'verified'
           OR metadata_recorded_at IS NULL OR applied_at IS NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version=100 AND migration_id='100_billing_adjustment_approval_authority'
          AND checksum_sha256='1ee7685a1adeebc2d4aefea26e8f33b41e10409594b97550d508060a44cd05ad'
          AND down_checksum_sha256='d0c12c91465398aed7d9f79f5c610abe205937c2f8a0fb16c3a9459423892265'
          AND integrity_state='verified' AND metadata_recorded_at IS NOT NULL
          AND applied_at IS NOT NULL
    ) OR to_regclass(format('%I.%I',current_schema(),'control_upgrade_node_commands')) IS NULL OR EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema=current_schema() AND table_name='control_upgrade_node_commands'
          AND column_name IN ('command_schema','execution_sequence','release_sequence','component')
    ) THEN
        RAISE EXCEPTION 'migration 101 requires the exact verified 100 release head'
            USING ERRCODE='P1010';
    END IF;
END;
$$;

LOCK TABLE control_upgrade_node_commands IN ACCESS EXCLUSIVE MODE;

DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM control_upgrade_node_commands
        WHERE convert_from(command_grant_bytes,'UTF8')::jsonb#>>'{grant,schema}'=
                  'cdnca.upgrade.command-grant/v3'
           OR convert_from(signed_execution_bytes,'UTF8')::jsonb#>>'{execution,schema}'=
                  'cdnca.upgrade.execution/v3'
    ) THEN
        RAISE EXCEPTION 'migration 101 cannot guess preexisting upgrade command v3 facts'
            USING ERRCODE='P1011';
    END IF;
END;
$$;

-- legacy rows remain nullable and are never guessed
ALTER TABLE control_upgrade_node_commands
    ADD COLUMN command_schema text,
    ADD COLUMN execution_sequence bigint,
    ADD COLUMN release_sequence bigint,
    ADD COLUMN component text,
    ADD CONSTRAINT control_upgrade_node_commands_v3_shape_101 CHECK (
        (command_schema IS NULL AND execution_sequence IS NULL AND
         release_sequence IS NULL AND component IS NULL) OR
        (command_schema='cdnca.upgrade.command-grant/v3' AND
         execution_sequence IS NOT NULL AND execution_sequence>0 AND
         release_sequence IS NOT NULL AND release_sequence>0 AND
         component IS NOT NULL AND component ~ '^[a-z][a-z0-9._-]{0,95}$')
    ),
    ADD CONSTRAINT control_upgrade_node_commands_execution_101_uk
        UNIQUE (installation_id, node_id, component, execution_sequence);

CREATE FUNCTION validate_control_upgrade_dual_sequence_101()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    grant_document jsonb;
    execution_document jsonb;
    grant_schema text;
    execution_schema text;
BEGIN
    IF TG_OP='UPDATE' AND ROW(
        NEW.command_schema,NEW.execution_sequence,NEW.release_sequence,NEW.component
    ) IS DISTINCT FROM ROW(
        OLD.command_schema,OLD.execution_sequence,OLD.release_sequence,OLD.component
    ) THEN
        RAISE EXCEPTION 'control upgrade dual-sequence facts are immutable'
            USING ERRCODE='P1012';
    END IF;

    BEGIN
        grant_document := convert_from(NEW.command_grant_bytes,'UTF8')::jsonb;
        execution_document := convert_from(NEW.signed_execution_bytes,'UTF8')::jsonb;
    EXCEPTION WHEN OTHERS THEN
        RAISE EXCEPTION 'control upgrade dual-sequence documents are invalid'
            USING ERRCODE='P1012';
    END;
    grant_schema := grant_document#>>'{grant,schema}';
    execution_schema := execution_document#>>'{execution,schema}';

    IF grant_schema='cdnca.upgrade.command-grant/v3' OR
       execution_schema='cdnca.upgrade.execution/v3' THEN
        IF grant_schema IS DISTINCT FROM 'cdnca.upgrade.command-grant/v3' OR
           execution_schema IS DISTINCT FROM 'cdnca.upgrade.execution/v3' OR
           NEW.command_schema IS DISTINCT FROM grant_schema OR
           grant_document#>>'{grant,execution_sequence}' IS DISTINCT FROM NEW.execution_sequence::text OR
           execution_document#>>'{execution,execution_sequence}' IS DISTINCT FROM NEW.execution_sequence::text OR
           grant_document#>>'{grant,release_sequence}' IS DISTINCT FROM NEW.release_sequence::text OR
           execution_document#>>'{execution,release_sequence}' IS DISTINCT FROM NEW.release_sequence::text OR
           grant_document#>>'{grant,component}' IS DISTINCT FROM NEW.component OR
           execution_document#>>'{execution,component}' IS DISTINCT FROM NEW.component THEN
            RAISE EXCEPTION 'control upgrade v3 dual-sequence facts do not match signed documents'
                USING ERRCODE='P1012';
        END IF;
    ELSIF NEW.command_schema IS NOT NULL OR NEW.execution_sequence IS NOT NULL OR
          NEW.release_sequence IS NOT NULL OR NEW.component IS NOT NULL THEN
        RAISE EXCEPTION 'legacy control upgrade commands cannot carry guessed dual-sequence facts'
            USING ERRCODE='P1012';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER control_upgrade_dual_sequence_validate_101
BEFORE INSERT OR UPDATE ON control_upgrade_node_commands
FOR EACH ROW EXECUTE FUNCTION validate_control_upgrade_dual_sequence_101();

REVOKE ALL ON FUNCTION validate_control_upgrade_dual_sequence_101() FROM PUBLIC;
