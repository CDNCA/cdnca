LOCK TABLE schema_migrations, dns_providers IN ACCESS EXCLUSIVE MODE;

-- REQUIRED_MIGRATION_105_UP_SHA256=aef23962ee9538fbc4724684ec8fc87edc2a2af33f76aa8a76b6992769af0d7b
-- REQUIRED_MIGRATION_105_DOWN_SHA256=f570ec734387701cce422729750234f98365db2e64bf0110f5965076f89ada23
DO $$
DECLARE
    required_up constant text := 'aef23962ee9538fbc4724684ec8fc87edc2a2af33f76aa8a76b6992769af0d7b';
    required_down constant text := 'f570ec734387701cce422729750234f98365db2e64bf0110f5965076f89ada23';
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 105 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 105 OR EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE migration_id IS NULL OR checksum_sha256 IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$'
           OR down_checksum_sha256 IS NULL OR down_checksum_sha256 !~ '^[0-9a-f]{64}$'
           OR integrity_state IS DISTINCT FROM 'verified' OR metadata_recorded_at IS NULL OR applied_at IS NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version=105 AND migration_id='105_upgrade_canary_active_probe_lkg'
          AND checksum_sha256=required_up AND down_checksum_sha256=required_down
          AND integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
    ) THEN
        RAISE EXCEPTION 'migration 106 requires the exact verified 105 release head' USING ERRCODE='P1060';
    END IF;
END;
$$;

ALTER TABLE dns_providers
    ADD COLUMN credential_version bigint NOT NULL DEFAULT 1 CHECK (credential_version > 0),
    ADD COLUMN credential_revoked boolean NOT NULL DEFAULT false;

UPDATE dns_providers SET credential_revoked=(status='disabled');

CREATE TABLE dns_provider_credential_history (
    provider_id uuid NOT NULL REFERENCES dns_providers(id) ON DELETE CASCADE,
    credential_version bigint NOT NULL CHECK (credential_version > 0),
    credential_key_id text NOT NULL CHECK (credential_key_id <> ''),
    credential_ciphertext bytea NOT NULL CHECK (octet_length(credential_ciphertext) > 28),
    credential_revoked boolean NOT NULL,
    credential_event text NOT NULL CHECK (credential_event IN (
        'baseline', 'rotation', 'revocation', 'rotation_revocation', 'rollback'
    )),
    provider_status text NOT NULL CHECK (provider_status IN ('unverified','verified','disabled')),
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (provider_id, credential_version)
);

INSERT INTO dns_provider_credential_history (
    provider_id, credential_version, credential_key_id, credential_ciphertext,
    credential_revoked, credential_event, provider_status
)
SELECT id, credential_version, credential_key_id, credential_ciphertext,
       credential_revoked, 'baseline', status
FROM dns_providers;

CREATE FUNCTION dns_provider_credential_lifecycle_106()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    credential_changed boolean;
    revocation_started boolean;
BEGIN
    credential_changed := NEW.credential_key_id IS DISTINCT FROM OLD.credential_key_id OR
                          NEW.credential_ciphertext IS DISTINCT FROM OLD.credential_ciphertext;
    revocation_started := NEW.status='disabled' AND NOT OLD.credential_revoked;
    NEW.credential_version := OLD.credential_version;
    NEW.credential_revoked := OLD.credential_revoked;
    IF credential_changed THEN
        NEW.credential_version := OLD.credential_version + 1;
        NEW.credential_revoked := NEW.status='disabled';
    ELSIF revocation_started THEN
        NEW.credential_version := OLD.credential_version + 1;
        NEW.credential_revoked := true;
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION dns_provider_credential_history_106()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    event_name text;
BEGIN
    IF TG_OP='INSERT' THEN
        INSERT INTO dns_provider_credential_history (
            provider_id, credential_version, credential_key_id, credential_ciphertext,
            credential_revoked, credential_event, provider_status
        ) VALUES (
            NEW.id, NEW.credential_version, NEW.credential_key_id, NEW.credential_ciphertext,
            NEW.credential_revoked, 'baseline', NEW.status
        );
        RETURN NEW;
    END IF;
    IF NEW.credential_version IS NOT DISTINCT FROM OLD.credential_version THEN
		IF NEW.status IS DISTINCT FROM OLD.status THEN
			UPDATE dns_provider_credential_history SET provider_status=NEW.status
			WHERE provider_id=NEW.id AND credential_version=NEW.credential_version;
		END IF;
        RETURN NEW;
    END IF;
    IF NEW.credential_key_id IS DISTINCT FROM OLD.credential_key_id OR
       NEW.credential_ciphertext IS DISTINCT FROM OLD.credential_ciphertext THEN
		IF NEW.status='verified' AND EXISTS (
			SELECT 1 FROM dns_provider_credential_history AS prior
			WHERE prior.provider_id=NEW.id AND prior.credential_version<NEW.credential_version
			  AND prior.credential_key_id=NEW.credential_key_id
			  AND prior.credential_ciphertext=NEW.credential_ciphertext
			  AND prior.provider_status='verified' AND NOT prior.credential_revoked
		) THEN
			event_name := 'rollback';
		ELSIF NEW.credential_revoked THEN
            event_name := 'rotation_revocation';
        ELSE
            event_name := 'rotation';
        END IF;
    ELSE
        event_name := 'revocation';
    END IF;
    INSERT INTO dns_provider_credential_history (
        provider_id, credential_version, credential_key_id, credential_ciphertext,
        credential_revoked, credential_event, provider_status
    ) VALUES (
        NEW.id, NEW.credential_version, NEW.credential_key_id, NEW.credential_ciphertext,
        NEW.credential_revoked, event_name, NEW.status
    );
    RETURN NEW;
END;
$$;

CREATE TRIGGER dns_provider_credential_lifecycle_106
BEFORE UPDATE ON dns_providers
FOR EACH ROW EXECUTE FUNCTION dns_provider_credential_lifecycle_106();

CREATE TRIGGER dns_provider_credential_history_insert_106
AFTER INSERT ON dns_providers
FOR EACH ROW EXECUTE FUNCTION dns_provider_credential_history_106();

CREATE TRIGGER dns_provider_credential_history_update_106
AFTER UPDATE ON dns_providers
FOR EACH ROW EXECUTE FUNCTION dns_provider_credential_history_106();
