DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM dns_providers WHERE status = 'verified') THEN
        RAISE EXCEPTION 'cannot roll back DNS provider verification while verified providers exist'
            USING ERRCODE = 'check_violation';
    END IF;
END
$$;

ALTER TABLE dns_providers
    DROP CONSTRAINT dns_providers_status_check;

ALTER TABLE dns_providers
    ADD CONSTRAINT dns_providers_status_check
    CHECK (status IN ('unverified', 'disabled'));
