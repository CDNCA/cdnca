ALTER TABLE dns_providers
    DROP CONSTRAINT dns_providers_status_check;

ALTER TABLE dns_providers
    ADD CONSTRAINT dns_providers_status_check
    CHECK (status IN ('unverified', 'verified', 'disabled'));
