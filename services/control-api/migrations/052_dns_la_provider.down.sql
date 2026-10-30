DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM dns_providers WHERE provider_type = 'dns_la') THEN
        RAISE EXCEPTION 'remove dns_la providers before rolling back migration 052'
            USING ERRCODE = '23514';
    END IF;
END;
$$;

DROP TRIGGER dns_providers_type_contract ON dns_providers;
DROP FUNCTION enforce_dns_provider_type_contract();

ALTER TABLE dns_providers
    DROP CONSTRAINT dns_providers_provider_type_check;

ALTER TABLE dns_providers
    ADD CONSTRAINT dns_providers_provider_type_check CHECK (
        provider_type IN ('aliyun', 'cloudflare', 'huawei', 'dnspod_cn', 'dns_com', 'dnsdun')
    );
