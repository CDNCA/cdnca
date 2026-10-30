DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM dns_providers
        WHERE provider_type = 'dnsdun' AND status <> 'disabled'
    ) THEN
        RAISE EXCEPTION 'disable or delete active legacy dnsdun providers before migration 052'
            USING ERRCODE = '23514';
    END IF;
END;
$$;

ALTER TABLE dns_providers
    DROP CONSTRAINT dns_providers_provider_type_check;

ALTER TABLE dns_providers
    ADD CONSTRAINT dns_providers_provider_type_check CHECK (
        provider_type IN ('aliyun', 'cloudflare', 'huawei', 'dnspod_cn', 'dns_com', 'dnsdun', 'dns_la')
    );

CREATE FUNCTION enforce_dns_provider_type_contract()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'INSERT' AND NEW.provider_type = 'dnsdun' THEN
        RAISE EXCEPTION 'new legacy dnsdun providers are disabled; create dns_la with newly entered credentials'
            USING ERRCODE = '23514';
    END IF;
    IF TG_OP = 'UPDATE' THEN
        IF OLD.provider_type = 'dnsdun' AND NEW.provider_type <> 'dnsdun' THEN
            RAISE EXCEPTION 'legacy dnsdun provider type cannot be rewritten'
                USING ERRCODE = '23514';
        END IF;
        IF OLD.provider_type <> 'dnsdun' AND NEW.provider_type = 'dnsdun' THEN
            RAISE EXCEPTION 'provider type cannot be changed to legacy dnsdun'
                USING ERRCODE = '23514';
        END IF;
        IF NEW.provider_type = 'dnsdun' AND NEW.status <> 'disabled' THEN
            RAISE EXCEPTION 'legacy dnsdun providers must remain disabled'
                USING ERRCODE = '23514';
        END IF;
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER dns_providers_type_contract
BEFORE INSERT OR UPDATE ON dns_providers
FOR EACH ROW EXECUTE FUNCTION enforce_dns_provider_type_contract();
