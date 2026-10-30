LOCK TABLE schema_migrations, users IN ACCESS EXCLUSIVE MODE;

DO $migration_251$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 250 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 250 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version=250 AND migration_id='250_notification_policy_write_receipts'
          AND checksum_sha256='63e8869b5d4b5c4e0239168f99e401fd9b5e1a6ba79b295937058658bee95589'
          AND down_checksum_sha256='824ccab6944aa4cf28d01a42adef89b73a4135dac136d8ccb077bb7672df71c2'
          AND integrity_state='verified'
    ) OR EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema=current_schema() AND table_name='users' AND column_name IN ('remark','qq')
    ) THEN
        RAISE EXCEPTION 'migration 251 requires the exact verified 250 head and untouched user metadata columns'
            USING ERRCODE='P2510';
    END IF;
END;
$migration_251$;

ALTER TABLE users
    ADD COLUMN remark text,
    ADD COLUMN qq text,
    ADD CONSTRAINT users_remark_normalized_251 CHECK (remark IS NULL OR (
        char_length(remark) BETWEEN 1 AND 512 AND remark=btrim(remark, U&'\0009\000A\000B\000C\000D\0020\0085\00A0\1680\2000\2001\2002\2003\2004\2005\2006\2007\2008\2009\200A\2028\2029\202F\205F\3000') AND
        remark !~ U&'[\0001-\0008\000B\000C\000E-\001F\007F-\009F]'
    )),
    ADD CONSTRAINT users_qq_normalized_251 CHECK (qq IS NULL OR (
        char_length(qq) BETWEEN 1 AND 32 AND qq=btrim(qq, U&'\0009\000A\000B\000C\000D\0020\0085\00A0\1680\2000\2001\2002\2003\2004\2005\2006\2007\2008\2009\200A\2028\2029\202F\205F\3000') AND
        qq !~ U&'[\0001-\001F\007F-\009F]'
    ));
