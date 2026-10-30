-- CREATE TABLE migration_owner_line_fake (id text);
/*
CREATE TABLE migration_owner_block_fake (id text);
/* CREATE TABLE migration_owner_nested_fake (id text); */
*/
SELECT 'CREATE TABLE migration_owner_single_fake (id text)';
SELECT $$CREATE TABLE migration_owner_dollar_empty_fake (id text)$$;
SELECT $body$
CREATE TABLE migration_owner_dollar_fake (id text)
$body$;

CREATE TABLE lexical_real_records (id text PRIMARY KEY);
