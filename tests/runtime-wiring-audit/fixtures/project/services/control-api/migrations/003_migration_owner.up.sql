CREATE TABLE migration_owner_records (
    id text PRIMARY KEY REFERENCES shared_records(id)
);
