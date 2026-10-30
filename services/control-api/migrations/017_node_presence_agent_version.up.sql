ALTER TABLE node_presence
    ADD COLUMN agent_version text,
    ADD COLUMN confirmed_agent_version text,
    ADD CONSTRAINT node_presence_agent_version_check CHECK (
        agent_version IS NULL OR agent_version ~ '^[A-Za-z0-9][A-Za-z0-9._+:-]{0,127}$'
    ),
    ADD CONSTRAINT node_presence_confirmed_agent_version_check CHECK (
        confirmed_agent_version IS NULL OR confirmed_agent_version ~ '^[A-Za-z0-9][A-Za-z0-9._+:-]{0,127}$'
    );
