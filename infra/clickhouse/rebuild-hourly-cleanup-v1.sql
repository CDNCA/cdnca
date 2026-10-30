SELECT throwIf(
    uniqExact(tuple(owner, lock_token)) != 1 OR any(owner) != {owner:String} OR
        any(lock_token) != {lock_token:String},
    'analytics rebuild cleanup owner does not match'
)
FROM {run_marker:Identifier};

DROP VIEW IF EXISTS {access_catchup:Identifier};
DROP VIEW IF EXISTS {security_catchup:Identifier};
DROP TABLE IF EXISTS {access_shadow:Identifier} SYNC;
DROP TABLE IF EXISTS {security_shadow:Identifier} SYNC;
DROP TABLE {run_marker:Identifier} SYNC;
