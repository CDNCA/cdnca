#!/usr/bin/env python3
"""Apply the ClickHouse analytics migrations for compose, Helm and external ClickHouse.

Same ledger (schema_migrations), ordering, checksum and refusal rules as the
native installer (scripts/native-runtime/configure-clickhouse.py), whose
functions are reused unchanged. Configuration comes only from the environment:

  CLICKHOUSE_MIGRATE_URL            http(s)://host:port (no credentials, path or query)
  CLICKHOUSE_MIGRATE_USER           migration identity
  CLICKHOUSE_MIGRATE_PASSWORD       or CLICKHOUSE_MIGRATE_PASSWORD_FILE
  CLICKHOUSE_MIGRATE_DATABASE       target database
  CLICKHOUSE_MIGRATE_CLUSTER        optional; non-empty enables ON CLUSTER + Replicated engines
  CLICKHOUSE_MIGRATE_CA_FILE        optional CA bundle for https
  CLICKHOUSE_MIGRATE_MIGRATIONS     migration directory (default /opt/cdnca/clickhouse/migrations)
  CLICKHOUSE_MIGRATE_GRANT_QUERY_USER / _INGEST_USER / _ROLLUP_USER
                                    optional; all three set makes `migrate` re-assert runtime grants

Actions:
  migrate       apply pending migrations; exit 1 on any failure
  check         verify the ledger only, list pending migrations
  dry-run       print the SQL `migrate` would run, change nothing; without
                CLICKHOUSE_MIGRATE_URL it prints the full sequence for an empty database
  print-grants  print the runtime grant SQL for the three runtime identities
"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import re
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request


def _load_native():
    here = Path(__file__).resolve().parent
    for candidate in (here / "configure-clickhouse.py", here.parent / "native-runtime" / "configure-clickhouse.py"):
        if candidate.is_file():
            spec = importlib.util.spec_from_file_location("native_clickhouse", candidate)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            return module
    raise SystemExit("configure-clickhouse.py not found next to the migrator")


CH = _load_native()
IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,62}")
MINIMUM_VERSION = (25, 3)
DEFAULT_MIGRATIONS = "/opt/cdnca/clickhouse/migrations"
# Statement heads that accept ON CLUSTER right after the object name.
DDL_HEAD = re.compile(r"^(\s*(?:CREATE\s+(?:OR\s+REPLACE\s+)?(?:MATERIALIZED\s+)?(?:TABLE|VIEW)(?:\s+IF\s+NOT\s+EXISTS)?"
                      r"|ALTER\s+TABLE|DROP\s+(?:TABLE|VIEW)(?:\s+IF\s+EXISTS)?)\s+)([A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)?)", re.I)
ENGINE = re.compile(r"(ENGINE\s*=\s*)(Replacing|Aggregating|Summing|Collapsing|VersionedCollapsing)?MergeTree\b(\s*\(([^()]*)\))?", re.I)
GRANT_HEAD = re.compile(r"^\s*GRANT\s+", re.I)
INSERT_TARGET = re.compile(r"^\s*INSERT\s+INTO\s+([A-Za-z_][A-Za-z0-9_]*)", re.I)


class MigrateError(RuntimeError):
    def __init__(self, reason):
        super().__init__(reason)
        self.reason = reason


def identifier(value, name):
    if not IDENTIFIER.fullmatch(value or ""):
        raise MigrateError(f"invalid_{name}")
    return value


def cluster_statement(sql, cluster):
    """Rewrite one migration statement for a replicated cluster; refuse unknown kinds."""
    if INSERT_TARGET.match(sql):
        return sql  # DML is routed per shard by the executor, never ON CLUSTER.
    if GRANT_HEAD.match(sql):
        return GRANT_HEAD.sub(lambda m: m[0] + f"ON CLUSTER {cluster} ", sql, count=1)
    match = DDL_HEAD.match(sql)
    if not match:
        raise MigrateError("statement_not_cluster_safe")
    sql = sql[:match.end()] + f" ON CLUSTER {cluster}" + sql[match.end():]
    # The ledger is one replicated table shared by every node of the cluster,
    # so any node reads the same migration history; data tables are per shard.
    # Its replica name must then be unique cluster-wide, hence shard + replica.
    ledger = match[2] == CH.LEDGER
    shard, replica = ("cdnca_ledger", "{shard}-{replica}") if ledger else ("{shard}", "{replica}")

    def replicated(engine):
        args = f"'/clickhouse/tables/{shard}/{{database}}/{{table}}', '{replica}'"
        extra = (engine[4] or "").strip()
        return f"{engine[1]}Replicated{engine[2] or ''}MergeTree({args}{', ' + extra if extra else ''})"
    return ENGINE.sub(replicated, sql)


class Connection:
    def __init__(self, url, user, password, database, ca_file=None, timeout=CH.MIGRATION_TIMEOUT):
        parsed = urllib.parse.urlsplit(url)
        if parsed.scheme not in ("http", "https") or not parsed.hostname or parsed.username or parsed.password \
                or parsed.path not in ("", "/") or parsed.query or parsed.fragment:
            raise MigrateError("invalid_url")
        self.scheme, self.port = parsed.scheme, parsed.port or (8443 if parsed.scheme == "https" else 8123)
        self.base = f"{parsed.scheme}://{parsed.netloc}/"
        self.user, self.password, self.database, self.timeout = user, password, database, timeout
        context = ssl.create_default_context(cafile=ca_file) if parsed.scheme == "https" else None
        handlers = [urllib.request.ProxyHandler({})]
        if context is not None:
            handlers.append(urllib.request.HTTPSHandler(context=context))
        self.opener = urllib.request.build_opener(*handlers)

    def at(self, host):
        other = Connection.__new__(Connection)
        other.__dict__.update(self.__dict__)
        other.base = f"{self.scheme}://{host}:{self.port}/"
        return other

    def __call__(self, sql, database=None):
        query = {"max_execution_time": str(self.timeout), "wait_end_of_query": "1"}
        if database is not False:
            query["database"] = database or self.database
        request = urllib.request.Request(self.base + "?" + urllib.parse.urlencode(query), data=sql.encode("utf-8"),
                                         method="POST", headers={"X-ClickHouse-User": self.user, "X-ClickHouse-Key": self.password})
        try:
            with self.opener.open(request, timeout=self.timeout + 30) as response:
                return response.read(16 << 20).decode("utf-8").strip()
        except urllib.error.HTTPError as failure:
            # Server text can echo SQL or credentials; relay only the error code name.
            code = re.search(rb"\(([A-Z][A-Z0-9_]{2,63})\)", failure.read(65536) or b"")
            raise MigrateError("clickhouse_" + (code[1].decode().lower() if code else "error"))
        except (urllib.error.URLError, OSError):
            raise MigrateError("clickhouse_network_error")


class Executor:
    """The `execute` callback for native_clickhouse_apply_migrations.

    Rewrites for ON CLUSTER, runs migration INSERT backfills once per shard
    (source and target are shard-local), and in dry-run prints every write.
    """

    def __init__(self, connection, cluster="", dry_run=False, out=sys.stdout):
        self.connection, self.cluster, self.dry_run, self.out = connection, cluster, dry_run, out
        self._shards, self.planned_ledger = None, False

    def shards(self):
        if self._shards is None:
            rows = self.connection("SELECT shard_num, host_name FROM system.clusters WHERE cluster = "
                                   f"'{self.cluster}' AND replica_num = 1 ORDER BY shard_num").splitlines()
            self._shards = [row.split("\t")[1] for row in rows]
            if not self._shards:
                raise MigrateError("cluster_not_found")
        return self._shards

    def __call__(self, sql):
        head = sql.lstrip()[:7].upper()
        if head.startswith("EXISTS") or head.startswith("SELECT"):
            if self.dry_run and self.planned_ledger and f"FROM {CH.LEDGER}" in sql:
                return ""  # the ledger only exists in the printed plan
            if self.connection is None:  # offline dry-run: an empty database
                return "0" if head.startswith("EXISTS") or "count()" in sql else ""
            return self.connection(sql)
        target = INSERT_TARGET.match(sql)
        per_shard = bool(self.cluster) and target is not None and target[1] != CH.LEDGER
        if self.cluster:
            sql = cluster_statement(sql, self.cluster)
        if self.dry_run:
            self.planned_ledger = self.planned_ledger or sql.lstrip().upper().startswith(f"CREATE TABLE IF NOT EXISTS {CH.LEDGER.upper()}")
            prefix = f"-- run on the first replica of every shard of {self.cluster}\n" if per_shard else ""
            self.out.write(prefix + sql.rstrip().rstrip(";") + ";\n\n")
            return ""
        if per_shard and len(self.shards()) > 1:
            for host in self.shards():
                self.connection.at(host)(sql)
            return ""
        return self.connection(sql)


def environment():
    env = os.environ
    password = env.get("CLICKHOUSE_MIGRATE_PASSWORD", "")
    if env.get("CLICKHOUSE_MIGRATE_PASSWORD_FILE"):
        password = Path(env["CLICKHOUSE_MIGRATE_PASSWORD_FILE"]).read_text().rstrip("\r\n")
    cluster = env.get("CLICKHOUSE_MIGRATE_CLUSTER", "")
    grants = [env.get(f"CLICKHOUSE_MIGRATE_GRANT_{kind}_USER", "") for kind in ("QUERY", "INGEST", "ROLLUP")]
    if any(grants) and not all(grants):
        raise MigrateError("grant_users_incomplete")
    return {"url": env.get("CLICKHOUSE_MIGRATE_URL", ""), "user": env.get("CLICKHOUSE_MIGRATE_USER", ""),
            "password": password, "database": identifier(env.get("CLICKHOUSE_MIGRATE_DATABASE", ""), "database"),
            "cluster": identifier(cluster, "cluster") if cluster else "", "ca_file": env.get("CLICKHOUSE_MIGRATE_CA_FILE") or None,
            "migrations": Path(env.get("CLICKHOUSE_MIGRATE_MIGRATIONS", DEFAULT_MIGRATIONS)),
            "grants": [identifier(user, "grant_user") for user in grants] if all(grants) else None}


def grant_statements(database, users):
    """The native least-privilege grants, mapped onto operator-chosen identity names."""
    statements = []
    CH.native_clickhouse_grants(database, statements.append)
    mapping = dict(zip((database + "_query", database + "_ingest", database + "_rollup"), users))
    pattern = re.compile(r"\b(" + "|".join(map(re.escape, mapping)) + r")\b")
    return [pattern.sub(lambda m: mapping[m[1]], sql) for sql in statements]


def connect(config):
    if not config["url"] or not config["user"] or not config["password"]:
        raise MigrateError("connection_settings_missing")
    connection = Connection(config["url"], config["user"], config["password"], config["database"], config["ca_file"])
    version = connection("SELECT version()", database=False)
    if tuple(int(part) for part in version.split(".")[:2]) < MINIMUM_VERSION:
        raise MigrateError("clickhouse_version_unsupported")
    return connection, version


def ensure_database(connection, config, execute):
    if connection is not None and connection(f"EXISTS DATABASE {config['database']}", database=False) == "1":
        return
    sql = f"CREATE DATABASE IF NOT EXISTS {config['database']}" + (f" ON CLUSTER {config['cluster']}" if config["cluster"] else "")
    if execute.dry_run:
        execute.out.write(sql + ";\n\n")
    else:
        connection(sql, database=False)


def run(action, out=sys.stdout):
    config = environment()
    if action == "print-grants":
        if not config["grants"]:
            raise MigrateError("grant_users_missing")
        executor = Executor(None, config["cluster"], dry_run=True, out=out)
        for sql in grant_statements(config["database"], config["grants"]):
            executor(sql)
        return None
    connection, version = (None, None) if action == "dry-run" and not config["url"] else connect(config)
    executor = Executor(connection, config["cluster"], dry_run=action == "dry-run", out=out)
    if action == "dry-run":
        out.write(f"-- cdnca ClickHouse migrations for database {config['database']}"
                  + (f" on cluster {config['cluster']}" if config["cluster"] else "") + "\n"
                  + ("-- offline: assumes an empty database\n\n" if connection is None else f"-- server {version}\n\n"))
        ensure_database(connection, config, executor)
    elif action == "migrate":
        ensure_database(connection, config, executor)
    elif connection(f"EXISTS DATABASE {config['database']}", database=False) != "1":
        raise MigrateError("database_missing")
    if action == "dry-run" and connection is not None and connection(f"EXISTS DATABASE {config['database']}", database=False) != "1":
        executor.connection = None  # the database does not exist yet: plan as empty
    result = CH.native_clickhouse_apply_migrations(config["migrations"], executor, check_only=action == "check")
    if action != "check" and config["grants"]:
        for sql in grant_statements(config["database"], config["grants"]):
            executor(sql)
    return {"database": config["database"], "cluster": config["cluster"] or None, "version": version,
            "pending": [item["path"] for item in result if item["pending"]],
            "applied": [item["path"] for item in result if item["applied_now"]]}


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("action", choices=["migrate", "check", "dry-run", "print-grants"])
    action = parser.parse_args().action
    try:
        result = run(action)
    except (MigrateError, CH.NativeClickHouseLedgerError, ValueError, OSError) as error:
        reason = getattr(error, "reason", None) or "invalid_input"
        print(json.dumps({"status": "migration_failed", "reason": reason}), file=sys.stderr if action in ("dry-run", "print-grants") else sys.stdout)
        raise SystemExit(1)
    if result is not None and action != "dry-run":
        print(json.dumps({"status": "migrations_checked" if action == "check" else "migrations_applied", **result}))


if __name__ == "__main__":
    main()
