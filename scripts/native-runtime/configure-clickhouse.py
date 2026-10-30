#!/usr/bin/env python3
"""Initialize or upgrade the fixed native ClickHouse profile from a verified release.

The caller verifies the enclosing release before invoking this helper.
`install` is fresh-install only: existing databases, users and private state are
never reset. `migrate` applies the release's not yet applied migrations, in
order, to an installed database; `migrate --check` only verifies the ledger.
Both record every migration in the schema_migrations ledger with its SHA-256.
"""
import argparse
import grp
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import re
import secrets
import stat
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request


VERSION = "25.3.6.56"
STATE = Path("/etc/cdnca-analytics")
# Host port profile written by install-control.sh (a BaoTa host may
# already run ClickHouse-like services on 8123/9000); absent = default ports.
RUNTIME_PORTS = Path("/etc/cdnca-native-dependencies/runtime.env")
LOOPBACK_DEFAULT = (b'<clickhouse>\n    <listen_host replace="replace">127.0.0.1</listen_host>\n'
                    b'    <interserver_listen_host replace="replace">127.0.0.1</interserver_listen_host>\n</clickhouse>\n')
_PROFILE_KEYS = {"ENV", "WEB_PORT", "NODE_DOWNLOAD_PORT", "PG_PORT", "REDIS_PORT", "CH_HTTP_PORT", "CH_TCP_PORT", "CH_MYSQL_PORT", "CH_POSTGRESQL_PORT", "CH_INTERSERVER_PORT"}
_LOOPBACK_TAGS = (("CH_HTTP_PORT", "http_port", 8123), ("CH_TCP_PORT", "tcp_port", 9000), ("CH_MYSQL_PORT", "mysql_port", 9004),
                  ("CH_POSTGRESQL_PORT", "postgresql_port", 9005), ("CH_INTERSERVER_PORT", "interserver_http_port", 9009))


def native_clickhouse_profile(path=RUNTIME_PORTS):
    """Strict KEY=value parse of the port profile; never executed."""
    try:
        text = path.read_text(encoding="ascii")
    except FileNotFoundError:
        return {}
    values = {}
    for line in text.splitlines():
        match = re.fullmatch(r"([A-Z_]+)=([a-z0-9]+)", line)
        if not match or match[1] not in _PROFILE_KEYS or match[1] in values:
            raise ValueError("invalid host port profile")
        key, value = match[1], match[2]
        if key == "ENV":
            if value not in ("bt", "plain"):
                raise ValueError("invalid host port profile")
        elif not re.fullmatch(r"[1-9][0-9]{3,4}", value) or int(value) > 65535:
            raise ValueError("invalid host port profile")
        values[key] = value
    return values


def native_clickhouse_ports(path=RUNTIME_PORTS):
    profile = native_clickhouse_profile(path)
    return {"http": int(profile.get("CH_HTTP_PORT", 8123)), "tcp": int(profile.get("CH_TCP_PORT", 9000))}


def native_clickhouse_loopback_content(ports=None, path=RUNTIME_PORTS):
    """Same bytes install-ubuntu-dependencies.sh writes: defaults unchanged, moved ports appended."""
    profile = native_clickhouse_profile(path) if ports is None else {"CH_HTTP_PORT": str(ports["http"]), "CH_TCP_PORT": str(ports["tcp"])}
    extra = b"".join(f"    <{tag}>{profile[key]}</{tag}>\n".encode() for key, tag, default in _LOOPBACK_TAGS
                     if key in profile and int(profile[key]) != default)
    return LOOPBACK_DEFAULT[:-len(b"</clickhouse>\n")] + extra + b"</clickhouse>\n"


def native_clickhouse_http_url(ports):
    return f"http://127.0.0.1:{ports['http']}"


PORTS = native_clickhouse_ports()
HTTP_URL = native_clickhouse_http_url(PORTS) + "/"
# Same ledger name and meaning as the control-api PostgreSQL migrator.
LEDGER = "schema_migrations"
MIGRATION = re.compile(r"([0-9]{3})_([a-z0-9]+(?:_[a-z0-9]+)*)[.]up[.]sql")
# A backfill migration may scan a large table; this bounds one statement.
MIGRATION_TIMEOUT = 3600
ROLLUPS = {
    "access_hourly_mv_v1": "access_hourly_facts_v1",
    "security_hourly_mv_v1": "security_hourly_facts_v1",
    "access_version_evidence_mv_v1": "access_version_evidence_v1",
    "security_version_evidence_mv_v1": "security_version_evidence_v1",
    "package_metric_access_facts_mv_v1": "package_metric_access_facts_v1",
    "access_metering_facts_mv_v1": "access_metering_facts_v1",
    "access_event_latest_state_mv_v1": "access_event_latest_state_v1",
    "access_event_conflict_state_mv_v1": "access_event_conflict_state_v1",
    "security_event_latest_state_mv_v1": "security_event_latest_state_v1",
    "security_event_conflict_state_mv_v1": "security_event_conflict_state_v1",
    "site_realtime_access_facts_mv_v1": "site_realtime_access_facts_v1",
    "access_event_query_index_mv_v1": "access_event_query_index_state_v1",
    "access_event_query_payload_mv_v1": "access_event_query_payload_state_v1",
    "security_event_query_index_mv_v1": "security_event_query_index_state_v1",
    "security_event_query_payload_mv_v1": "security_event_query_payload_state_v1",
    "security_event_evidence_mv_v1": "security_event_evidence_state_v1",
    "security_event_count_mv_v1": "security_event_count_state_v1",
}
RETENTION_TTL_TABLES = [
    "access_events", "access_event_latest_state_v1", "access_event_query_index_state_v1",
    "access_event_query_payload_state_v1", "security_events", "security_event_latest_state_v1",
    "security_event_query_index_state_v1", "security_event_query_payload_state_v1",
    "security_event_evidence_state_v1", "security_event_count_state_v1",
    "access_hourly_facts_v1", "security_hourly_facts_v1",
]


def native_clickhouse_identifier(value):
    if not re.fullmatch(r"(?:cdnca_|cdnca_ch_acceptance_)[a-z0-9_]{1,36}", value):
        raise ValueError("invalid native ClickHouse database")
    return value


def native_clickhouse_command(sql, *, database="default", config=None, denied=False, authentication_denied=False):
    command = ["clickhouse-client", "--host", "127.0.0.1", "--port", str(PORTS["tcp"]), "--database", database,
               "--multiquery", "--log_queries=0", "--max_execution_time=60"]
    if config is not None:
        command += ["--config-file", str(config)]
    result = subprocess.run(command, input=sql, universal_newlines=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=120)
    if authentication_denied:
        if result.returncode != 0 and any(code in result.stderr for code in ["AUTHENTICATION_FAILED", "IP_ADDRESS_NOT_ALLOWED", "REQUIRED_PASSWORD"]):
            return ""
        raise RuntimeError("ClickHouse did not reject the forbidden login")
    if denied:
        if result.returncode != 0 and "ACCESS_DENIED" in result.stderr:
            return ""
        raise RuntimeError("ClickHouse did not reject the forbidden operation")
    if result.returncode:
        # SQL errors can echo credentials or hashes. Never relay server stderr.
        reason = re.search(r"\((ACCESS_DENIED|NO_DATA_TO_INSERT|AUTHENTICATION_FAILED|UNKNOWN_SETTING|SYNTAX_ERROR|UNKNOWN_DATABASE|NETWORK_ERROR)\)", result.stderr)
        raise RuntimeError("ClickHouse command failed (" + (reason[1] if reason else "UNKNOWN") + "); inspect the private server log")
    return result.stdout.strip()


def native_clickhouse_private_file(path, contents):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "w") as target:
        target.write(contents)
        target.flush()
        os.fsync(target.fileno())


def native_clickhouse_client_config(user, password):
    # Both values are generated hex/identifier data, never arbitrary XML input.
    if not re.fullmatch(r"[a-z0-9_]+", user) or not re.fullmatch(r"[0-9a-f]{64}", password):
        raise ValueError("invalid native ClickHouse credential structure")
    return f"<config><user>{user}</user><password>{password}</password></config>\n"


class NativeClickHouseLedgerError(ValueError):
    """The database ledger and the release migrations disagree; never auto-repaired."""

    def __init__(self, reason, detail=""):
        super().__init__(reason + (": " + detail if detail else ""))
        self.reason = reason


def native_clickhouse_migrations(directory):
    """The release's complete migration inventory: 001..N, contiguous, regular files."""
    if directory.is_symlink() or not directory.is_dir():
        raise ValueError("migration directory must be a verified regular directory")
    result = sorted(directory.glob("*.up.sql"))
    if not result or len(result) > 999:
        raise ValueError("native ClickHouse migration inventory is empty or too large")
    for index, path in enumerate(result, 1):
        info = path.lstat()
        match = MIGRATION.fullmatch(path.name)
        if not match or int(match[1]) != index or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise ValueError("invalid native ClickHouse migration inventory")
    return result


def native_clickhouse_statements(sql):
    """Split a migration into statements at semicolons outside literals and comments."""
    statements, current, index, quote = [], [], 0, None
    while index < len(sql):
        char = sql[index]
        if quote:
            current.append(char)
            if char == "\\" and index + 1 < len(sql):
                current.append(sql[index + 1])
                index += 1
            elif char == quote:
                if sql.startswith(quote, index + 1):
                    current.append(quote)
                    index += 1
                else:
                    quote = None
        elif char in "'\"`":
            quote = char
            current.append(char)
        elif sql.startswith("--", index):
            end = sql.find("\n", index)
            index = len(sql) if end < 0 else end
            continue
        elif sql.startswith("/*", index):
            end = sql.find("*/", index + 2)
            if end < 0:
                raise ValueError("unterminated comment in ClickHouse migration")
            index = end + 2
            current.append(" ")
            continue
        elif char == ";":
            statements.append("".join(current).strip())
            current = []
        else:
            current.append(char)
        index += 1
    if quote:
        raise ValueError("unterminated literal in ClickHouse migration")
    statements.append("".join(current).strip())
    return [statement for statement in statements if statement]


def native_clickhouse_http(sql, *, database, user, password, timeout=60):
    """One statement over the loopback HTTP interface; credentials only in headers."""
    query = urllib.parse.urlencode({"database": database, "max_execution_time": str(timeout), "wait_end_of_query": "1"})
    request = urllib.request.Request(HTTP_URL + "?" + query, data=sql.encode("utf-8"), method="POST",
                                     headers={"X-ClickHouse-User": user, "X-ClickHouse-Key": password})
    # Loopback only: never route through an inherited proxy.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(request, timeout=timeout + 30) as response:
            return response.read(16 << 20).decode("utf-8").strip()
    except urllib.error.HTTPError as failure:
        # Server text can echo SQL or credentials; keep only the error code name.
        reason = re.search(rb"\(([A-Z][A-Z0-9_]{2,63})\)", failure.read(65536) or b"")
        raise RuntimeError("ClickHouse command failed (" + (reason[1].decode() if reason else "UNKNOWN") + "); inspect the private server log")
    except (urllib.error.URLError, OSError):
        raise RuntimeError("ClickHouse command failed (NETWORK_ERROR); inspect the private server log")


def native_clickhouse_admin_login(state):
    path = state / "admin.xml"
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600 or info.st_uid != os.geteuid():
        raise ValueError("unsafe ClickHouse administrator configuration")
    match = re.fullmatch(r"<config><user>([a-z0-9_]+)</user><password>([0-9a-f]{64})</password></config>\n", path.read_text())
    if not match:
        raise ValueError("invalid ClickHouse administrator configuration")
    return match[1], match[2]


def native_clickhouse_apply_migrations(migrations, execute, *, check_only=False):
    """Apply the not yet applied migrations in order, recording each in the ledger.

    `execute` runs one statement in the target database. A ledger row is written
    as running (applied=0) before a migration's first statement and replaced by
    applied=1 after its last, so an interrupted migration is re-run from its
    start on retry; migrations must therefore be idempotent (IF NOT EXISTS).
    A recorded checksum that differs from the release file is always refused.
    """
    inventory = []
    for path in native_clickhouse_migrations(migrations):
        body = path.read_bytes()
        inventory.append({"version": int(path.name[:3]), "name": path.name[:-len(".up.sql")], "path": path.name,
                          "sha256": hashlib.sha256(body).hexdigest(), "sql": body.decode("utf-8")})
    if execute(f"EXISTS TABLE {LEDGER}") != "1":
        if check_only:
            raise NativeClickHouseLedgerError("ledger_missing")
        # Never replay 001 over a schema whose history is unknown.
        if execute("SELECT count() FROM system.tables WHERE database = currentDatabase()") != "0":
            raise NativeClickHouseLedgerError("unledgered_schema")
        execute(f"CREATE TABLE IF NOT EXISTS {LEDGER} (version UInt16, name String, checksum FixedString(64), "
                "applied UInt8, recorded_at DateTime64(3, 'UTC') DEFAULT now64(3)) "
                "ENGINE = ReplacingMergeTree(applied) ORDER BY version")
    recorded = {}
    for line in execute(f"SELECT version, name, checksum, applied FROM {LEDGER} FINAL ORDER BY version").splitlines():
        version, name, checksum, applied = line.split("\t")
        recorded[int(version)] = (name, checksum, applied == "1")
    if recorded and max(recorded) > len(inventory):
        raise NativeClickHouseLedgerError("ledger_ahead", f"database has migration {max(recorded):03}, release has {len(inventory):03}")
    for item in inventory:
        row = recorded.get(item["version"])
        if row and (row[0] != item["name"] or row[1] != item["sha256"]):
            raise NativeClickHouseLedgerError("checksum_mismatch", item["path"])
    applied = [version for version, row in recorded.items() if row[2]]
    if any(version not in recorded or not recorded[version][2] for version in range(1, max(applied, default=0) + 1)):
        raise NativeClickHouseLedgerError("ledger_gap")
    pending = [item for item in inventory if item["version"] not in applied]
    result = [{"path": item["path"], "sha256": item["sha256"], "pending": item in pending, "applied_now": False} for item in inventory]
    if check_only:
        return result
    for item in pending:
        # name and sha256 come from the validated inventory, never from input.
        record = f"INSERT INTO {LEDGER} (version, name, checksum, applied) VALUES ({item['version']}, '{item['name']}', '{item['sha256']}', %d)"
        execute(record % 0)
        for statement in native_clickhouse_statements(item["sql"]):
            execute(statement)
        execute(record % 1)
        result[item["version"] - 1]["applied_now"] = True
    return result


def native_clickhouse_grants(database, execute):
    """Least-privilege grants for the fixed runtime identities; idempotent."""
    query_user, ingest_user, rollup_user = database + "_query", database + "_ingest", database + "_rollup"
    for table in ["access_events", "security_events", "access_version_evidence_v1", "security_version_evidence_v1"]:
        execute(f"GRANT SELECT ON {database}.{table} TO {rollup_user}")
    for view, target in ROLLUPS.items():
        execute(f"GRANT INSERT ON {database}.{target} TO {rollup_user}")
        execute(f"ALTER TABLE {database}.{view} MODIFY SQL SECURITY DEFINER DEFINER = {rollup_user}")
    execute(f"GRANT SELECT ON {database}.* TO {query_user}")
    execute(f"GRANT SELECT ON system.columns TO {ingest_user}")
    for table in ["access_events", "security_events", "connections_ingest_receipts_v1", "l4_session_facts_v1", "l4_session_logs_v1",
                  "autodefense_verdicts_v1", "node_security_events_v1", "cc_rule_stats_v1", "subscription_minutes_v1",
                  "market_security_events_v1"]:
        execute(f"GRANT INSERT ON {database}.{table} TO {ingest_user}")
    execute(f"GRANT SELECT ON {database}.connections_ingest_receipts_v1 TO {ingest_user}")
    # FX01: control-api makes these history TTLs follow the cleanup settings;
    # the grant allows changing the TTL only (keep in sync with ttlTargets in
    # services/control-api/internal/retentioncleanup/clickhouse_ttl.go).
    for table in RETENTION_TTL_TABLES:
        execute(f"GRANT ALTER MODIFY TTL ON {database}.{table} TO {ingest_user}")


def upgrade_native_clickhouse(migrations, state, *, check_only=False):
    """Bring an installed database to this release's migration head."""
    native_clickhouse_migrations(migrations)
    database = native_clickhouse_identifier(json.loads((state / "credentials.json").read_text())["database"])
    user, password = native_clickhouse_admin_login(state)
    execute = lambda sql: native_clickhouse_http(sql, database=database, user=user, password=password, timeout=MIGRATION_TIMEOUT)
    if execute("SELECT version()") != VERSION:
        raise ValueError("native ClickHouse version mismatch")
    result = native_clickhouse_apply_migrations(migrations, execute, check_only=check_only)
    if not check_only:
        # New migrations may add tables or rebuild views; re-assert every grant.
        native_clickhouse_grants(database, execute)
    return {"database": database, "pending": [item["path"] for item in result if item["pending"]],
            "applied": [item["path"] for item in result if item["applied_now"]]}


def native_clickhouse_failure_reason(error):
    if isinstance(error, NativeClickHouseLedgerError):
        return error.reason
    if isinstance(error, (RuntimeError, subprocess.SubprocessError)):
        return "clickhouse_error"
    return "invalid_input"


def configure_native_clickhouse(migrations, state, *, database="cdnca_analytics"):
    database = native_clickhouse_identifier(database)
    if state.exists() or state.is_symlink():
        raise FileExistsError("existing analytics state; use recovery, not fresh installation")
    files = native_clickhouse_migrations(migrations)
    if native_clickhouse_command("SELECT version()") != VERSION:
        raise ValueError("native ClickHouse version mismatch")
    query_user, ingest_user = database + "_query", database + "_ingest"
    rollup_user = database + "_rollup"
    for query in [f"EXISTS DATABASE {database}",
                  f"SELECT count() FROM system.users WHERE name IN ('{query_user}', '{ingest_user}', '{rollup_user}')"]:
        if native_clickhouse_command(query) != "0":
            raise FileExistsError("existing ClickHouse database or runtime user; refusing overwrite")
    state.mkdir(mode=0o700)
    credentials = {"database": database, "query_user": query_user, "ingest_user": ingest_user,
                   "query_password": secrets.token_hex(32), "ingest_password": secrets.token_hex(32)}
    native_clickhouse_private_file(state / "credentials.json", json.dumps(credentials) + "\n")
    for kind in ["query", "ingest"]:
        native_clickhouse_private_file(state / f"{kind}.xml", native_clickhouse_client_config(credentials[f"{kind}_user"], credentials[f"{kind}_password"]))
    native_clickhouse_private_file(state / "rollup-login.xml", f"<config><user>{rollup_user}</user><password></password></config>\n")
    native_clickhouse_command(f"CREATE DATABASE {database}")
    # The same ledgered, ordered path as `migrate`; an upgrade later continues from it.
    applied = native_clickhouse_apply_migrations(files[0].parent, lambda sql: native_clickhouse_command(sql, database=database))
    inventory = [{"path": item["path"], "sha256": item["sha256"]} for item in applied]
    for kind in ["query", "ingest"]:
        digest = hashlib.sha256(credentials[f"{kind}_password"].encode()).hexdigest()
        native_clickhouse_command(f"CREATE USER {credentials[f'{kind}_user']} IDENTIFIED WITH sha256_hash BY '{digest}' HOST IP '127.0.0.1'")
    # Explicit security is required on 25.3: omitted view security retains
    # legacy invoker behavior even when the session default says DEFINER.
    # This identity cannot log in, and has no schema or user-management rights.
    native_clickhouse_command(f"CREATE USER {rollup_user} NOT IDENTIFIED HOST NONE")
    native_clickhouse_grants(database, native_clickhouse_command)
    verify_native_clickhouse(state)
    environment = {
        "CLICKHOUSE_URL": native_clickhouse_http_url(PORTS), "CLICKHOUSE_DATABASE": database,
        "CLICKHOUSE_USERNAME": query_user, "CLICKHOUSE_PASSWORD": credentials["query_password"],
        "ANALYTICS_INGEST_CLICKHOUSE_URL": native_clickhouse_http_url(PORTS), "ANALYTICS_INGEST_CLICKHOUSE_DATABASE": database,
        "ANALYTICS_INGEST_CLICKHOUSE_USER": ingest_user, "ANALYTICS_INGEST_CLICKHOUSE_PASSWORD": credentials["ingest_password"],
    }
    native_clickhouse_private_file(state / "runtime.env", "".join(f"{key}={value}\n" for key, value in environment.items()))
    native_clickhouse_private_file(state / "receipt.json", json.dumps({"schema": "cdnca.native-clickhouse/v1",
        "version": VERSION, "database": database, "migrations": inventory, "rollup_definer": rollup_user,
        "rollups": ROLLUPS, "database_preflight": "passed"}, indent=2) + "\n")


def verify_native_clickhouse(state, *, require_private_admin=False):
    credentials_path = state / "credentials.json"
    info = credentials_path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600 or info.st_uid != os.geteuid():
        raise ValueError("unsafe ClickHouse credential file")
    database = native_clickhouse_identifier(json.loads(credentials_path.read_text())["database"])
    query, ingest = state / "query.xml", state / "ingest.xml"
    configs = [query, ingest, state / "rollup-login.xml"]
    if require_private_admin:
        configs += [state / "admin.xml", state / "anonymous.xml"]
    for config in configs:
        info = config.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600 or info.st_uid != os.geteuid():
            raise ValueError("unsafe ClickHouse client configuration")
    if require_private_admin:
        native_clickhouse_command("SELECT 1", config=state / "admin.xml")
        native_clickhouse_command("SELECT 1", config=state / "anonymous.xml", authentication_denied=True)
    native_clickhouse_command("SELECT 1", config=state / "rollup-login.xml", authentication_denied=True)
    for table in ["access_events", "security_events", "connections_ingest_receipts_v1", "l4_session_facts_v1", "access_event_query_index_state_v1"]:
        native_clickhouse_command(f"SELECT count() FROM {table} WHERE 0", database=database, config=query)
    for table in ["access_events", "security_events"]:
        # clickhouse-client rejects an empty JSONEachRow stream before sending
        # it. A zero-row literal SELECT checks INSERT without fabricating data
        # or granting the ingest identity SELECT on the underlying table.
        empty_insert = f"INSERT INTO {table} (metric_version) SELECT toUInt16(1) WHERE 0"
        native_clickhouse_command(empty_insert, database=database, config=ingest)
        native_clickhouse_command(empty_insert, database=database, config=query, denied=True)
        native_clickhouse_command(f"SELECT count() FROM {table}", database=database, config=ingest, denied=True)
    # Smart auto defense (AD-08): control-api writes verdicts and node
    # security events with the ingest identity and reads them with the query one.
    for table in ["autodefense_verdicts_v1", "node_security_events_v1"]:
        native_clickhouse_command(f"SELECT count() FROM {table} WHERE 0", database=database, config=query)
        native_clickhouse_command(f"SELECT count() FROM {table}", database=database, config=ingest, denied=True)
    for table, column, value in [("connections_ingest_receipts_v1", "schema_version", "toUInt32(1)"),
                                 ("l4_session_facts_v1", "source_watermark", "toUInt64(1)"),
                                 ("autodefense_verdicts_v1", "score", "toUInt8(0)"),
                                 ("node_security_events_v1", "count", "toUInt64(0)")]:
        empty_insert = f"INSERT INTO {table} ({column}) SELECT {value} WHERE 0"
        native_clickhouse_command(empty_insert, database=database, config=ingest)
        native_clickhouse_command(empty_insert, database=database, config=query, denied=True)
    native_clickhouse_command("SELECT count() FROM connections_ingest_receipts_v1 WHERE 0", database=database, config=ingest)
    native_clickhouse_command("SELECT count() FROM l4_session_facts_v1", database=database, config=ingest, denied=True)
    for config in [query, ingest]:
        for privilege in ["CREATE TABLE", "ALTER TABLE", "DROP TABLE", "TRUNCATE"]:
            if native_clickhouse_command(f"CHECK GRANT {privilege} ON {database}.*", config=config) != "0":
                raise RuntimeError("ClickHouse runtime identity has forbidden schema privileges")
        native_clickhouse_command("SELECT name FROM system.users", database=database, config=config, denied=True)


def native_clickhouse_installed():
    if json.loads((STATE / "installed.json").read_text()) != {"schema": "cdnca.native-clickhouse-install/v1", "version": VERSION}:
        raise ValueError("ClickHouse installation receipt is missing or incompatible")


def native_clickhouse_migrate(args):
    """Upgrade entry point: one JSON line on stdout, success or a stable failure reason."""
    try:
        if args.migrations is None:
            raise ValueError("verified release migrations are required")
        native_clickhouse_installed()
        result = upgrade_native_clickhouse(args.migrations, STATE, check_only=args.check)
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError, KeyError) as error:
        # Retrying is safe: applied migrations are skipped by checksum.
        print(json.dumps({"status": "migration_failed", "reason": native_clickhouse_failure_reason(error)}))
        raise SystemExit(1)
    print(json.dumps({"status": "migrations_checked" if args.check else "migrations_applied",
                      "pending": result["pending"], "applied": result["applied"]}))


def native_clickhouse_main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["install", "preflight", "migrate"])
    parser.add_argument("--migrations", type=Path)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    if os.geteuid() != 0 or platform.system() != "Linux" or platform.machine() != "x86_64":
        raise ValueError("native analytics requires Linux amd64 root")
    if args.check and args.action != "migrate":
        raise ValueError("--check applies only to migrate")
    os.umask(0o077)
    if args.action == "migrate":
        native_clickhouse_migrate(args)
        return
    if args.action == "preflight":
        native_clickhouse_installed()
        verify_native_clickhouse(STATE, require_private_admin=True)
    else:
        if args.migrations is None:
            raise ValueError("verified release migrations are required")
        default_config = Path("/etc/clickhouse-server/users.d/cdnca-private-default.xml")
        if default_config.exists() or default_config.is_symlink():
            raise FileExistsError("existing private ClickHouse administrator configuration")
        configure_native_clickhouse(args.migrations, STATE)
        # The application only receives query/ingest credentials. Keep the
        # package's maintenance identity private rather than passwordless.
        password = secrets.token_hex(32)
        native_clickhouse_private_file(STATE / "admin.xml", native_clickhouse_client_config("default", password))
        native_clickhouse_private_file(STATE / "anonymous.xml", "<config><user>default</user><password></password></config>\n")
        digest = hashlib.sha256(password.encode()).hexdigest()
        native_clickhouse_private_file(default_config, "<clickhouse><users><default>"
            "<password remove=\"remove\"/><password_sha256_hex>" + digest + "</password_sha256_hex>"
            "<networks replace=\"replace\"><ip>127.0.0.1</ip></networks>"
            "</default></users></clickhouse>\n")
        os.chown(default_config, 0, grp.getgrnam("clickhouse").gr_gid)
        os.chmod(default_config, 0o640)
        subprocess.run(["systemctl", "restart", "clickhouse-server"], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=90)
        for attempt in range(30):
            try:
                native_clickhouse_command("SELECT 1", config=STATE / "admin.xml")
                break
            except RuntimeError:
                if attempt == 29:
                    raise
                time.sleep(1)
        verify_native_clickhouse(STATE, require_private_admin=True)
        native_clickhouse_private_file(STATE / "installed.json", json.dumps({"schema": "cdnca.native-clickhouse-install/v1", "version": VERSION}) + "\n")
    print(json.dumps({"status": "runtime_preflight_passed", "environment_file": str(STATE / "runtime.env"),
                      "receipt_file": str(STATE / "receipt.json")}))


if __name__ == "__main__":
    try:
        native_clickhouse_main()
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError):
        raise SystemExit("native ClickHouse initialization failed; preserve private state and inspect the server log, do not rerun or reset")
