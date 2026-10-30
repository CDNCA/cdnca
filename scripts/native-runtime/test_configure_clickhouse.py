import importlib.util
from datetime import datetime, timezone
from contextlib import ExitStack
import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch
import uuid


SPEC = importlib.util.spec_from_file_location("native_clickhouse", Path(__file__).with_name("configure-clickhouse.py"))
CH = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CH)
MIGRATIONS = Path(__file__).resolve().parents[2] / "infra/clickhouse/migrations"


class FakeLedgerClickHouse:
    """Executes the ledger protocol in memory and records every other statement."""

    def __init__(self, tables=0):
        self.ledger, self.statements, self.created, self.tables = {}, [], False, tables
        self.fail_on = None

    def __call__(self, sql):
        sql = sql.strip()
        self.statements.append(sql)
        if self.fail_on and self.fail_on in sql:
            raise RuntimeError("ClickHouse command failed (UNKNOWN); inspect the private server log")
        if sql.startswith("EXISTS TABLE " + CH.LEDGER):
            return "1" if self.created else "0"
        if sql.startswith("SELECT count() FROM system.tables"):
            return str(self.tables)
        if sql.startswith("CREATE TABLE IF NOT EXISTS " + CH.LEDGER):
            self.created = True
            return ""
        if sql.startswith("SELECT version, name, checksum, applied FROM " + CH.LEDGER):
            return "\n".join(f"{v}\t{n}\t{c}\t{a}" for v, (n, c, a) in sorted(self.ledger.items()))
        if sql.startswith("INSERT INTO " + CH.LEDGER):
            values = sql.split("VALUES", 1)[1].strip().strip("()").split(",")
            version, name, checksum, applied = [value.strip().strip("'") for value in values[:4]]
            current = self.ledger.get(int(version))
            if current is None or int(applied) >= current[2]:
                self.ledger[int(version)] = (name, checksum, int(applied))
            return ""
        return ""


def write_migrations(directory, count, body=lambda index: f"CREATE TABLE IF NOT EXISTS t{index} (x UInt8) ENGINE = Memory;"):
    directory.mkdir(exist_ok=True)
    for index in range(1, count + 1):
        (directory / f"{index:03}_fixture_{index}.up.sql").write_text(body(index))


class TestNativeClickHouseMigrationLedger(unittest.TestCase):
    def test_inventory_is_not_a_fixed_count(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            write_migrations(directory, 17)
            self.assertEqual(len(CH.native_clickhouse_migrations(directory)), 17)
            (directory / "018_fixture_18.up.sql").write_text("SELECT 1;")
            self.assertEqual(len(CH.native_clickhouse_migrations(directory)), 18)
            (directory / "020_gap.up.sql").write_text("SELECT 1;")
            with self.assertRaises(ValueError):
                CH.native_clickhouse_migrations(directory)
            (directory / "020_gap.up.sql").unlink()
            (directory / "019_fixture.up.sql").symlink_to(directory / "001_fixture_1.up.sql")
            with self.assertRaises(ValueError):
                CH.native_clickhouse_migrations(directory)
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaises(ValueError):
                CH.native_clickhouse_migrations(Path(temporary))

    def test_statements_split_outside_literals_and_comments(self):
        sql = ("-- header; not a statement\nCREATE TABLE a (s String DEFAULT 'x;y') ENGINE = Memory;\n"
               "/* block; comment */ INSERT INTO a VALUES ('it''s;'), ('a\\';b');\n\n"
               "SELECT `odd;name` FROM a; -- trailing\n")
        statements = CH.native_clickhouse_statements(sql)
        self.assertEqual(len(statements), 3)
        self.assertIn("'x;y'", statements[0])
        self.assertIn("'it''s;'", statements[1])
        self.assertIn("`odd;name`", statements[2])
        with self.assertRaises(ValueError):
            CH.native_clickhouse_statements("SELECT 'unterminated;")
        self.assertEqual(CH.native_clickhouse_statements("-- only a comment\n"), [])
        # Every shipped migration splits into non-empty statements.
        for path in CH.native_clickhouse_migrations(MIGRATIONS):
            self.assertTrue(CH.native_clickhouse_statements(path.read_text()), path.name)

    def test_fresh_database_applies_all_in_order_and_records_checksums(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary) / "m"
            write_migrations(directory, 3)
            fake = FakeLedgerClickHouse()
            applied = CH.native_clickhouse_apply_migrations(directory, fake)
            self.assertEqual([item["path"] for item in applied], ["001_fixture_1.up.sql", "002_fixture_2.up.sql", "003_fixture_3.up.sql"])
            self.assertEqual(sorted(fake.ledger), [1, 2, 3])
            self.assertTrue(all(row[2] == 1 for row in fake.ledger.values()))
            for index, path in enumerate(sorted(directory.glob("*.up.sql")), 1):
                self.assertEqual(fake.ledger[index][1], CH.hashlib.sha256(path.read_bytes()).hexdigest())
            ddl = [statement for statement in fake.statements if statement.startswith("CREATE TABLE IF NOT EXISTS t")]
            self.assertEqual(ddl, [f"CREATE TABLE IF NOT EXISTS t{index} (x UInt8) ENGINE = Memory" for index in (1, 2, 3)])
            # The running marker precedes each migration's DDL.
            first = fake.statements.index("CREATE TABLE IF NOT EXISTS t1 (x UInt8) ENGINE = Memory")
            self.assertIn("VALUES (1, '001_fixture_1', ", fake.statements[first - 1])

    def test_upgrade_applies_only_new_migrations_and_is_idempotent(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary) / "m"
            write_migrations(directory, 16)
            fake = FakeLedgerClickHouse()
            CH.native_clickhouse_apply_migrations(directory, fake)
            write_migrations(directory, 18)
            fake.statements.clear()
            result = CH.native_clickhouse_apply_migrations(directory, fake)
            self.assertEqual([item["path"] for item in result if item["applied_now"]], ["017_fixture_17.up.sql", "018_fixture_18.up.sql"])
            self.assertEqual(sorted(fake.ledger), list(range(1, 19)))
            self.assertNotIn("CREATE TABLE IF NOT EXISTS t1 (x UInt8) ENGINE = Memory", fake.statements)
            fake.statements.clear()
            again = CH.native_clickhouse_apply_migrations(directory, fake)
            self.assertFalse(any(item["applied_now"] for item in again))
            self.assertFalse(any(statement.startswith(("INSERT", "CREATE TABLE IF NOT EXISTS t")) for statement in fake.statements))

    def test_changed_applied_migration_is_rejected_before_any_ddl(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary) / "m"
            write_migrations(directory, 16)
            fake = FakeLedgerClickHouse()
            CH.native_clickhouse_apply_migrations(directory, fake)
            (directory / "003_fixture_3.up.sql").write_text("CREATE TABLE IF NOT EXISTS evil (x UInt8) ENGINE = Memory;")
            write_migrations(directory, 17, body=lambda index: "CREATE TABLE IF NOT EXISTS evil (x UInt8) ENGINE = Memory;" if index == 3 else f"CREATE TABLE IF NOT EXISTS t{index} (x UInt8) ENGINE = Memory;")
            fake.statements.clear()
            with self.assertRaisesRegex(CH.NativeClickHouseLedgerError, "checksum_mismatch") as failure:
                CH.native_clickhouse_apply_migrations(directory, fake)
            self.assertEqual(failure.exception.reason, "checksum_mismatch")
            self.assertFalse(any(statement.startswith(("INSERT", "CREATE TABLE IF NOT EXISTS t", "CREATE TABLE IF NOT EXISTS evil")) for statement in fake.statements))
            self.assertNotIn(17, fake.ledger)
            # A tampered ledger digest is the same refusal.
            write_migrations(directory, 17)
            fake.ledger[5] = (fake.ledger[5][0], "0" * 64, 1)
            with self.assertRaisesRegex(CH.NativeClickHouseLedgerError, "checksum_mismatch"):
                CH.native_clickhouse_apply_migrations(directory, fake)
            with self.assertRaisesRegex(CH.NativeClickHouseLedgerError, "checksum_mismatch"):
                CH.native_clickhouse_apply_migrations(directory, fake, check_only=True)

    def test_ledger_ahead_gap_missing_and_unledgered_schema_are_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary) / "m"
            write_migrations(directory, 3)
            fake = FakeLedgerClickHouse()
            CH.native_clickhouse_apply_migrations(directory, fake)
            (directory / "003_fixture_3.up.sql").unlink()
            with self.assertRaisesRegex(CH.NativeClickHouseLedgerError, "ledger_ahead"):
                CH.native_clickhouse_apply_migrations(directory, fake)
            write_migrations(directory, 3)
            del fake.ledger[2]
            with self.assertRaisesRegex(CH.NativeClickHouseLedgerError, "ledger_gap"):
                CH.native_clickhouse_apply_migrations(directory, fake)
            # check-only never creates the ledger.
            empty = FakeLedgerClickHouse()
            with self.assertRaisesRegex(CH.NativeClickHouseLedgerError, "ledger_missing"):
                CH.native_clickhouse_apply_migrations(directory, empty, check_only=True)
            self.assertFalse(empty.created)
            # An existing schema without a ledger is never re-migrated from 001.
            legacy = FakeLedgerClickHouse(tables=12)
            with self.assertRaisesRegex(CH.NativeClickHouseLedgerError, "unledgered_schema"):
                CH.native_clickhouse_apply_migrations(directory, legacy)
            self.assertFalse(legacy.created)

    def test_interrupted_migration_is_retried_and_check_only_reports_pending(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary) / "m"
            write_migrations(directory, 16)
            fake = FakeLedgerClickHouse()
            CH.native_clickhouse_apply_migrations(directory, fake)
            write_migrations(directory, 18)
            pending = CH.native_clickhouse_apply_migrations(directory, fake, check_only=True)
            self.assertEqual([item["path"] for item in pending if item["pending"]], ["017_fixture_17.up.sql", "018_fixture_18.up.sql"])
            self.assertNotIn(17, fake.ledger)
            fake.fail_on = "CREATE TABLE IF NOT EXISTS t17"
            with self.assertRaises(RuntimeError):
                CH.native_clickhouse_apply_migrations(directory, fake)
            self.assertEqual(fake.ledger[17][2], 0)
            self.assertNotIn(18, fake.ledger)
            fake.fail_on = None
            result = CH.native_clickhouse_apply_migrations(directory, fake)
            self.assertEqual([item["path"] for item in result if item["applied_now"]], ["017_fixture_17.up.sql", "018_fixture_18.up.sql"])
            self.assertEqual(fake.ledger[17][2], 1)
            # An interrupted migration whose file then changed is not silently re-run.
            write_migrations(directory, 19)
            fake.ledger[19] = ("019_fixture_19", "1" * 64, 0)
            with self.assertRaisesRegex(CH.NativeClickHouseLedgerError, "checksum_mismatch"):
                CH.native_clickhouse_apply_migrations(directory, fake)

    def test_http_executor_keeps_credentials_out_of_url_and_errors(self):
        class Response:
            def __init__(self, body):
                self.body = body
            def read(self, limit=-1):
                return self.body
            def __enter__(self):
                return self
            def __exit__(self, *args):
                return False
        requests = []
        class Opener:
            def open(self, request, timeout):
                requests.append((request, timeout))
                if b"boom" in request.data:
                    raise CH.urllib.error.HTTPError(request.full_url, 500, "x", {}, CH.io.BytesIO(
                        b"Code: 57. DB::Exception: secret-password leaked (TABLE_ALREADY_EXISTS)"))
                return Response(b"1\n")
        with patch.object(CH.urllib.request, "build_opener", return_value=Opener()) as build:
            self.assertEqual(CH.native_clickhouse_http("SELECT 1", database="cdnca_analytics", user="default",
                                                        password="secret-password", timeout=7), "1")
            handler = build.call_args[0][0]
            self.assertIsInstance(handler, CH.urllib.request.ProxyHandler)
            self.assertEqual(handler.proxies, {})
            request, timeout = requests[0]
            # The server enforces 7s; the socket waits longer so the server's own error arrives.
            self.assertIn("max_execution_time=7", request.full_url)
            self.assertGreater(timeout, 7)
            self.assertTrue(request.full_url.startswith("http://127.0.0.1:8123/?"))
            self.assertIn("database=cdnca_analytics", request.full_url)
            self.assertNotIn("secret-password", request.full_url)
            self.assertEqual(request.get_header("X-clickhouse-key"), "secret-password")
            self.assertEqual(request.data, b"SELECT 1")
            with self.assertRaisesRegex(RuntimeError, r"\(TABLE_ALREADY_EXISTS\)") as failure:
                CH.native_clickhouse_http("boom", database="cdnca_analytics", user="default", password="secret-password")
            self.assertNotIn("secret-password", str(failure.exception))

    def test_upgrade_uses_private_admin_and_reapplies_grants(self):
        with tempfile.TemporaryDirectory() as temporary:
            state, directory = Path(temporary) / "state", Path(temporary) / "m"
            state.mkdir(mode=0o700)
            CH.native_clickhouse_private_file(state / "credentials.json", json.dumps({"database": "cdnca_analytics"}) + "\n")
            CH.native_clickhouse_private_file(state / "admin.xml", CH.native_clickhouse_client_config("default", "a" * 64))
            write_migrations(directory, 2)
            fake, calls = FakeLedgerClickHouse(), []
            def http(sql, **kwargs):
                calls.append(kwargs)
                return "25.3.6.56" if sql == "SELECT version()" else fake(sql)
            with patch.object(CH, "native_clickhouse_http", side_effect=http):
                result = CH.upgrade_native_clickhouse(directory, state)
            self.assertEqual(result["applied"], ["001_fixture_1.up.sql", "002_fixture_2.up.sql"])
            self.assertTrue(all(call["user"] == "default" and call["password"] == "a" * 64 for call in calls))
            self.assertTrue(all(call["database"] == "cdnca_analytics" for call in calls))
            sql = "\n".join(fake.statements)
            self.assertIn("GRANT INSERT ON cdnca_analytics.l4_session_facts_v1 TO cdnca_analytics_ingest", sql)
            self.assertIn("MODIFY SQL SECURITY DEFINER DEFINER = cdnca_analytics_rollup", sql)
            self.assertNotIn("CREATE USER", sql)
            fake.statements.clear()
            with patch.object(CH, "native_clickhouse_http", side_effect=http):
                checked = CH.upgrade_native_clickhouse(directory, state, check_only=True)
            self.assertEqual(checked["pending"], [])
            self.assertFalse(any(statement.startswith(("GRANT", "ALTER", "INSERT", "CREATE")) for statement in fake.statements))
            with patch.object(CH, "native_clickhouse_http", return_value="24.1"):
                with self.assertRaisesRegex(ValueError, "version"):
                    CH.upgrade_native_clickhouse(directory, state)
            os.chmod(state / "admin.xml", 0o644)
            with self.assertRaises(ValueError):
                CH.upgrade_native_clickhouse(directory, state)

    def test_failure_line_names_only_a_stable_reason(self):
        self.assertEqual(CH.native_clickhouse_failure_reason(CH.NativeClickHouseLedgerError("checksum_mismatch", "003")), "checksum_mismatch")
        self.assertEqual(CH.native_clickhouse_failure_reason(RuntimeError("ClickHouse command failed (UNKNOWN)")), "clickhouse_error")
        self.assertEqual(CH.native_clickhouse_failure_reason(ValueError("bad")), "invalid_input")


class TestNativeClickHouseConfiguration(unittest.TestCase):
    def test_migrations_are_complete_and_regular(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            for index in range(1, 17):
                (directory / f"{index:03}_fixture.up.sql").write_text("SELECT 1;")
            self.assertEqual(len(CH.native_clickhouse_migrations(directory)), 16)
            (directory / "016_fixture.up.sql").unlink()
            self.assertEqual(len(CH.native_clickhouse_migrations(directory)), 15)
            (directory / "016_fixture.up.sql").symlink_to(directory / "001_fixture.up.sql")
            with self.assertRaises(ValueError):
                CH.native_clickhouse_migrations(directory)

    def test_private_files_are_exclusive_and_not_followed(self):
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / "private"
            CH.native_clickhouse_private_file(target, "original")
            self.assertEqual(target.stat().st_mode & 0o777, 0o600)
            with self.assertRaises(FileExistsError):
                CH.native_clickhouse_private_file(target, "replacement")
            self.assertEqual(target.read_text(), "original")
            link = Path(temporary) / "link"
            link.symlink_to(target)
            with self.assertRaises(FileExistsError):
                CH.native_clickhouse_private_file(link, "replacement")

    def test_identifier_is_not_sql(self):
        for value in ["a;DROP TABLE access_events", "", "default", "x.y", "x'", "a" * 64]:
            with self.assertRaises(ValueError):
                CH.native_clickhouse_identifier(value)
        self.assertEqual(CH.native_clickhouse_identifier("cdnca_analytics"), "cdnca_analytics")

    def test_credentials_never_enter_arguments_and_errors_are_redacted(self):
        with patch.object(CH.subprocess, "run") as run:
            run.return_value.returncode = 1
            run.return_value.stderr = "private SQL and password must not escape"
            run.return_value.stdout = "private response"
            with self.assertRaisesRegex(RuntimeError, "ClickHouse command failed") as failure:
                CH.native_clickhouse_command("sensitive SQL", config=Path("/private/client.xml"))
            self.assertNotIn("sensitive", str(failure.exception))
            self.assertNotIn("sensitive SQL", repr(run.call_args[0]))
            self.assertEqual(run.call_args[1]["input"], "sensitive SQL")
            self.assertNotIn("--password", run.call_args[0][0])
            with self.assertRaises(RuntimeError):
                CH.native_clickhouse_command("bad query", config=Path("/private/client.xml"), denied=True)
            run.return_value.stderr = "Code: 497. ACCESS_DENIED"
            CH.native_clickhouse_command("forbidden query", config=Path("/private/client.xml"), denied=True)
            with self.assertRaises(RuntimeError):
                CH.native_clickhouse_command("SELECT 1", authentication_denied=True)
            run.return_value.stderr = "Code: 516. AUTHENTICATION_FAILED"
            CH.native_clickhouse_command("SELECT 1", authentication_denied=True)
            run.return_value.stderr = "NETWORK_ERROR"
            with self.assertRaises(RuntimeError):
                CH.native_clickhouse_command("SELECT 1", authentication_denied=True)

    def test_existing_state_and_version_drift_are_not_overwritten(self):
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary) / "state"
            state.mkdir()
            with patch.object(CH, "native_clickhouse_command") as command:
                with self.assertRaises(FileExistsError):
                    CH.configure_native_clickhouse(MIGRATIONS, state)
                command.assert_not_called()
            state.rmdir()
            with patch.object(CH, "native_clickhouse_command", return_value="24.1") as command:
                with self.assertRaisesRegex(ValueError, "version"):
                    CH.configure_native_clickhouse(MIGRATIONS, state)
                self.assertFalse(state.exists())
                self.assertEqual(command.call_count, 1)

    def test_every_migration_materialized_view_runs_as_rollup_definer(self):
        # An MV left out of ROLLUPS keeps INVOKER security, so the ingest identity
        # (INSERT only) is refused on its source table: the ge-waf 022
        # security_event_evidence_mv_v1 broke fresh install at verify (install-smoke S3).
        import re
        views = set()
        for path in CH.native_clickhouse_migrations(MIGRATIONS):
            views |= set(re.findall(r"CREATE MATERIALIZED VIEW IF NOT EXISTS ([a-z0-9_]+)", path.read_text()))
        self.assertTrue(views)
        self.assertEqual(sorted(views - set(CH.ROLLUPS)), [])

    def test_event_state_tables_follow_cleanup_retention(self):
        # Per-event state the log pages read (expires on occurred_at like its
        # source events) must follow the cleanup settings, not a fixed 90 days:
        # 022 evidence and 025 count were left out.
        import re
        text = "\n".join(path.read_text() for path in CH.native_clickhouse_migrations(MIGRATIONS))
        tables = set()
        for table, body in re.findall(r"CREATE TABLE IF NOT EXISTS ((?:access|security)_event_[a-z0-9_]+_state_v1)\s*\((.*?)SETTINGS", text, re.S):
            if table in CH.ROLLUPS.values() and re.search(r"TTL toDateTime\(occurred_at, 'UTC'\)", body):
                tables.add(table)
        self.assertIn("security_event_latest_state_v1", tables)
        self.assertEqual(sorted(tables - set(CH.RETENTION_TTL_TABLES)), [])

    def test_query_and_ingest_grants_are_separate(self):
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary) / "state"
            ledger = FakeLedgerClickHouse()
            with patch.object(CH, "native_clickhouse_command") as command, patch.object(CH, "verify_native_clickhouse"):
                command.side_effect = lambda sql, **kwargs: "25.3.6.56" if sql == "SELECT version()" else (
                    ledger(sql) if CH.LEDGER in sql or sql.startswith("SELECT count() FROM system.tables") else "0")
                CH.configure_native_clickhouse(MIGRATIONS, state)
            self.assertEqual(sorted(ledger.ledger), list(range(1, len(CH.native_clickhouse_migrations(MIGRATIONS)) + 1)))
            sql = "\n".join(call[0][0] for call in command.call_args_list)
            self.assertIn("GRANT SELECT ON cdnca_analytics.* TO cdnca_analytics_query", sql)
            self.assertIn("GRANT INSERT ON cdnca_analytics.access_events", sql)
            self.assertIn("GRANT INSERT ON cdnca_analytics.security_events", sql)
            self.assertIn("GRANT INSERT ON cdnca_analytics.connections_ingest_receipts_v1 TO cdnca_analytics_ingest", sql)
            self.assertIn("GRANT SELECT ON cdnca_analytics.connections_ingest_receipts_v1 TO cdnca_analytics_ingest", sql)
            self.assertIn("GRANT INSERT ON cdnca_analytics.l4_session_facts_v1 TO cdnca_analytics_ingest", sql)
            self.assertNotIn("GRANT SELECT ON cdnca_analytics.l4_session_facts_v1 TO cdnca_analytics_ingest", sql)
            # Smart auto defense (AD-08): write only.
            self.assertIn("GRANT INSERT ON cdnca_analytics.autodefense_verdicts_v1 TO cdnca_analytics_ingest", sql)
            self.assertIn("GRANT INSERT ON cdnca_analytics.market_security_events_v1 TO cdnca_analytics_ingest", sql)
            self.assertIn("GRANT INSERT ON cdnca_analytics.node_security_events_v1 TO cdnca_analytics_ingest", sql)
            self.assertNotIn("GRANT SELECT ON cdnca_analytics.autodefense_verdicts_v1 TO cdnca_analytics_ingest", sql)
            self.assertNotIn("GRANT SELECT ON cdnca_analytics.* TO cdnca_analytics_ingest", sql)
            self.assertNotIn("GRANT ALL", sql)
            self.assertNotIn("GRANT INSERT ON cdnca_analytics.*", sql)
            # FX01: TTL-only, table-scoped; never a schema-wide ALTER.
            self.assertEqual(sql.count("GRANT ALTER MODIFY TTL ON cdnca_analytics."), len(CH.RETENTION_TTL_TABLES))
            self.assertIn("GRANT ALTER MODIFY TTL ON cdnca_analytics.access_events TO cdnca_analytics_ingest", sql)
            self.assertNotIn("GRANT ALTER MODIFY TTL ON cdnca_analytics.package_metric_access_facts_v1", sql)
            self.assertNotIn("GRANT ALTER ON", sql)
            self.assertNotIn("GRANT ALTER TABLE", sql)
            self.assertIn("CREATE USER cdnca_analytics_rollup NOT IDENTIFIED HOST NONE", sql)
            self.assertEqual(sql.count("MODIFY SQL SECURITY DEFINER DEFINER = cdnca_analytics_rollup"), len(CH.ROLLUPS))
            credentials = json.loads((state / "credentials.json").read_text())
            self.assertNotEqual(credentials["query_password"], credentials["ingest_password"])
            for secret in [credentials["query_password"], credentials["ingest_password"]]:
                self.assertNotIn(secret, sql)
                self.assertNotIn(secret, repr(command.call_args_list))
            self.assertEqual((state / "runtime.env").stat().st_mode & 0o777, 0o600)
            self.assertEqual(len(json.loads((state / "receipt.json").read_text())["migrations"]), len(CH.native_clickhouse_migrations(MIGRATIONS)))
            with self.assertRaises(FileNotFoundError):
                CH.verify_native_clickhouse(state, require_private_admin=True)

    @unittest.skipUnless(os.getenv("NATIVE_CLICKHOUSE_INTEGRATION") == "1", "real isolated ClickHouse is opt-in")
    def test_real_materialized_views_and_least_privilege(self):
        database = "cdnca_ch_acceptance_" + uuid.uuid4().hex[:12]
        with tempfile.TemporaryDirectory(prefix="cdnca-ch-rbac-") as temporary, ExitStack() as resources:
            state = Path(temporary) / "state"
            admin = os.environ.get("NATIVE_CLICKHOUSE_TEST_ADMIN_CONFIG")
            if admin:
                command = CH.native_clickhouse_command
                resources.enter_context(patch.object(CH, "native_clickhouse_command", side_effect=
                    lambda sql, **kwargs: command(sql, **{**kwargs, "config": kwargs.get("config") or Path(admin)})))
            # The UUID namespace was checked absent before credentials are
            # written. Clean up only this test's exact owned database/users.
            def cleanup():
                if (state / "credentials.json").exists():
                    CH.native_clickhouse_command(f"DROP DATABASE IF EXISTS {database} SYNC; DROP USER IF EXISTS {database}_query; DROP USER IF EXISTS {database}_ingest; DROP USER IF EXISTS {database}_rollup")
            resources.callback(cleanup)
            CH.configure_native_clickhouse(MIGRATIONS, state, database=database)
            event = {
                "metric_version": 1, "event_id": "native-permission-probe", "occurred_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S.000"),
                "tenant_id": str(uuid.uuid4()), "site_id": str(uuid.uuid4()), "node_id": str(uuid.uuid4()),
                "package_subscription_id": str(uuid.uuid4()),
                "host": "acceptance.invalid", "path": "/", "client_ip": "::1", "method": "GET", "protocol": "HTTP/1.1",
                "cache_status": "miss", "status_code": 200, "request_bytes": 1, "response_bytes": 2, "duration_us": 3,
            }
            # This database is test-owned. These synthetic rows never enter the installation database.
            CH.native_clickhouse_command("INSERT INTO access_events FORMAT JSONEachRow\n" + json.dumps(event),
                                         config=state / "ingest.xml", database=database)
            security = {key: event[key] for key in ["metric_version", "event_id", "occurred_at", "tenant_id", "site_id", "node_id", "package_subscription_id", "host", "path", "client_ip", "status_code", "request_bytes", "response_bytes"]}
            security.update(event_type="waf", action="block", severity="low")
            CH.native_clickhouse_command("INSERT INTO security_events FORMAT JSONEachRow\n" + json.dumps(security),
                                         config=state / "ingest.xml", database=database)
            for table in ["access_events", "security_events", *CH.ROLLUPS.values()]:
                self.assertEqual(CH.native_clickhouse_command(f"SELECT count() FROM {table}", config=state / "query.xml", database=database), "1", table)
            connection = {
                "schema_version": 1, "receipt_id": "native-connection-probe", "batch_id": "batch-1", "event_id": "connection-1",
                "tenant_id": event["tenant_id"], "site_id": event["site_id"], "package_subscription_id": event["package_subscription_id"],
                "node_id": event["node_id"], "domain": "acceptance.invalid", "listen_port": 443,
                "installation_id": str(uuid.uuid4()), "occurred_at": event["occurred_at"], "connections": 1,
                "payload_sha256": "a" * 64, "canonical_event_sha256": "b" * 64, "evidence_sha256": "c" * 64,
                "source_watermark": 1, "finalized_through": event["occurred_at"], "nats_stream": "CONNECTIONS_INGEST_V1",
                "nats_durable": "probe", "nats_stream_sequence": 1, "nats_consumer_sequence": 1,
                "puback_stream": "CONNECTIONS_INGEST_V1", "puback_sequence": 1, "puback_duplicate": 0,
                "clickhouse_insert_token": "d" * 64, "state": "ch_prepared", "state_rank": 2,
            }
            CH.native_clickhouse_command("INSERT INTO connections_ingest_receipts_v1 FORMAT JSONEachRow\n" + json.dumps(connection),
                                         config=state / "ingest.xml", database=database)
            self.assertEqual(CH.native_clickhouse_command("SELECT count() FROM connections_ingest_receipts_v1",
                                                         config=state / "ingest.xml", database=database), "1")
            l4 = {"tenant_id": event["tenant_id"], "node_id": event["node_id"], "site_id": event["site_id"],
                  "stream_id": str(uuid.uuid4()), "listener_id": str(uuid.uuid4()), "session_id": "probe-session",
                  "started_at": event["occurred_at"], "finalized_at": event["occurred_at"], "bytes_up": 1, "bytes_down": 2,
                  "status_code": 200, "error_code": "", "config_version_id": str(uuid.uuid4()), "config_revision": 1,
                  "protocol": "tcp", "listen_port": 443, "event_id": "l4-probe", "traceparent": "", "task_id": "",
                  "source_watermark": 1, "evidence_sha256": "e" * 64, "canonical_event_sha256": "f" * 64}
            CH.native_clickhouse_command("INSERT INTO l4_session_facts_v1 FORMAT JSONEachRow\n" + json.dumps(l4),
                                         config=state / "ingest.xml", database=database)
            for table in ["connections_ingest_receipts_v1", "l4_session_facts_v1"]:
                self.assertEqual(CH.native_clickhouse_command(f"SELECT count() FROM {table}", config=state / "query.xml", database=database), "1", table)
            CH.native_clickhouse_command("INSERT INTO access_version_evidence_v1 SELECT * FROM access_version_evidence_v1 LIMIT 0",
                                         config=state / "ingest.xml", database=database, denied=True)
            CH.verify_native_clickhouse(state)

    @unittest.skipUnless(os.getenv("NATIVE_CLICKHOUSE_INTEGRATION") == "1" and os.getenv("NATIVE_CLICKHOUSE_TEST_ADMIN_CONFIG"),
                         "real isolated ClickHouse with a private admin is opt-in")
    def test_real_upgrade_from_sixteen_applied_migrations(self):
        database = "cdnca_ch_acceptance_" + uuid.uuid4().hex[:12]
        admin = Path(os.environ["NATIVE_CLICKHOUSE_TEST_ADMIN_CONFIG"])
        with tempfile.TemporaryDirectory(prefix="cdnca-ch-upgrade-") as temporary, ExitStack() as resources:
            state, migrations = Path(temporary) / "state", Path(temporary) / "migrations"
            command = CH.native_clickhouse_command
            resources.enter_context(patch.object(CH, "native_clickhouse_command", side_effect=
                lambda sql, **kwargs: command(sql, **{**kwargs, "config": kwargs.get("config") or admin})))
            resources.enter_context(patch.object(CH, "HTTP_URL", os.environ.get("NATIVE_CLICKHOUSE_TEST_HTTP_URL", CH.HTTP_URL)))
            def cleanup():
                if (state / "credentials.json").exists():
                    CH.native_clickhouse_command(f"DROP DATABASE IF EXISTS {database} SYNC; DROP USER IF EXISTS {database}_query; DROP USER IF EXISTS {database}_ingest; DROP USER IF EXISTS {database}_rollup")
            resources.callback(cleanup)
            ledger = lambda sql: CH.native_clickhouse_command(sql, database=database)
            migrations.mkdir()
            baseline = CH.native_clickhouse_migrations(MIGRATIONS)[:16]
            for path in baseline:
                shutil.copyfile(path, migrations / path.name)
            # The 1.0.35 baseline: an installation with exactly the 16 shipped migrations.
            CH.configure_native_clickhouse(migrations, state, database=database)
            CH.native_clickhouse_private_file(state / "admin.xml", admin.read_text())
            self.assertEqual(ledger(f"SELECT count(), max(version), min(applied) FROM {CH.LEDGER} FINAL"), "16\t16\t1")
            recorded = ledger(f"SELECT checksum FROM {CH.LEDGER} FINAL WHERE version = 3")
            self.assertEqual(recorded, CH.hashlib.sha256(baseline[2].read_bytes()).hexdigest())
            # A later release appends 017 (and the real 017+ of this tree, if any).
            for path in CH.native_clickhouse_migrations(MIGRATIONS)[16:]:
                shutil.copyfile(path, migrations / path.name)
            probe = f"{len(CH.native_clickhouse_migrations(migrations)) + 1:03}_chupgrade_probe.up.sql"
            (migrations / probe).write_text(
                "-- upgrade probe; idempotent by construction\n"
                "CREATE TABLE IF NOT EXISTS chupgrade_probe_v1 (id UInt64, note String DEFAULT 'a;b') ENGINE = MergeTree ORDER BY id;\n"
                "ALTER TABLE chupgrade_probe_v1 ADD COLUMN IF NOT EXISTS extra UInt8 DEFAULT 0;\n")
            total = len(CH.native_clickhouse_migrations(migrations))
            checked = CH.upgrade_native_clickhouse(migrations, state, check_only=True)
            self.assertEqual(checked["pending"][-1], probe)
            self.assertEqual(ledger(f"SELECT count() FROM {CH.LEDGER} FINAL"), "16")
            result = CH.upgrade_native_clickhouse(migrations, state)
            self.assertEqual(result["applied"][-1], probe)
            self.assertEqual(len(result["applied"]), total - 16)
            self.assertEqual(ledger(f"SELECT count(), max(version), min(applied) FROM {CH.LEDGER} FINAL"), f"{total}\t{total}\t1")
            self.assertEqual(CH.native_clickhouse_command("SELECT count() FROM chupgrade_probe_v1 WHERE extra = 0",
                                                         database=database, config=state / "query.xml"), "0")
            CH.verify_native_clickhouse(state)
            # Re-running the same release is a no-op: no ledger row is written.
            rows = ledger(f"SELECT count() FROM {CH.LEDGER}")
            self.assertEqual(CH.upgrade_native_clickhouse(migrations, state)["applied"], [])
            self.assertEqual(ledger(f"SELECT count() FROM {CH.LEDGER}"), rows)
            # A changed, already applied migration is refused before any DDL.
            original = (migrations / baseline[2].name).read_bytes()
            (migrations / baseline[2].name).write_bytes(original + b"\nCREATE TABLE IF NOT EXISTS chupgrade_evil (x UInt8) ENGINE = Memory;\n")
            for check_only in (True, False):
                with self.assertRaisesRegex(CH.NativeClickHouseLedgerError, "checksum_mismatch"):
                    CH.upgrade_native_clickhouse(migrations, state, check_only=check_only)
            self.assertEqual(ledger("EXISTS TABLE chupgrade_evil"), "0")
            (migrations / baseline[2].name).write_bytes(original)
            # So is a tampered ledger digest.
            ledger(f"INSERT INTO {CH.LEDGER} (version, name, checksum, applied) VALUES (5, '{baseline[4].name[:-7]}', '{'0' * 64}', 1)")
            with self.assertRaisesRegex(CH.NativeClickHouseLedgerError, "checksum_mismatch"):
                CH.upgrade_native_clickhouse(migrations, state)


class TestNativeClickHousePortProfile(unittest.TestCase):
    """fix-btenv: install-control.sh may move ClickHouse off 8123/9000 on a BaoTa host."""

    def test_absent_profile_keeps_defaults(self):
        with tempfile.TemporaryDirectory() as directory:
            ports = CH.native_clickhouse_ports(Path(directory) / "runtime.env")
            self.assertEqual(ports, {"http": 8123, "tcp": 9000})
            self.assertEqual(CH.native_clickhouse_loopback_content(ports), CH.LOOPBACK_DEFAULT)

    def test_profile_moves_http_and_native_ports(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "runtime.env"
            path.write_text("ENV=bt\nPG_PORT=15432\nCH_HTTP_PORT=18123\nCH_TCP_PORT=19100\n")
            ports = CH.native_clickhouse_ports(path)
            self.assertEqual(ports, {"http": 18123, "tcp": 19100})
            self.assertTrue(CH.native_clickhouse_loopback_content(ports).endswith(
                b"    <http_port>18123</http_port>\n    <tcp_port>19100</tcp_port>\n</clickhouse>\n"))
            command = []
            with patch.object(CH, "PORTS", ports), patch.object(CH.subprocess, "run",
                    side_effect=lambda argv, **_: command.extend(argv) or CH.subprocess.CompletedProcess(argv, 0, "", "")):
                CH.native_clickhouse_command("SELECT 1")
            self.assertEqual(command[command.index("--port") + 1], "19100")
            self.assertEqual(CH.native_clickhouse_http_url(ports), "http://127.0.0.1:18123")

    def test_malformed_profile_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "runtime.env"
            for bad in ("CH_HTTP_PORT=80\n", "CH_HTTP_PORT=$(id)\n", "CH_HTTP_PORT=18123\nCH_HTTP_PORT=18124\n", "export CH_TCP_PORT=1\n"):
                path.write_text(bad)
                with self.assertRaises(ValueError, msg=bad):
                    CH.native_clickhouse_ports(path)


if __name__ == "__main__":
    unittest.main()
