import importlib.util
import io
import os
from pathlib import Path
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location("migrate", Path(__file__).with_name("cdnca-clickhouse-migrate.py"))
M = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(M)
MIGRATIONS = Path(__file__).resolve().parents[2] / "infra/clickhouse/migrations"


class ClusterStatement(unittest.TestCase):
    def test_every_shipped_statement_is_cluster_safe(self):
        for path in sorted(MIGRATIONS.glob("*.up.sql")):
            for sql in M.CH.native_clickhouse_statements(path.read_text()):
                rewritten = M.cluster_statement(sql, "c1")
                if not sql.upper().startswith("INSERT"):
                    self.assertIn(" ON CLUSTER c1", rewritten, path.name)
                self.assertNotRegex(rewritten, r"ENGINE\s*=\s*(Replacing|Aggregating)?MergeTree", path.name)

    def test_rewrites(self):
        self.assertEqual(M.cluster_statement("ALTER TABLE t ADD COLUMN x UInt8", "c"), "ALTER TABLE t ON CLUSTER c ADD COLUMN x UInt8")
        self.assertEqual(M.cluster_statement("DROP VIEW IF EXISTS v", "c"), "DROP VIEW IF EXISTS v ON CLUSTER c")
        self.assertEqual(M.cluster_statement("CREATE TABLE IF NOT EXISTS t (x UInt8) ENGINE = ReplacingMergeTree(x) ORDER BY x", "c"),
                         "CREATE TABLE IF NOT EXISTS t ON CLUSTER c (x UInt8) ENGINE = ReplicatedReplacingMergeTree("
                         "'/clickhouse/tables/{shard}/{database}/{table}', '{replica}', x) ORDER BY x")
        self.assertIn("ReplicatedAggregatingMergeTree('/clickhouse/tables/{shard}/{database}/{table}', '{replica}')",
                      M.cluster_statement("CREATE TABLE t (x UInt8) ENGINE = AggregatingMergeTree ORDER BY x", "c"))
        ledger = M.cluster_statement("CREATE TABLE IF NOT EXISTS schema_migrations (v UInt8) ENGINE = ReplacingMergeTree(v) ORDER BY v", "c")
        self.assertIn("'/clickhouse/tables/cdnca_ledger/{database}/{table}', '{shard}-{replica}', v", ledger)
        self.assertEqual(M.cluster_statement("GRANT SELECT ON d.t TO u", "c"), "GRANT ON CLUSTER c SELECT ON d.t TO u")
        self.assertIn(" ON CLUSTER c ", M.cluster_statement("ALTER TABLE d.v MODIFY SQL SECURITY DEFINER DEFINER = r", "c"))

    def test_refuses_unknown_statement(self):
        for sql in ["OPTIMIZE TABLE t FINAL", "RENAME TABLE a TO b", "SYSTEM RELOAD DICTIONARIES"]:
            with self.assertRaises(M.MigrateError):
                M.cluster_statement(sql, "c")


class Recorder:
    def __init__(self, host="h0"):
        self.host, self.calls = host, []

    def at(self, host):
        other = Recorder(host)
        other.calls = self.calls
        return other

    def __call__(self, sql, database=None):
        self.calls.append((self.host, sql))
        if "system.clusters" in sql:
            return "1\tch1\n2\tch2"
        return ""


class ExecutorRouting(unittest.TestCase):
    def test_backfill_runs_once_per_shard_and_ledger_once(self):
        recorder = Recorder()
        execute = M.Executor(recorder, "c")
        execute("INSERT INTO facts SELECT * FROM events")
        execute("INSERT INTO schema_migrations (version) VALUES (1)")
        execute("CREATE TABLE IF NOT EXISTS t (x UInt8) ENGINE = MergeTree ORDER BY x")
        writes = [(host, sql) for host, sql in recorder.calls if "system.clusters" not in sql]
        self.assertEqual([host for host, _ in writes], ["ch1", "ch2", "h0", "h0"])
        self.assertIn("ON CLUSTER c", writes[3][1])

    def test_single_node_passes_statements_through(self):
        recorder = Recorder()
        M.Executor(recorder)("INSERT INTO facts SELECT 1")
        self.assertEqual(recorder.calls, [("h0", "INSERT INTO facts SELECT 1")])


class OfflineDryRun(unittest.TestCase):
    def run_offline(self, **extra):
        env = {"CLICKHOUSE_MIGRATE_DATABASE": "cdnca_analytics", "CLICKHOUSE_MIGRATE_MIGRATIONS": str(MIGRATIONS), **extra}
        out = io.StringIO()
        with patch.dict(os.environ, env, clear=True):
            M.run("dry-run", out)
        return out.getvalue()

    def test_prints_every_migration_and_ledger_rows(self):
        text = self.run_offline()
        count = len(list(MIGRATIONS.glob("*.up.sql")))
        self.assertEqual(text.count("INSERT INTO schema_migrations"), 2 * count)
        self.assertIn("CREATE DATABASE IF NOT EXISTS cdnca_analytics;", text)

    def test_cluster_and_grants(self):
        text = self.run_offline(CLICKHOUSE_MIGRATE_CLUSTER="c1", CLICKHOUSE_MIGRATE_GRANT_QUERY_USER="q",
                                CLICKHOUSE_MIGRATE_GRANT_INGEST_USER="i", CLICKHOUSE_MIGRATE_GRANT_ROLLUP_USER="r")
        self.assertIn("CREATE DATABASE IF NOT EXISTS cdnca_analytics ON CLUSTER c1;", text)
        self.assertIn("GRANT ON CLUSTER c1 SELECT ON cdnca_analytics.* TO q;", text)
        self.assertIn("DEFINER = r;", text)
        self.assertNotIn("cdnca_analytics_query", text)

    def test_rejects_bad_identifiers_and_partial_grants(self):
        for extra in [{"CLICKHOUSE_MIGRATE_CLUSTER": "c;DROP"}, {"CLICKHOUSE_MIGRATE_GRANT_QUERY_USER": "q"}]:
            with self.assertRaises(M.MigrateError):
                self.run_offline(**extra)

    def test_url_with_credentials_is_refused(self):
        with self.assertRaises(M.MigrateError):
            M.Connection("http://u:p@h:8123", "u", "p", "d")


if __name__ == "__main__":
    unittest.main()
