"""Static parity between infra/clickhouse/migrations (single node) and replicated/ (ON CLUSTER).

  python3 -B -m unittest infra/clickhouse/replicated/test_replicated_parity.py

Three independent checks:
  1. the committed mirror equals generate.py output (nobody hand-edits it, nobody forgets to regenerate);
  2. statement by statement, undoing ON CLUSTER and the Replicated engine gives back the single-node text;
  3. replaying both chains through a small DDL model gives the same final tables (columns and types,
     ORDER BY, PARTITION BY, TTL, engine family and version column) and the same views/MVs (target and
     SELECT), with every MergeTree replicated under a per-database, per-table Keeper path.
CDNCA_REPLICATED_DIR points the test at another directory (used to show the old hand-written files fail).
"""
import importlib.util
import os
from pathlib import Path
import re
import unittest

HERE = Path(__file__).resolve().parent
REPLICATED = Path(os.environ.get("CDNCA_REPLICATED_DIR", HERE))
SINGLE = HERE.parent / "migrations"
CLUSTER = "cdnca_analytics"


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


GENERATE = _load("replicated_generate", HERE / "generate.py")
split = GENERATE.load_migrator().CH.native_clickhouse_statements

REPLICATED_ENGINE = re.compile(
    r"Replicated(\w*)MergeTree\(\s*'/clickhouse/tables/\{shard\}/\{database\}/\{table\}'\s*,\s*'\{replica\}'\s*(?:,\s*([^()]*))?\)")
SINGLE_ENGINE = re.compile(r"\b(\w*)MergeTree\b(?:\s*\(([^()]*)\))?")


def norm(sql):
    return " ".join(sql.split())


def unreplicate(sql):
    """Undo the cluster rewrite: drop ON CLUSTER and the Replicated engine prefix and Keeper arguments."""
    sql = sql.replace(f" ON CLUSTER {CLUSTER}", "", 1)
    return REPLICATED_ENGINE.sub(lambda m: f"{m[1]}MergeTree" + (f"({m[2].strip()})" if m[2] else ""), sql)


def canonical_engine(sql):
    return SINGLE_ENGINE.sub(lambda m: f"{m[1]}MergeTree" + (f"({m[2].strip()})" if m[2] and m[2].strip() else ""), sql)


def top_level_split(text, sep=","):
    parts, depth, quote, current = [], 0, None, []
    for char in text:
        if quote:
            quote = None if char == quote else quote
        elif char in "'\"`":
            quote = char
        elif char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
        elif char == sep and depth == 0:
            parts.append("".join(current).strip())
            current = []
            continue
        current.append(char)
    parts.append("".join(current).strip())
    return [part for part in parts if part]


def matching_paren(text, start):
    depth = 0
    for index in range(start, len(text)):
        depth += {"(": 1, ")": -1}.get(text[index], 0)
        if depth == 0:
            return index
    raise ValueError("unbalanced parentheses")


COLUMN_TYPE_END = re.compile(r"\s+(?:DEFAULT|MATERIALIZED|ALIAS|EPHEMERAL|CODEC|COMMENT|TTL|AFTER|FIRST)\b|$", re.I)
CLAUSE = re.compile(r"\b(ENGINE\s*=|(?:PARTITION BY|ORDER BY|PRIMARY KEY|TTL|SETTINGS)\b)", re.I)


def column(definition):
    """(name, type) of one column definition or ADD COLUMN body."""
    name, rest = definition.split(None, 1)
    return name, norm(rest[:COLUMN_TYPE_END.search(rest).start()])


class Schema:
    """Final schema after a chain of migrations, for the DDL subset the migrations use."""

    def __init__(self):
        self.tables, self.views = {}, {}

    def apply(self, sql):
        text = norm(sql)
        if re.match(r"(SELECT|INSERT)\b", text, re.I):
            return
        create = re.match(r"CREATE (OR REPLACE )?(MATERIALIZED )?(TABLE|VIEW)( IF NOT EXISTS)? (\w+)(?: ON CLUSTER \w+)? ?", text, re.I)
        if create:
            name, body = create[5], text[create.end():]
            if create[4] and (name in self.tables or name in self.views):
                return
            if create[3].upper() == "TABLE":
                self.tables[name] = self.table(body)
            else:
                target = re.match(r"TO (\w+) AS (.*)$", body, re.I)
                self.views[name] = (target[1], target[2]) if target else (None, re.sub(r"^AS ", "", body))
            return
        drop = re.match(r"DROP (TABLE|VIEW)( IF EXISTS)? (\w+)", text, re.I)
        if drop:
            (self.tables if drop[1].upper() == "TABLE" else self.views).pop(drop[3], None)
            return
        alter = re.match(r"ALTER TABLE (\w+)(?: ON CLUSTER \w+)? (.*)$", text, re.I)
        if not alter:
            raise AssertionError(f"statement outside the modelled DDL subset: {text[:120]}")
        table = self.tables[alter[1]]
        if re.match(r"UPDATE\b", alter[2], re.I):
            return
        for action in top_level_split(alter[2]):
            if m := re.match(r"ADD COLUMN (IF NOT EXISTS )?(.*)$", action, re.I):
                name, kind = column(m[2])
                if name in dict(table["columns"]):
                    continue
                after = re.search(r"\bAFTER (\w+)\s*$", m[2], re.I)
                names = [existing for existing, _ in table["columns"]]
                table["columns"].insert(names.index(after[1]) + 1 if after else len(names), (name, kind))
            elif m := re.match(r"DROP COLUMN (IF EXISTS )?(\w+)$", action, re.I):
                table["columns"] = [entry for entry in table["columns"] if entry[0] != m[2]]
            elif m := re.match(r"MODIFY TTL (.*)$", action, re.I):
                table["TTL"] = m[1]
            elif m := re.match(r"ADD CONSTRAINT (IF NOT EXISTS )?(\w+) (.*)$", action, re.I):
                table["constraints"][m[2]] = m[3]
            elif m := re.match(r"DROP CONSTRAINT (IF EXISTS )?(\w+)$", action, re.I):
                table["constraints"].pop(m[2], None)
            else:
                raise AssertionError(f"ALTER action outside the modelled subset: {action[:120]}")

    @staticmethod
    def table(body):
        close = matching_paren(body, 0)
        columns, constraints = [], {}
        for element in top_level_split(body[1:close]):
            if m := re.match(r"CONSTRAINT (\w+) (.*)$", element, re.I):
                constraints[m[1]] = m[2]
            elif not re.match(r"(INDEX|PROJECTION)\b", element, re.I):
                columns.append(column(element))
        table = {"columns": columns, "constraints": constraints}
        tail = body[close + 1:]
        marks = list(CLAUSE.finditer(tail))
        for index, mark in enumerate(marks):
            end = marks[index + 1].start() if index + 1 < len(marks) else len(tail)
            table[re.sub(r"\s*=$", "", mark[1].upper())] = tail[mark.end():end].strip()
        return table


def chain(directory, rewrite=None):
    schema = Schema()
    for path in sorted(directory.glob("*.up.sql")):
        for statement in split(path.read_text(encoding="utf-8")):
            schema.apply(rewrite(statement) if rewrite else statement)
    return schema


class ReplicatedParity(unittest.TestCase):
    def test_mirror_is_generated_and_current(self):
        expected = GENERATE.expected()
        actual = {path.name: path.read_text(encoding="utf-8") for path in REPLICATED.glob("*.sql")}
        self.assertEqual(sorted(expected), sorted(actual), "replicated/ must mirror every migrations/*.sql file")
        for name, text in expected.items():
            self.assertEqual(text, actual[name], f"{name} is stale: run infra/clickhouse/replicated/generate.py")

    def test_statements_match_single_node_after_undoing_cluster_rewrite(self):
        for source in sorted(SINGLE.glob("*.sql")):
            mirror = REPLICATED / source.name
            self.assertTrue(mirror.is_file(), f"replicated/{source.name} missing")
            single = split(source.read_text(encoding="utf-8"))
            replicated = split(mirror.read_text(encoding="utf-8"))
            self.assertEqual(len(single), len(replicated), f"{source.name}: statement count")
            for index, (one, other) in enumerate(zip(single, replicated), 1):
                if re.match(r"\s*(SELECT|INSERT)\b", one, re.I):
                    self.assertEqual(norm(one), norm(other), f"{source.name} #{index}: DML/guard must be unchanged")
                    continue
                self.assertIn(f" ON CLUSTER {CLUSTER}", other, f"{source.name} #{index}: DDL without ON CLUSTER")
                if re.match(r"\s*DROP TABLE\b", other, re.I):
                    # The only intended difference: replicated drops are SYNC so up can follow down at once.
                    self.assertRegex(other, r"\bSYNC\s*$", f"{source.name} #{index}: replicated DROP TABLE must be SYNC")
                    one, other = (re.sub(r"\s+SYNC\s*$", "", sql) for sql in (one, other))
                self.assertEqual(norm(canonical_engine(one)), norm(canonical_engine(unreplicate(other))),
                                 f"{source.name} #{index}")

    def test_final_schema_matches(self):
        single = chain(SINGLE)
        replicated = chain(REPLICATED)
        self.assertEqual(sorted(single.tables), sorted(replicated.tables), "tables")
        self.assertEqual(sorted(single.views), sorted(replicated.views), "views and materialized views")
        for name, table in single.tables.items():
            other = replicated.tables[name]
            self.assertEqual(table["columns"], other["columns"], f"{name}: columns and types")
            for clause in ("ORDER BY", "PARTITION BY", "PRIMARY KEY", "TTL", "constraints"):
                self.assertEqual(table.get(clause), other.get(clause), f"{name}: {clause}")
            engine = SINGLE_ENGINE.match(table["ENGINE"])
            replicated_engine = REPLICATED_ENGINE.match(other["ENGINE"])
            self.assertIsNotNone(replicated_engine, f"{name}: engine not Replicated with per-table Keeper path: {other['ENGINE']}")
            self.assertEqual(engine[1], replicated_engine[1], f"{name}: engine family")
            self.assertEqual((engine[2] or "").strip(), (replicated_engine[2] or "").strip(),
                             f"{name}: ReplacingMergeTree version column / engine arguments")
        for name, view in single.views.items():
            self.assertEqual(view, replicated.views[name], f"{name}: target table and SELECT")
        # The release head this mirror must reach (sec-log-agg 025).
        self.assertIn(("requests", "UInt32"), replicated.tables["security_hourly_facts_v1"]["columns"])
        self.assertIn("event_count AS requests", replicated.views["security_hourly_mv_v1"][1])
        self.assertIn("security_event_count_state_v1", replicated.tables)


if __name__ == "__main__":
    unittest.main()
