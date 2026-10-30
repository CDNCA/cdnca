#!/usr/bin/env python3
"""Synthetic inventory tests, not evidence of a real database restore."""

import hashlib
import importlib.metadata
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


SCRIPT = Path(__file__).with_name("restore-inventory.py")
SPEC = importlib.util.spec_from_file_location("restore_inventory", SCRIPT)
INVENTORY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(INVENTORY)
try:
    PARSER_READY = importlib.metadata.version("pglast") == "8.5"
except importlib.metadata.PackageNotFoundError:
    PARSER_READY = False

ATOMIC_FUNCTION = b"""CREATE FUNCTION public.fixture_guard(operation text, required_scopes uuid[])
RETURNS void
LANGUAGE sql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
BEGIN ATOMIC
    SELECT public.iam_validate_stage2b_authority_operation_v1(operation);
    SELECT public.iam_require_stage2b_global_exclusive_v1();
    SELECT public.iam_assert_scope_locks_v1(required_scopes);
END;"""


def synthetic_inventory_dump(rows=b"duplicate\rvalue\nother\nduplicate\rvalue\n", extra=b"", definition=None):
    definition = definition or b"CREATE TABLE public.fixture (value text, CONSTRAINT allowed CHECK ((value <> 'private-literal') AND (value <> 'other')));"
    return (b"--\n-- PostgreSQL database dump\n--\n\n"
            b"-- Dumped from database version 17.11\n-- Dumped by pg_dump version 17.11\n\n"
            b"SET standard_conforming_strings = on;\n"
            b"SELECT pg_catalog.set_config('search_path', '', false);\n" + definition + b"\n"
            b"COPY public.fixture (value) FROM stdin;\n" + rows + b"\\.\n" + extra +
            b"--\n-- PostgreSQL database dump complete\n--\n\n")


class RestoreInventoryTests(unittest.TestCase):
    def test_atomic_function_bookkeeping(self):
        # Parser responses here isolate byte/range bookkeeping, not grammar validity.
        raw = synthetic_inventory_dump(extra=ATOMIC_FUNCTION + b"\n")
        parsed = {"stmts": [{"stmt": {"CreateFunctionStmt": {"sql_body": ["fixture-only"]}}}]}
        with mock.patch.object(INVENTORY, "canonical_create_table", side_effect=lambda raw: raw), \
                mock.patch.object(INVENTORY, "parse_inventory_statement", create=True,
                                  side_effect=[ValueError("inventory_statement_parse_rejected"), parsed]) as parser:
            result = INVENTORY.restore_sql_inventory(raw)
        self.assertEqual(len(result["schema_objects"]), 5)
        self.assertIn(hashlib.sha256(ATOMIC_FUNCTION).hexdigest(), result["schema_objects"].values())
        self.assertEqual(parser.call_args_list[-1], mock.call(ATOMIC_FUNCTION, "CreateFunctionStmt"))
        changed = ATOMIC_FUNCTION.replace(b"(required_scopes)", b"(NULL)")
        with mock.patch.object(INVENTORY, "canonical_create_table", side_effect=lambda raw: raw), \
                mock.patch.object(INVENTORY, "parse_inventory_statement", create=True,
                                  side_effect=[ValueError("inventory_statement_parse_rejected"), parsed]):
            self.assertNotEqual(result, INVENTORY.restore_sql_inventory(synthetic_inventory_dump(extra=changed + b"\n")))
        without_body = {"stmts": [{"stmt": {"CreateFunctionStmt": {}}}]}
        with mock.patch.object(INVENTORY, "canonical_create_table", side_effect=lambda raw: raw), \
                mock.patch.object(INVENTORY, "parse_inventory_statement", create=True,
                                  side_effect=[ValueError("inventory_statement_parse_rejected"), without_body]), \
                self.assertRaisesRegex(ValueError, "atomic_function_body_rejected"):
            INVENTORY.restore_sql_inventory(raw)

    @unittest.skipUnless(PARSER_READY, "requires externally provisioned pglast==8.5; not parser PASS")
    def test_real_atomic_function_parser_boundaries(self):
        raw = synthetic_inventory_dump(extra=ATOMIC_FUNCTION + b"\n")
        result = INVENTORY.restore_sql_inventory(raw)
        self.assertEqual(len(result["schema_objects"]), 5)
        self.assertIn(hashlib.sha256(ATOMIC_FUNCTION).hexdigest(), result["schema_objects"].values())
        duplicate = INVENTORY.restore_sql_inventory(synthetic_inventory_dump(extra=(ATOMIC_FUNCTION + b"\n") * 2))
        self.assertEqual(len(duplicate["schema_objects"]), 6)
        self.assertEqual(list(duplicate["schema_objects"].values()).count(hashlib.sha256(ATOMIC_FUNCTION).hexdigest()), 2)
        for statement in (ATOMIC_FUNCTION + b"\nSELECT 1;", b"CREATE TABLE public.extra (value text);"):
            with self.assertRaises(ValueError):
                INVENTORY.parse_inventory_statement(statement, "CreateFunctionStmt")
        changed = ATOMIC_FUNCTION.replace(b"(required_scopes)", b"(NULL)")
        self.assertNotEqual(result, INVENTORY.restore_sql_inventory(synthetic_inventory_dump(extra=changed + b"\n")))
        quoted = (b'CREATE FUNCTION public."BEGIN ATOMIC END"() RETURNS text LANGUAGE sql AS $body$\n'
                  b"SELECT 'BEGIN ATOMIC\nEND;';\n$body$;")
        quoted_identifier = (b'CREATE FUNCTION public."fixture\nBEGIN ATOMIC\nEND;"() RETURNS text '
                             b"LANGUAGE sql AS 'SELECT ''literal''';")
        quoted_atomic = (b'CREATE FUNCTION public."BEGIN ATOMIC END"() RETURNS text LANGUAGE sql\n'
                         b"BEGIN ATOMIC\n    SELECT 'BEGIN ATOMIC\nEND;'::text;\nEND;")
        for function in (quoted, quoted_identifier, quoted_atomic):
            with self.subTest(digest=hashlib.sha256(function).hexdigest()):
                inventory = INVENTORY.restore_sql_inventory(synthetic_inventory_dump(extra=function + b"\n"))
                self.assertEqual(len(inventory["schema_objects"]), 5)
                self.assertIn(hashlib.sha256(function).hexdigest(), inventory["schema_objects"].values())
        outside = b"SELECT public.iam_require_stage2b_global_exclusive_v1();\n"
        for extra in (outside, ATOMIC_FUNCTION + b"\n" + outside,
                      ATOMIC_FUNCTION.replace(b"\nEND;", b""),
                      ATOMIC_FUNCTION.replace(b"\nEND;", b"\nEND;\nEND;"),
                      ATOMIC_FUNCTION.replace(b"BEGIN ATOMIC", b"AS 'SELECT 1';\nBEGIN ATOMIC"),
                      ATOMIC_FUNCTION.replace(b"(required_scopes)", b"(required_scopes invalid token)")):
            with self.subTest(digest=hashlib.sha256(extra).hexdigest()), self.assertRaises(ValueError):
                INVENTORY.restore_sql_inventory(synthetic_inventory_dump(extra=extra + b"\n"))

    def test_statement_multiset_rows_cr_and_duplicates_preserved(self):
        # This stub isolates scanner/inventory bookkeeping; it is NOT parser evidence.
        with mock.patch.object(INVENTORY, "canonical_create_table", side_effect=lambda raw: raw):
            extra = b"COMMENT ON TABLE public.fixture IS 'private-comment';\n"
            left = INVENTORY.restore_sql_inventory(synthetic_inventory_dump(extra=extra * 2))
            right = INVENTORY.restore_sql_inventory(synthetic_inventory_dump(
                rows=b"other\nduplicate\rvalue\nduplicate\rvalue\n", extra=extra * 2))
            self.assertEqual(left, right)
            self.assertEqual(len(left["schema_objects"]), 6)
            self.assertEqual(list(left["schema_objects"]), [f"{index:012d}" for index in range(1, 7)])
            values = list(left["schema_objects"].values())
            self.assertEqual(values.count(hashlib.sha256(extra[:-1]).hexdigest()), 2)
            self.assertEqual(next(iter(left["table_rows"].values()))["rows"], 3)
            for changed in (synthetic_inventory_dump(rows=b"duplicate\rvalue\nother\n", extra=extra * 2),
                            synthetic_inventory_dump(rows=b"duplicatevalue\nother\nduplicatevalue\n", extra=extra * 2),
                            synthetic_inventory_dump(extra=extra)):
                self.assertNotEqual(left, INVENTORY.restore_sql_inventory(changed))

    def test_sequence_values_exact_and_still_in_statement_inventory(self):
        with mock.patch.object(INVENTORY, "canonical_create_table", side_effect=lambda raw: raw):
            raw = synthetic_inventory_dump(extra=b"SELECT pg_catalog.setval('public.fixture_seq', -9223372036854775808, false);\n")
            inventory = INVENTORY.restore_sql_inventory(raw)
            self.assertEqual(inventory["sequences"], {"public.fixture_seq": {"last_value": -(2**63), "is_called": False}})
            self.assertEqual(len(inventory["schema_objects"]), 5)
            quoted = b'SELECT pg_catalog.setval(\'"quoted schema"."a\'\'b"\', 9223372036854775807, true);\n'
            result = INVENTORY.restore_sql_inventory(synthetic_inventory_dump(extra=quoted))
            self.assertEqual(result["sequences"], {'"quoted schema"."a\'b"': {"last_value": 2**63 - 1, "is_called": True}})

    def test_unknown_sequence_large_object_and_incomplete_copy_refused(self):
        base = synthetic_inventory_dump()
        variants = [
            synthetic_inventory_dump(extra=b"SELECT pg_catalog.setval('unqualified', 1, true);\n"),
            synthetic_inventory_dump(extra=b"SELECT pg_catalog.setval('public.s', 9223372036854775808, true);\n"),
            synthetic_inventory_dump(extra=b"SELECT setval('public.s', 1);\n"),
            synthetic_inventory_dump(extra=b"SELECT pg_catalog.setval('public.s', 1, true);\n" * 2),
            synthetic_inventory_dump(extra=b"SELECT pg_catalog.lo_create(123);\n"),
            synthetic_inventory_dump(extra=b"SELECT lowrite(0, 'secret');\n"),
            synthetic_inventory_dump(extra=b"ALTER LARGE OBJECT 123 OWNER TO fixture;\n"),
            synthetic_inventory_dump(extra=b"COMMENT ON LARGE OBJECT 123 IS 'secret';\n"),
            synthetic_inventory_dump(extra=b"-- Name: 123; Type: BLOB; Schema: -; Owner: fixture\n"),
            base.replace(b"COPY public.fixture (value)", b"COPY pg_catalog.pg_largeobject (value)"),
            base.replace(b"COPY public.fixture (value) FROM stdin;\n", b"COPY public.fixture (value) FROM stdin;\n\\.\nCOPY public.fixture (value) FROM stdin;\n"),
            base.replace(b"\\.\n", b"", 1),
            base.replace(b"-- PostgreSQL database dump complete\n", b""),
            base.replace(b"version 17.11", b"version 16.5"),
            base.replace(b"standard_conforming_strings = on", b"standard_conforming_strings = off"),
            base + b"SELECT 1;\n",
            base + b"\x00",
        ]
        with mock.patch.object(INVENTORY, "canonical_create_table", side_effect=lambda raw: raw):
            for value in variants:
                with self.subTest(digest=hashlib.sha256(value).hexdigest()), self.assertRaises(ValueError):
                    INVENTORY.restore_sql_inventory(value)

    @unittest.skipUnless(PARSER_READY, "requires externally provisioned pglast==8.5; not parser PASS")
    def test_real_pinned_parser_only_ignores_reviewed_locations(self):
        left = b"CREATE TABLE public.fixture (value text, CONSTRAINT c CHECK ((value <> 'a') AND (value <> 'b')));"
        right = b"CREATE TABLE public.fixture (value text, CONSTRAINT c CHECK (((value <> 'a') AND (value <> 'b'))));"
        self.assertEqual(INVENTORY.canonical_create_table(left), INVENTORY.canonical_create_table(right))
        array = b"CREATE TABLE public.fixture (value text CHECK (value = ANY (ARRAY['a', 'b'])));"
        self.assertEqual(INVENTORY.canonical_create_table(array), INVENTORY.canonical_create_table(array.replace(b"ARRAY[", b"ARRAY [")))
        for changed in (left.replace(b"'a'", b"'different'"), left.replace(b"<> 'a'", b"= 'a'"),
                        left.replace(b" AND ", b" OR "), left.replace(b"value text", b"value integer")):
            self.assertNotEqual(INVENTORY.canonical_create_table(left), INVENTORY.canonical_create_table(changed))
        self.assertEqual(INVENTORY.restore_sql_inventory(synthetic_inventory_dump(definition=left)),
                         INVENTORY.restore_sql_inventory(synthetic_inventory_dump(definition=right)))

    def test_parser_pin_and_errors_never_expose_sql(self):
        with mock.patch.object(importlib.metadata, "version", return_value="8.4"):
            with self.assertRaisesRegex(ValueError, "parser_version_rejected"):
                INVENTORY.canonical_create_table(b"CREATE TABLE secret_data (value text);")
        if PARSER_READY:
            with self.assertRaises(ValueError) as error:
                INVENTORY.canonical_create_table(b"CREATE TABLE secret_data (PRIVATE_SECRET invalid(; ")
            self.assertNotIn("PRIVATE_SECRET", str(error.exception))

    def test_pair_binds_real_files_and_exclusive_private_outputs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            files = [root / name for name in ("dump", "original.sql", "restored.sql")]
            contents = [b"PGDMP synthetic archive only", synthetic_inventory_dump(), synthetic_inventory_dump(rows=b"other\nduplicate\rvalue\nduplicate\rvalue\n")]
            for path, raw in zip(files, contents):
                path.write_bytes(raw)
                path.chmod(0o600)
            outputs = [root / "original.json", root / "restored.json"]
            args = tuple(value for path, raw in zip(files, contents) for value in (path, hashlib.sha256(raw).hexdigest()))
            with mock.patch.object(INVENTORY, "canonical_create_table", side_effect=lambda raw: raw):
                receipt = INVENTORY.build_restore_inventory_pair(*args, *outputs)
            self.assertEqual(receipt["status"], "inventory_written")
            original, restored = [json.loads(path.read_bytes()) for path in outputs]
            required = {"schema", "comparison", "dump", "original_sql", "redump_sql", "origin", "schema_objects", "table_rows", "sequences", "large_objects"}
            self.assertEqual(set(original), required)
            self.assertEqual(original["schema"], "cdnca.restore-inventory/v1")
            self.assertEqual(original["comparison"], {"schema": "cdnca.restore-comparison/v1", "method": "root_reviewed_pg17_full_inventory_v1"})
            self.assertEqual(original["origin"], "original")
            self.assertEqual(restored["origin"], "restored")
            for field in required - {"origin"}:
                self.assertEqual(original[field], restored[field])
            self.assertEqual(original["dump"], {"bytes": len(contents[0]), "sha256": hashlib.sha256(contents[0]).hexdigest(), "mode": 384})
            self.assertEqual(original["large_objects"], {})
            for path in outputs:
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
                self.assertEqual(path.stat().st_nlink, 1)
            before = [path.read_bytes() for path in outputs]
            with mock.patch.object(INVENTORY, "canonical_create_table", side_effect=lambda raw: raw), self.assertRaises((OSError, ValueError)):
                INVENTORY.build_restore_inventory_pair(*args, *outputs)
            self.assertEqual([path.read_bytes() for path in outputs], before)
            self.assertEqual([path.read_bytes() for path in files], contents)

    def test_private_input_and_pair_publication_failure_leave_no_artifact(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            path = root / "input"
            raw = b"fixture-only"
            digest = hashlib.sha256(raw).hexdigest()
            path.write_bytes(raw)
            path.chmod(0o600)
            self.assertEqual(INVENTORY.read_restore_inventory_input(path, digest)[0], raw)
            for reason in ("hash", "permissions", "symlink", "hardlink", "fifo"):
                target = root / reason
                target.write_bytes(raw)
                target.chmod(0o600)
                if reason == "permissions":
                    target.chmod(0o644)
                elif reason == "symlink":
                    target.unlink()
                    target.symlink_to(path)
                elif reason == "hardlink":
                    target.unlink()
                    os.link(path, target)
                elif reason == "fifo":
                    target.unlink()
                    os.mkfifo(target, 0o600)
                with self.subTest(reason=reason), self.assertRaises((OSError, ValueError)):
                    INVENTORY.read_restore_inventory_input(target, "0" * 64 if reason == "hash" else digest)
                target.unlink()
            outputs = [root / "one.json", root / "two.json"]
            actual_link = os.link
            calls = []

            def fail_second_link(source, target, **kwargs):
                calls.append(target)
                if len(calls) == 2:
                    raise OSError("synthetic output failure")
                return actual_link(source, target, **kwargs)

            with mock.patch.object(os, "link", side_effect=fail_second_link), self.assertRaises(OSError):
                INVENTORY.publish_restore_inventory_pair(outputs, [b"{}\n", b"{}\n"])
            self.assertFalse(any(output.exists() for output in outputs))
            self.assertEqual(sorted(item.name for item in root.iterdir()), ["input"])
            outputs[1].write_bytes(b"existing-output-must-stay")
            with self.assertRaises(FileExistsError):
                INVENTORY.publish_restore_inventory_pair(outputs, [b"{}\n", b"{}\n"])
            self.assertFalse(outputs[0].exists())
            self.assertEqual(outputs[1].read_bytes(), b"existing-output-must-stay")
            outputs[1].unlink()
            with mock.patch.object(os, "fsync", side_effect=[None, None, OSError("synthetic directory failure")]), self.assertRaises(OSError):
                INVENTORY.publish_restore_inventory_pair(outputs, [b"{}\n", b"{}\n"])
            self.assertEqual(sorted(item.name for item in root.iterdir()), ["input"])
            alias = root / "alias"
            alias.symlink_to(root, target_is_directory=True)
            with self.assertRaises(ValueError):
                INVENTORY.read_restore_inventory_input(alias / "input", digest)
            with self.assertRaises(ValueError):
                INVENTORY.publish_restore_inventory_pair([alias / "one.json", alias / "two.json"], [b"{}\n", b"{}\n"])

    def test_cli_failure_is_redacted(self):
        arguments = ["--dump", "/PRIVATE_SECRET", "--dump-sha256", "0" * 64,
                     "--original-sql", "/PRIVATE_SECRET", "--original-sql-sha256", "0" * 64,
                     "--redump-sql", "/PRIVATE_SECRET", "--redump-sql-sha256", "0" * 64,
                     "--original-output", "/PRIVATE_SECRET", "--restored-output", "/PRIVATE_SECRET"]
        for extra in ([], ["--unexpected", "PRIVATE_SECRET"], ["--dump-sha256"]):
            with self.subTest(argument_count=len(extra)):
                result = subprocess.run([sys.executable, "-B", str(SCRIPT), *arguments, *extra],
                                        capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode, 1)
                self.assertEqual(result.stdout, "")
                self.assertEqual(result.stderr, "restore inventory refused; no success receipt\n")


if __name__ == "__main__":
    unittest.main()
