#!/usr/bin/env python3
"""Generate private PG17 SQL inventories; never connect to a database.

Requires externally provisioned pglast==8.5 on the release host, not customers.
Only the current zero-large-object dump profile is supported; unknown LO forms
are refused. This tool records inventory, not a claim that a restore succeeded.
"""

import argparse
import contextlib
import hashlib
import importlib.metadata
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import stat
import sys
import tempfile


SPEC = importlib.util.spec_from_file_location("restore084_inventory_scanner", Path(__file__).with_name("restore-084-search-path.py"))
SCANNER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SCANNER)
MAX_BYTES = SCANNER.MAX_BYTES
SETVAL = re.compile(rb"SELECT pg_catalog\.setval\('((?:[^'\n]|'')+)', (-?(?:0|[1-9][0-9]*)), (true|false)\);")
QUALIFIED = re.compile(SCANNER.IDENTIFIER + rb"\." + SCANNER.IDENTIFIER)
COMPARISON = {"schema": "cdnca.restore-comparison/v1", "method": "root_reviewed_pg17_full_inventory_v1"}


def parse_inventory_statement(statement, expected_kind):
    try:
        if importlib.metadata.version("pglast") != "8.5":
            raise ValueError("parser_version_rejected")
    except importlib.metadata.PackageNotFoundError:
        raise ValueError("parser_version_rejected") from None
    try:
        from pglast.parser import parse_sql_json
        tree = json.loads(parse_sql_json(statement.decode("utf-8")))
        if len(tree["stmts"]) != 1 or set(tree["stmts"][0]["stmt"]) != {expected_kind}:
            raise ValueError("unexpected_statement_ast")
        return tree
    except Exception:
        raise ValueError("inventory_statement_parse_rejected") from None


def canonical_create_table(statement):
    tree = parse_inventory_statement(statement, "CreateStmt")
    pending = [tree]
    while pending:
        node = pending.pop()
        if isinstance(node, dict):
            for field in ("location", "stmt_location", "stmt_len"):
                node.pop(field, None)
            array = node.get("A_ArrayExpr")
            if isinstance(array, dict):
                array.pop("list_start", None)
                array.pop("list_end", None)
            pending.extend(node.values())
        elif isinstance(node, list):
            pending.extend(node)
    return json.dumps(tree, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")


def inventory_statement_ranges(raw):
    """Rejoin SQL-standard function bodies without changing the fixed COPY scanner."""
    spans = SCANNER.scan_084_dump(raw)
    index = 0
    while index < len(spans):
        start, end, block_end = spans[index]
        statement = raw[start:end]
        if statement == b"END;" or statement.startswith(b"BEGIN ATOMIC"):
            raise ValueError("orphan_atomic_function_boundary")
        if statement.startswith(b"CREATE FUNCTION ") and re.search(rb"(?m)^[ \t]*BEGIN ATOMIC[ \t]*(?:\n|$)", statement):
            try:
                # A marker inside a quoted name/string is already a complete statement.
                parse_inventory_statement(statement, "CreateFunctionStmt")
            except ValueError as error:
                if str(error) != "inventory_statement_parse_rejected":
                    raise
                for following in range(index + 1, min(index + 65, len(spans))):
                    next_start, next_end, next_block_end = spans[following]
                    if next_block_end != next_end or next_end - start > 65536:
                        raise ValueError("atomic_function_boundary_rejected")
                    if raw[next_start:next_end] != b"END;":
                        continue
                    tree = parse_inventory_statement(raw[start:next_end], "CreateFunctionStmt")
                    if not tree["stmts"][0]["stmt"]["CreateFunctionStmt"].get("sql_body"):
                        raise ValueError("atomic_function_body_rejected")
                    end = block_end = next_end
                    index = following
                    break
                else:
                    raise ValueError("atomic_function_boundary_rejected")
        yield start, end, block_end
        index += 1


def restore_sql_inventory(raw):
    if (not raw.startswith(b"--\n-- PostgreSQL database dump\n--\n") or not raw.endswith(b"\n")
            or not raw or len(raw) > MAX_BYTES or b"\x00" in raw):
        raise ValueError("dump_encoding_or_size_rejected")
    for label in (b"Dumped from database", b"Dumped by pg_dump"):
        versions = re.findall(rb"^-- " + label + rb" version ([^\n]+)$", raw, re.M)
        if len(versions) != 1 or not re.match(rb"17(?:\.|\s|$)", versions[0]):
            raise ValueError("dump_version_rejected")
    hashes, copies, sequences = [], {}, {}
    strings_seen, path_seen, tables, previous_end = False, False, 0, 0
    for start, end, block_end in inventory_statement_ranges(raw):
        if re.search(rb"^-- [^\n]*Type: (?:BLOB|LARGE OBJECT)\b", raw[previous_end:start], re.M):
            raise ValueError("large_objects_not_supported")
        previous_end = block_end
        statement = raw[start:end]
        if re.match(rb"(?i:SET\s+standard_conforming_strings)\b", statement):
            if statement != b"SET standard_conforming_strings = on;" or strings_seen or copies:
                raise ValueError("string_mode_rejected")
            strings_seen = True
        if re.match(rb"(?i:SET\s+(?:LOCAL\s+|SESSION\s+)?search_path)\b", statement):
            raise ValueError("search_path_rejected")
        sequence = SETVAL.fullmatch(statement)
        if sequence:
            name = sequence[1].replace(b"''", b"'")
            if not QUALIFIED.fullmatch(name):
                raise ValueError("sequence_name_rejected")
            name = name.decode("utf-8")
            value = int(sequence[2])
            if not -(2**63) <= value < 2**63 or name in sequences:
                raise ValueError("sequence_state_rejected")
            sequences[name] = {"last_value": value, "is_called": sequence[3] == b"true"}
        elif re.match(rb"(?i:SELECT)\b", statement):
            if statement != SCANNER.EMPTY_PATH or path_seen or copies:
                raise ValueError("unsupported_dump_select")
            path_seen = True
        if re.match(rb"(?i:(?:ALTER|COMMENT|GRANT|REVOKE|SECURITY))\b", statement) and re.search(rb"(?i:LARGE\s+OBJECT)\b", statement):
            raise ValueError("large_objects_not_supported")
        digest = hashlib.sha256(statement).hexdigest()
        if statement.startswith(b"CREATE TABLE "):
            digest = hashlib.sha256(canonical_create_table(statement)).hexdigest()
            tables += 1
        hashes.append(digest)
        if block_end > end:
            copy = SCANNER.COPY.fullmatch(statement)
            if not copy or copy[2].strip(b'"').lower() in (b"pg_largeobject", b"pg_largeobject_metadata"):
                raise ValueError("copy_relation_rejected")
            if digest in copies or not strings_seen or not path_seen:
                raise ValueError("duplicate_or_unsafe_copy")
            data = raw[end:block_end]
            if not data.startswith(b"\n") or not data.endswith(b"\\.\n"):
                raise ValueError("copy_boundary_rejected")
            body = data[1:-3]
            if body and not body.endswith(b"\n"):
                raise ValueError("copy_row_boundary_rejected")
            rows = [] if not body else [row + b"\n" for row in body[:-1].split(b"\n")]
            copies[digest] = {"rows": len(rows), "content_sha256": hashlib.sha256(b"".join(sorted(rows))).hexdigest()}
    if (not tables or not copies or not strings_seen or not path_seen
            or re.search(rb"^-- [^\n]*Type: (?:BLOB|LARGE OBJECT)\b", raw[previous_end:], re.M)):
        raise ValueError("incomplete_or_large_object_dump")
    return {"schema_objects": {f"{index:012d}": digest for index, digest in enumerate(sorted(hashes), 1)},
            "table_rows": copies, "sequences": sequences, "large_objects": {}}


def read_restore_inventory_input(path, expected_sha256):
    path = Path(path).absolute()
    if not re.fullmatch(r"[a-f0-9]{64}", expected_sha256) or any(parent.is_symlink() for parent in path.parents):
        raise ValueError("input_path_or_digest_rejected")
    parent = path.parent.stat()
    if parent.st_uid != os.geteuid() or stat.S_IMODE(parent.st_mode) != 0o700:
        raise ValueError("input_directory_not_private")
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), "rb") as stream:
        before = os.fstat(stream.fileno())
        if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or not 0 < before.st_size <= MAX_BYTES
                or before.st_uid != os.geteuid() or stat.S_IMODE(before.st_mode) != 0o600):
            raise ValueError("input_file_not_private_regular")
        raw = stream.read(MAX_BYTES + 1)
        after = os.fstat(stream.fileno())
    if ((before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (after.st_size, after.st_mtime_ns, after.st_ctime_ns)
            or len(raw) != before.st_size or hashlib.sha256(raw).hexdigest() != expected_sha256):
        raise ValueError("input_changed_or_digest_mismatch")
    return raw, {"sha256": expected_sha256, "bytes": len(raw), "mode": stat.S_IMODE(before.st_mode)}


def publish_restore_inventory_pair(outputs, contents):
    outputs = [Path(path).absolute() for path in outputs]
    if len(outputs) != 2 or len(contents) != 2 or outputs[0] == outputs[1] or outputs[0].parent != outputs[1].parent:
        raise ValueError("distinct_sibling_outputs_required")
    parent = outputs[0].parent
    if parent.is_symlink() or any(item.is_symlink() for item in parent.parents):
        raise ValueError("output_symlink_directory_rejected")
    info = parent.stat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise ValueError("output_directory_not_private")
    temporary, published = [], []
    try:
        for output, body in zip(outputs, contents):
            with tempfile.NamedTemporaryFile(prefix=".restore-inventory-", dir=parent, delete=False) as stream:
                path = Path(stream.name)
                temporary.append(path)
                stream.write(body)
                stream.flush()
                os.fsync(stream.fileno())
            os.link(path, output, follow_symlinks=False)
            published.append((output, path.stat()))
        descriptor = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    except BaseException:
        for output, owned in reversed(published):
            actual = output.lstat()
            if (actual.st_dev, actual.st_ino) == (owned.st_dev, owned.st_ino):
                output.unlink()
        raise
    finally:
        for path in temporary:
            path.unlink()


def build_restore_inventory_pair(dump, dump_sha256, original, original_sha256, restored, restored_sha256, original_output, restored_output):
    _, dump_fact = read_restore_inventory_input(dump, dump_sha256)
    original_raw, original_fact = read_restore_inventory_input(original, original_sha256)
    restored_raw, restored_fact = read_restore_inventory_input(restored, restored_sha256)
    original_fact.pop("mode")
    restored_fact.pop("mode")
    base = {"schema": "cdnca.restore-inventory/v1", "comparison": COMPARISON, "dump": dump_fact,
            "original_sql": original_fact, "redump_sql": restored_fact}
    inventories = [{**base, "origin": origin, **restore_sql_inventory(raw)}
                   for origin, raw in (("original", original_raw), ("restored", restored_raw))]
    publish_restore_inventory_pair([original_output, restored_output],
                                   [json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode() + b"\n" for value in inventories])
    return {"schema": "cdnca.restore-inventory-generation/v1", "status": "inventory_written",
            "original_statements": len(inventories[0]["schema_objects"]), "restored_statements": len(inventories[1]["schema_objects"]),
            "original_copy_tables": len(inventories[0]["table_rows"]), "restored_copy_tables": len(inventories[1]["table_rows"]),
            "original_rows": sum(item["rows"] for item in inventories[0]["table_rows"].values()),
            "restored_rows": sum(item["rows"] for item in inventories[1]["table_rows"].values()), "large_objects": 0}


def restore_inventory_main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for label in ("dump", "original-sql", "redump-sql"):
        parser.add_argument("--" + label, required=True, type=Path)
        parser.add_argument("--" + label + "-sha256", required=True)
    parser.add_argument("--original-output", required=True, type=Path)
    parser.add_argument("--restored-output", required=True, type=Path)
    try:
        with contextlib.redirect_stderr(io.StringIO()):
            args = parser.parse_args(argv)
    except SystemExit as error:
        if error.code == 0:
            return 0
        print("restore inventory refused; no success receipt", file=sys.stderr)
        return 1
    try:
        receipt = build_restore_inventory_pair(args.dump, args.dump_sha256, args.original_sql, args.original_sql_sha256,
                                               args.redump_sql, args.redump_sql_sha256, args.original_output, args.restored_output)
    except Exception:
        print("restore inventory refused; no success receipt", file=sys.stderr)
        return 1
    print(json.dumps(receipt, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(restore_inventory_main())
