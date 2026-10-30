"""Schema-only phase for the separately reviewed management publisher; no CLI.

Signature/source acquisition, filesystem safety, locks, stopping writers, backup
restore proof and the compatible code rollback baseline belong to that publisher.
Callbacks below are its fixed adapters, NOT an authorization or sandbox boundary.
"""

import copy
import hashlib
import json
import re


NEW_SQL = {version: {f"migrations/{name}.{direction}.sql" for direction in ("up", "down")}
           for version, name in ((270, "270_l2_topology_default_region"), (271, "271_node_network_inventory"))}
SQL_PATH = re.compile(r"migrations/([0-9]{3})_([a-z0-9]+(?:_[a-z0-9]+)*)\.(up|down)\.sql\Z")
OBJECT_ID = re.compile(r"[0-9a-f]{40}\Z")
DIGEST = re.compile(r"[0-9a-f]{64}\Z")
VERSION = re.compile(r"(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})\Z")
RECORD_FIELDS = {"schema", "binding", "action", "phase", "before_head", "state", "reason",
                 "command_status", "business_rollback"}


def _strict_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate_json_key")
        result[key] = value
    return result


def _manifest_sql(raw):
    if type(raw) is not bytes or not 0 < len(raw) <= 8 << 20:
        raise ValueError("invalid_manifest_bytes")
    manifest = json.loads(raw, object_pairs_hook=_strict_object)
    if type(manifest) is not dict or set(manifest) != {
            "schema", "key_id", "version", "built_at", "source", "platform", "files"}:
        raise ValueError("invalid_manifest_fields")
    source = manifest["source"]
    if (manifest["schema"] != "cdnca.native-management.release/v2" or
            not isinstance(manifest["key_id"], str) or not re.fullmatch(r"[A-Za-z0-9._-]{1,128}", manifest["key_id"]) or
            not isinstance(manifest["version"], str) or not VERSION.fullmatch(manifest["version"]) or
            not isinstance(manifest["built_at"], str) or not manifest["built_at"].endswith("Z") or
            manifest["platform"] not in ({"os": "linux", "arch": "amd64"}, {"os": "linux", "arch": "arm64"}) or
            type(source) is not dict or set(source) != {"commit", "tree", "previous_commit"} or
            any(not isinstance(value, str) or not OBJECT_ID.fullmatch(value) for value in source.values()) or
            type(manifest["files"]) is not list or not 1 <= len(manifest["files"]) <= 65536):
        raise ValueError("invalid_manifest_metadata")
    files = {}
    for item in manifest["files"]:
        if type(item) is not dict or set(item) != {"path", "sha256", "bytes", "mode"}:
            raise ValueError("invalid_file_entry")
        path = item["path"]
        if (not isinstance(path, str) or any(part in ("", ".", "..") for part in path.split("/")) or
                any(ord(character) < 32 or character in "\\\x7f" for character in path) or path in files or
                not isinstance(item["sha256"], str) or not DIGEST.fullmatch(item["sha256"]) or
                type(item["bytes"]) is not int or item["bytes"] < 1 or
                type(item["mode"]) is not int or item["mode"] not in (0o644, 0o755)):
            raise ValueError("invalid_file_inventory")
        files[path] = item
    for path, mode in (("bin/control-api", 0o755), ("bin/agent-gateway", 0o755), ("static/web/index.html", 0o644)):
        if path not in files or files[path]["mode"] != mode:
            raise ValueError("missing_release_component")
    sql = {path: entry for path, entry in files.items() if path.startswith("migrations/")}
    if any(not SQL_PATH.fullmatch(path) or entry["mode"] != 0o644 for path, entry in sql.items()):
        raise ValueError("invalid_sql_inventory")
    return manifest, sql, files["bin/control-api"]["sha256"]


def verify_migration_inputs(baseline_raw, candidate_raw, source_proof, baseline_sql, candidate_sql):
    """Bind signed-manifest raw bytes to actual SQL bytes acquired by the publisher.

source_proof['sql'] is the complete SQL byte/mode map extracted from the exact
remote-confirmed Git commit/tree, not copied from the candidate manifest. The
publisher must authenticate that acquisition and both signatures beforehand.
This function performs no signature, network, filesystem or Git operations.
    """
    before, old, _ = _manifest_sql(baseline_raw)
    after, new, control_digest = _manifest_sql(candidate_raw)
    proof_fields = {"schema", "source_commit", "source_tree", "remote_commit", "sql",
                    "baseline_manifest_sha256", "candidate_manifest_sha256"}
    if (type(source_proof) is not dict or set(source_proof) != proof_fields or
            source_proof["schema"] != "cdnca.management-migration-source/v1" or
            source_proof["source_commit"] != after["source"]["commit"] or
            source_proof["remote_commit"] != after["source"]["commit"] or
            source_proof["source_tree"] != after["source"]["tree"] or
            source_proof["baseline_manifest_sha256"] != hashlib.sha256(baseline_raw).hexdigest() or
            source_proof["candidate_manifest_sha256"] != hashlib.sha256(candidate_raw).hexdigest() or
            after["source"]["previous_commit"] != before["source"]["commit"] or
            after["source"]["commit"] == before["source"]["commit"] or after["platform"] != before["platform"] or
            tuple(map(int, after["version"].split("."))) <= tuple(map(int, before["version"].split(".")))):
        raise ValueError("source_or_manifest_binding_mismatch")
    if (len(old), len(new)) not in ((538, 540), (540, 542)):
        raise ValueError("only_adjacent_269_270_271_paths_allowed")
    baseline_head, candidate_head = len(old) // 2, len(new) // 2
    if set(new) - set(old) != NEW_SQL[candidate_head] or any(new.get(path) != value for path, value in old.items()):
        raise ValueError("only_exact_next_migration_allowed")
    migrations = {}
    for path, entry in new.items():
        match = SQL_PATH.fullmatch(path)
        version, direction = int(match[1]), match[3]
        identifier = path.removeprefix("migrations/").rsplit(".", 2)[0]
        item = migrations.setdefault(version, {"id": identifier})
        if item["id"] != identifier or direction in item:
            raise ValueError("invalid_migration_pair")
        item[direction] = entry["sha256"]
    if (set(migrations) != set(range(1, candidate_head + 1)) or any(set(item) != {"id", "up", "down"} for item in migrations.values()) or
            any(int(SQL_PATH.fullmatch(path)[1]) > baseline_head for path in old)):
        raise ValueError("invalid_migration_sequence")
    for inventory, expected in ((baseline_sql, old), (candidate_sql, new), (source_proof["sql"], new)):
        if type(inventory) is not dict or set(inventory) != set(expected):
            raise ValueError("sql_byte_inventory_mismatch")
        for path, value in inventory.items():
            if (type(value) is not dict or set(value) != {"content", "mode"} or type(value["content"]) is not bytes or
                    type(value["mode"]) is not int or value["mode"] != expected[path]["mode"] or
                    len(value["content"]) != expected[path]["bytes"] or
                    hashlib.sha256(value["content"]).hexdigest() != expected[path]["sha256"]):
                raise ValueError("sql_content_or_mode_mismatch")
    candidate = {"manifest_sha256": source_proof["candidate_manifest_sha256"],
                 "source_commit": after["source"]["commit"], "source_tree": after["source"]["tree"],
                 "control_api_sha256": control_digest}
    binding = hashlib.sha256(baseline_raw + b"\x00" + candidate_raw).hexdigest()
    return {"candidate": candidate, "binding": binding, "migrations": migrations,
            "baseline_head": baseline_head, "candidate_head": candidate_head}


def classify_ledger(verified, snapshot):
    """Validate a single consistent, idle migration snapshot from the fixed reader."""
    if (verified["baseline_head"], verified["candidate_head"]) not in ((269, 270), (270, 271)):
        raise ValueError("invalid_verified_path")
    if (type(snapshot) is not dict or set(snapshot) != {"ledger", "owners", "default_region_count", "network_report_count", "migration_idle"} or
            snapshot["owners"] != ["cdnca"] or snapshot["migration_idle"] is not True or
            type(snapshot["ledger"]) is not list or len(snapshot["ledger"]) not in (verified["baseline_head"], verified["candidate_head"])):
        raise ValueError("unknown_ledger")
    head = len(snapshot["ledger"])
    for version, row in enumerate(snapshot["ledger"], 1):
        if (type(row) is not dict or set(row) != {"version", "id", "up", "down", "state", "dated"} or
                type(row["version"]) is not int or row["version"] != version or
                row["state"] != "verified" or row["dated"] is not True or
                any(row[field] != verified["migrations"][version][field] for field in ("id", "up", "down"))):
            raise ValueError("ledger_checksum_or_sequence_mismatch")
    defaults, reports = snapshot["default_region_count"], snapshot["network_report_count"]
    if (type(defaults) is not int or defaults < 0 or head == 269 and defaults != 0 or
            head < 271 and reports is not None or head == 271 and (type(reports) is not int or reports < 0)):
        raise ValueError("unknown_fact_state")
    return {"head": head, "default_region_count": defaults, "network_report_count": reports,
            "down_allowed": head > verified["baseline_head"] and defaults == 0 and reports in (None, 0)}


def migration_step(verified, action, expected_head, read_state, run_candidate, save_record, previous=None):
    """One candidate invocation at most; no automatic rollback, service or file IO.

save_record must atomically fsync the private journal before returning. Its last
record MUST be passed back after restart. read_state must prove the previous
migrator has exited and take a consistent ledger/fact snapshot while holding the
database migration lock. The caller's release/runner locks span the whole phase.
run_candidate is an audited adapter accepting exactly (candidate identity,
direction); a Python callback cannot itself prove which executable was run.
    """
    if action not in ("status", "up", "down") or action != "status" and (type(expected_head) is not int or expected_head not in (269, 270, 271)):
        raise ValueError("invalid_action_or_expected_head")
    if previous is not None:
        if (type(previous) is not dict or set(previous) != RECORD_FIELDS or
                previous["schema"] != "cdnca.management-migration-step/v1" or previous["binding"] != verified["binding"] or
                previous["phase"] not in ("intent", "unknown", "observed", "refused") or
                previous["action"] not in ("status", "up", "down") or
                previous["command_status"] not in ("not_run", "succeeded", "unknown") or
                previous["reason"] not in ("ledger_unavailable", "observed", "head_changed", "facts_or_baseline_floor",
                                          "already_at_candidate", "candidate_invocation", "schema_step_observed", "command_outcome_requires_status") or
                previous["before_head"] is not None and (type(previous["before_head"]) is not int or previous["before_head"] not in (269, 270, 271)) or
                previous["business_rollback"] != "not_evaluated"):
            raise ValueError("invalid_prior_record")
        prior_state = previous["state"]
        if prior_state is not None:
            if (type(prior_state) is not dict or set(prior_state) != {"head", "default_region_count", "network_report_count", "down_allowed"} or
                    type(prior_state["head"]) is not int or prior_state["head"] not in (269, 270, 271) or
                    type(prior_state["default_region_count"]) is not int or prior_state["default_region_count"] < 0 or
                    type(prior_state["down_allowed"]) is not bool or
                    prior_state["network_report_count"] is not None and (type(prior_state["network_report_count"]) is not int or prior_state["network_report_count"] < 0)):
                raise ValueError("invalid_prior_state")
        if ((previous["phase"] != "unknown" and prior_state is None) or
                (previous["phase"] == "observed" and previous["command_status"] == "unknown") or
                (previous["phase"] == "intent" and (previous["action"] == "status" or previous["command_status"] != "unknown")) or
                (previous["phase"] == "refused" and previous["command_status"] != "not_run")):
            raise ValueError("inconsistent_prior_record")
        if previous["phase"] in ("intent", "unknown") and action != "status":
            raise ValueError("status_required_after_unknown")
    record = {"schema": "cdnca.management-migration-step/v1", "binding": verified["binding"], "action": action,
              "phase": "unknown", "before_head": None, "state": None, "reason": "ledger_unavailable",
              "command_status": "not_run", "business_rollback": "not_evaluated"}
    try:
        state = classify_ledger(verified, read_state())
    except Exception:
        save_record(copy.deepcopy(record))
        return record
    record.update(before_head=state["head"], state=state, phase="observed", reason="observed")
    if action != "status":
        if state["head"] != expected_head:
            record.update(phase="refused", reason="head_changed")
        elif action == "down" and not state["down_allowed"]:
            record.update(phase="refused", reason="facts_or_baseline_floor")
        elif action == "up" and state["head"] == verified["candidate_head"]:
            record["reason"] = "already_at_candidate"
        else:
            record.update(phase="intent", reason="candidate_invocation", command_status="unknown")
            save_record(copy.deepcopy(record))
            try:
                outcome = run_candidate(copy.deepcopy(verified["candidate"]), action)
                if outcome is None:
                    record["command_status"] = "succeeded"
            except Exception:
                pass  # Do not expose command errors, database details or credentials.
            finally:
                record.update(phase="unknown", state=None, reason="ledger_unavailable")
                try:
                    record["state"] = classify_ledger(verified, read_state())
                    target = verified["candidate_head"] if action == "up" else expected_head - 1
                    if record["command_status"] == "succeeded" and record["state"]["head"] == target:
                        record.update(phase="observed", reason="schema_step_observed")
                    else:
                        record["reason"] = "command_outcome_requires_status"
                except Exception:
                    pass
                save_record(copy.deepcopy(record))
            return record
    save_record(copy.deepcopy(record))
    return record
