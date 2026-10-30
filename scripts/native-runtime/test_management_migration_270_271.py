"""Pure fault injection: no PostgreSQL, services, signing keys or network calls."""

import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import unittest


class ManagementMigration270271Tests(unittest.TestCase):
    def setUp(self, baseline_head=270):
        spec = importlib.util.spec_from_file_location(
            "management_migration", Path(__file__).with_name("management-migration-270-271.py"))
        self.helper = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.helper)
        self.sql = {}
        for version in range(1, baseline_head + 2):
            name = {270: "l2_topology_default_region", 271: "node_network_inventory"}.get(version, "fixture")
            for direction in ("up", "down"):
                self.sql[f"migrations/{version:03d}_{name}.{direction}.sql"] = {
                    "content": f"-- fixture {version} {direction}\nSELECT 1;\n".encode(), "mode": 0o644}
        self.old_sql = {path: copy.deepcopy(value) for path, value in self.sql.items() if int(path[11:14]) <= baseline_head}
        self.baseline = self.manifest(self.old_sql, f"1.0.{baseline_head - 258}", "a" * 40, "b" * 40, "c" * 40)
        self.candidate = self.manifest(self.sql, f"1.0.{baseline_head - 257}", "d" * 40, "e" * 40, "a" * 40)
        self.proof = {"schema": "cdnca.management-migration-source/v1", "source_commit": "d" * 40,
                      "source_tree": "e" * 40, "remote_commit": "d" * 40, "sql": copy.deepcopy(self.sql)}
        self.bind_raw()
        self.events = []
        self.head = baseline_head
        self.default_count = 0
        self.report_count = 0
        self.read_error = False

    def manifest(self, sql, version, commit, tree, previous):
        files = [{"path": path, "mode": value["mode"], "bytes": len(value["content"]),
                  "sha256": hashlib.sha256(value["content"]).hexdigest()} for path, value in sql.items()]
        files.extend({"path": path, "mode": mode, "bytes": 1, "sha256": "f" * 64} for path, mode in (
            ("bin/control-api", 0o755), ("bin/agent-gateway", 0o755), ("static/web/index.html", 0o644)))
        return {"schema": "cdnca.native-management.release/v2", "key_id": "fixture-publisher",
                "version": version, "built_at": "2026-10-10T00:00:00Z",
                "source": {"commit": commit, "tree": tree, "previous_commit": previous},
                "platform": {"os": "linux", "arch": "amd64"}, "files": sorted(files, key=lambda item: item["path"])}

    def bind_raw(self):
        self.baseline_raw = json.dumps(self.baseline).encode()
        self.candidate_raw = json.dumps(self.candidate).encode()
        self.proof["baseline_manifest_sha256"] = hashlib.sha256(self.baseline_raw).hexdigest()
        self.proof["candidate_manifest_sha256"] = hashlib.sha256(self.candidate_raw).hexdigest()

    def verify(self):
        return self.helper.verify_migration_inputs(
            self.baseline_raw, self.candidate_raw, self.proof, self.old_sql, self.sql)

    def snapshot(self, head=None):
        head = self.head if head is None else head
        rows = []
        for version in range(1, head + 1):
            paths = [path for path in self.sql if path.startswith(f"migrations/{version:03d}_")]
            identifier = paths[0].removeprefix("migrations/").rsplit(".", 2)[0]
            rows.append({"version": version, "id": identifier, "state": "verified", "dated": True,
                         "up": hashlib.sha256(self.sql[f"migrations/{identifier}.up.sql"]["content"]).hexdigest(),
                         "down": hashlib.sha256(self.sql[f"migrations/{identifier}.down.sql"]["content"]).hexdigest()})
        return {"ledger": rows, "owners": ["cdnca"], "default_region_count": self.default_count,
                "network_report_count": self.report_count if head == 271 else None, "migration_idle": True}

    def read(self):
        self.events.append("read")
        if self.read_error:
            raise OSError("not safe to display raw database details")
        return self.snapshot()

    def _run_candidate(self, candidate, direction):
        self.events.append(("run", candidate, direction))
        self.head = 271 if direction == "up" else self.head - 1

    def save(self, record):
        self.events.append(("save", copy.deepcopy(record)))

    def step(self, action, expected_head=None, run=None, previous=None, save=None):
        return self.helper.migration_step(self.verify(), action, self.head if expected_head is None else expected_head,
                                          self.read, run or self._run_candidate, save or self.save, previous)

    def test_inputs_bind_every_sql_byte_mode_raw_manifest_and_source(self):
        verified = self.verify()
        self.assertEqual(len(verified["migrations"]), 271)
        self.assertEqual((verified["baseline_head"], verified["candidate_head"]), (270, 271))
        self.assertEqual(verified["candidate"]["manifest_sha256"], hashlib.sha256(self.candidate_raw).hexdigest())
        self.assertEqual(verified["candidate"]["control_api_sha256"], "f" * 64)
        self.assertEqual(self.events, [])

    def test_raw_manifest_hash_and_duplicate_json_keys_are_rejected(self):
        self.candidate_raw += b" "
        with self.assertRaises(ValueError): self.verify()
        self.candidate_raw = b'{"schema":"a","schema":"b"}'
        self.proof["candidate_manifest_sha256"] = hashlib.sha256(self.candidate_raw).hexdigest()
        with self.assertRaises(ValueError): self.verify()

    def test_manifest_and_source_identity_mismatches_fail_closed(self):
        for field in ("source_commit", "source_tree", "remote_commit", "baseline_manifest_sha256"):
            with self.subTest(field=field):
                original = self.proof[field]
                self.proof[field] = "0" * len(original)
                with self.assertRaises(ValueError): self.verify()
                self.proof[field] = original
        for field, value in (("schema", "cdnca.native-management.release/v1"), ("version", "1.0.11")):
            original = self.candidate[field]
            self.candidate[field] = value
            self.bind_raw()
            with self.subTest(field=field), self.assertRaises(ValueError): self.verify()
            self.candidate[field] = original
            self.bind_raw()
        self.candidate["source"]["previous_commit"] = "0" * 40
        self.bind_raw()
        with self.assertRaises(ValueError): self.verify()

    def test_old_sql_change_is_rejected_even_when_new_manifest_and_source_agree(self):
        path = next(iter(self.old_sql))
        for field, value in (("content", b"SELECT changed;"), ("mode", 0o755)):
            with self.subTest(field=field):
                before = copy.deepcopy(self.sql[path])
                self.sql[path][field] = value
                self.proof["sql"][path] = copy.deepcopy(self.sql[path])
                self.candidate = self.manifest(self.sql, "1.0.13", "d" * 40, "e" * 40, "a" * 40)
                self.bind_raw()
                with self.assertRaises(ValueError): self.verify()
                self.sql[path] = before

    def test_extra_missing_duplicate_or_wrong_new_sql_is_rejected(self):
        original = copy.deepcopy(self.candidate)
        new = next(item for item in self.candidate["files"] if item["path"].startswith("migrations/271_"))
        for kind in ("missing", "duplicate", "wrong-name", "extra"):
            self.candidate = copy.deepcopy(original)
            if kind == "missing": self.candidate["files"].remove(new)
            elif kind == "duplicate": self.candidate["files"].append(copy.deepcopy(new))
            else: self.candidate["files"].append({**new, "path": "migrations/272_unowned.up.sql" if kind == "extra" else "migrations/271_wrong.up.sql"})
            self.bind_raw()
            with self.subTest(kind=kind), self.assertRaises(ValueError): self.verify()

    def test_actual_and_source_sql_bytes_and_inventory_are_both_checked(self):
        path = "migrations/271_node_network_inventory.up.sql"
        for mapping in (self.sql, self.proof["sql"], self.old_sql):
            member = path if path in mapping else next(iter(mapping))
            original = copy.deepcopy(mapping[member])
            mapping[member]["content"] += b"tamper"
            with self.assertRaises(ValueError): self.verify()
            mapping[member] = original
        self.proof["sql"].pop(path)
        with self.assertRaises(ValueError): self.verify()

    def test_exact_269_270_271_states(self):
        for baseline in (269, 270):
            self.setUp(baseline)
            verified = self.verify()
            for head in (baseline, baseline + 1):
                with self.subTest(baseline=baseline, head=head):
                    state = self.helper.classify_ledger(verified, self.snapshot(head))
                    self.assertEqual(state["head"], head)
                    self.assertEqual(state["down_allowed"], head > baseline)

    def test_only_two_adjacent_paths_and_no_direct_269_to_271(self):
        self.old_sql = {path: value for path, value in self.old_sql.items() if int(path[11:14]) <= 269}
        self.baseline = self.manifest(self.old_sql, "1.0.11", "a" * 40, "b" * 40, "c" * 40)
        self.bind_raw()
        with self.assertRaises(ValueError): self.verify()

    def test_candidate270_rejects_271_even_for_status(self):
        future = self.snapshot(271)
        self.setUp(269)
        with self.assertRaises(ValueError): self.helper.classify_ledger(self.verify(), future)
        result = self.helper.migration_step(self.verify(), "status", None, lambda: future, self._run_candidate, self.save)
        self.assertEqual(result["phase"], "unknown")
        self.assertIsNone(result["state"])

    def test_first_stage_up_reaches_only_270_and_preserves_269_floor(self):
        self.setUp(269)
        def bridge(candidate, direction): self.head = 270
        result = self.step("up", run=bridge)
        self.assertEqual(result["phase"], "observed")
        self.assertEqual(result["state"]["head"], 270)
        result = self.step("down", previous=result)
        self.assertEqual(result["state"]["head"], 269)
        result = self.step("down", previous=result)
        self.assertEqual(result["phase"], "refused")

    def test_first_stage_partial_fail_before_or_after_commit_reads_real_head(self):
        for committed in (269, 270):
            self.setUp(269)
            def lost(candidate, direction):
                self.head = committed
                raise TimeoutError()
            result = self.step("up", run=lost)
            with self.subTest(committed=committed):
                self.assertEqual(result["phase"], "unknown")
                self.assertEqual(result["state"]["head"], committed)

    def test_second_stage_rejects_269_and_never_rolls_bridge_back(self):
        with self.assertRaises(ValueError): self.helper.classify_ledger(self.verify(), self.snapshot(269))
        result = self.step("down")
        self.assertEqual(result["phase"], "refused")
        self.assertFalse(any(isinstance(event, tuple) and event[0] == "run" for event in self.events))

    def test_second_stage_up_preserves_existing_default_region_facts(self):
        self.default_count = 1
        result = self.step("up")
        self.assertEqual((result["phase"], result["state"]["head"]), ("observed", 271))
        result = self.step("down", previous=result)
        self.assertEqual(result["phase"], "refused")
        self.assertEqual(self.default_count, 1)

    def test_gaps_unknown_heads_checksums_metadata_owner_and_noninteger_counts_rejected(self):
        verified = self.verify()
        for kind in ("gap", "268", "duplicate", "checksum", "id", "unverified", "undated", "owner", "bool-count", "absent-271", "premature-271", "active-migration"):
            data = self.snapshot(271)
            if kind == "gap": data["ledger"].pop(5)
            elif kind == "268": data = self.snapshot(268)
            elif kind == "duplicate": data["ledger"][2] = data["ledger"][1]
            elif kind == "checksum": data["ledger"][269]["down"] = "0" * 64
            elif kind == "id": data["ledger"][269]["id"] = "270_wrong"
            elif kind == "unverified": data["ledger"][0]["state"] = "legacy-unverified"
            elif kind == "undated": data["ledger"][0]["dated"] = False
            elif kind == "owner": data["owners"] = ["postgres"]
            elif kind == "bool-count": data["default_region_count"] = True
            elif kind == "absent-271": data["network_report_count"] = None
            elif kind == "premature-271": data = self.snapshot(270); data["network_report_count"] = 0
            elif kind == "active-migration": data["migration_idle"] = False
            with self.subTest(kind=kind), self.assertRaises(ValueError): self.helper.classify_ledger(verified, data)

    def test_facts_block_down_without_mutating_anything(self):
        for head, defaults, reports in ((270, 0, 0), (270, 1, 0), (271, 0, 1), (271, 1, 0), (271, 1, 1)):
            self.head, self.default_count, self.report_count = head, defaults, reports
            self.events = []
            result = self.step("down")
            self.assertEqual(result["phase"], "refused")
            self.assertFalse(any(isinstance(event, tuple) and event[0] == "run" for event in self.events))
            self.assertEqual((self.head, self.default_count, self.report_count), (head, defaults, reports))

    def test_down_is_one_step_and_never_touches_269(self):
        self.head = 271
        first = self.step("down")
        self.assertEqual(first["state"]["head"], 270)
        second = self.step("down", previous=first)
        self.assertEqual(second["state"]["head"], 270)
        result = self.step("down", previous=second)
        self.assertEqual(result["phase"], "refused")
        self.assertEqual(len([event for event in self.events if isinstance(event, tuple) and event[0] == "run"]), 1)

    def test_durable_intent_precedes_only_pinned_candidate_call(self):
        result = self.step("up")
        self.assertEqual(result["phase"], "observed")
        self.assertEqual(result["state"]["head"], 271)
        run_index = next(index for index, event in enumerate(self.events) if isinstance(event, tuple) and event[0] == "run")
        self.assertEqual(self.events[run_index - 1][1]["phase"], "intent")
        self.assertEqual(self.events[run_index][1], self.verify()["candidate"])
        self.assertEqual(self.events[-2], "read")
        self.assertEqual(result["business_rollback"], "not_evaluated")

    def test_up_failure_at_each_legal_head_always_reads_actual_ledger(self):
        for committed in (270, 271):
            self.head, self.events = 270, []
            def fail(candidate, direction):
                self.events.append(("run", candidate, direction))
                self.head = committed
                raise OSError("raw secret must not escape")
            result = self.step("up", run=fail)
            with self.subTest(committed=committed):
                self.assertEqual(result["phase"], "unknown")
                self.assertEqual(result["state"]["head"], committed)
                self.assertEqual(self.events[-2], "read")
                self.assertNotIn("raw secret", json.dumps(result))
                self.assertEqual(len([event for event in self.events if isinstance(event, tuple) and event[0] == "run"]), 1)

    def test_down_failure_before_or_after_each_commit_preserves_actual_state(self):
        for start in (270, 271):
            for committed in (start, start - 1):
                self.setUp(start - 1)
                self.head, self.events = start, []
                def fail(candidate, direction):
                    self.head = committed
                    raise subprocess.TimeoutExpired("fixed-candidate", 1)
                result = self.step("down", run=fail)
                with self.subTest(start=start, committed=committed):
                    self.assertEqual(result["phase"], "unknown")
                    self.assertEqual(result["state"]["head"], committed)
                    self.assertGreaterEqual(self.head, 269)

    def test_partial_up_success_exit_is_not_migration_complete(self):
        def incomplete(candidate, direction): self.head = 270
        result = self.step("up", run=incomplete)
        self.assertEqual(result["phase"], "unknown")
        self.assertEqual(result["state"]["head"], 270)

    def test_guard_race_is_refusal_and_does_not_delete_facts(self):
        self.head = 271
        def guarded(candidate, direction):
            self.report_count = 1
            raise RuntimeError("P2712")
        result = self.step("down", run=guarded)
        self.assertEqual(result["phase"], "unknown")
        self.assertFalse(result["state"]["down_allowed"])
        self.assertEqual((self.head, self.report_count), (271, 1))

    def test_unknown_read_after_command_is_sticky_until_status(self):
        def lost(candidate, direction):
            self.head = 271
            self.read_error = True
            raise TimeoutError("unknown")
        result = self.step("up", run=lost)
        self.assertEqual(result["phase"], "unknown")
        self.assertIsNone(result["state"])
        self.read_error = False
        before = len(self.events)
        with self.assertRaises(ValueError): self.step("up", previous=json.loads(json.dumps(result)))
        self.assertEqual(len(self.events), before)
        restored = self.step("status", previous=json.loads(json.dumps(result)))
        self.assertEqual(restored["phase"], "observed")
        self.assertEqual(restored["state"]["head"], 271)
        self.assertEqual(restored["command_status"], "not_run")

    def test_process_restart_from_intent_can_only_status_then_head_cas(self):
        result = self.step("up")
        intent = next(event[1] for event in self.events if isinstance(event, tuple) and event[0] == "save" and event[1]["phase"] == "intent")
        with self.assertRaises(ValueError): self.step("down", previous=intent)
        restored = self.step("status", previous=intent)
        result = self.step("up", expected_head=269, previous=restored)
        self.assertEqual(result["phase"], "refused")
        self.assertEqual(result["reason"], "head_changed")

    def test_journal_identity_and_corruption_cannot_unlock_a_write(self):
        result = self.step("status")
        for field, value in (("binding", "0" * 64), ("phase", "invented"), ("business_rollback", "healthy"),
                             ("action", "other"), ("state", None), ("command_status", "unknown")):
            damaged = {**result, field: value}
            with self.subTest(field=field), self.assertRaises(ValueError): self.step("up", previous=damaged)

    def test_final_record_failure_preserves_durable_intent_for_restart(self):
        durable = []
        def fail_final(record):
            if record["phase"] != "intent": raise OSError("disk full")
            durable.append(copy.deepcopy(record))
        with self.assertRaises(OSError): self.step("up", save=fail_final)
        self.assertEqual(len(durable), 1)
        self.assertEqual(durable[0]["phase"], "intent")
        with self.assertRaises(ValueError): self.step("up", previous=durable[0])
        result = self.step("status", previous=durable[0])
        self.assertEqual(result["state"]["head"], 271)

    def test_interrupt_still_observes_and_persists_unknown(self):
        def interrupted(candidate, direction):
            self.head = 270
            raise KeyboardInterrupt()
        with self.assertRaises(KeyboardInterrupt): self.step("up", run=interrupted)
        self.assertEqual(self.events[-2], "read")
        result = self.events[-1][1]
        self.assertEqual(result["phase"], "unknown")
        self.assertEqual(result["state"]["head"], 270)

    def test_unrecognised_adapter_return_never_claims_success(self):
        for value in (0, 1, False, "success"):
            self.head = 270
            def returned(candidate, direction):
                self.head = 271
                return value
            result = self.step("up", run=returned)
            with self.subTest(value=value):
                self.assertEqual(result["phase"], "unknown")
                self.assertEqual(result["state"]["head"], 271)

    def test_pending_migrator_cannot_be_cleared_by_status(self):
        def unavailable():
            result = self.snapshot()
            result["migration_idle"] = False
            return result
        result = self.helper.migration_step(self.verify(), "status", None, unavailable, self._run_candidate, self.save)
        self.assertEqual(result["phase"], "unknown")
        with self.assertRaises(ValueError): self.step("up", previous=result)

    def test_initial_unknown_state_and_intent_persistence_failure_never_run(self):
        self.read_error = True
        result = self.step("up")
        self.assertEqual(result["phase"], "unknown")
        self.assertFalse(any(isinstance(event, tuple) and event[0] == "run" for event in self.events))
        self.read_error, self.events = False, []
        def fail_save(record): raise OSError("disk full")
        with self.assertRaises(OSError): self.step("up", save=fail_save)
        self.assertFalse(any(isinstance(event, tuple) and event[0] == "run" for event in self.events))

    def test_status_is_read_only_and_failed_observation_does_not_clear_unknown(self):
        result = self.step("status")
        self.read_error = True
        result = self.step("status", previous=result)
        self.assertEqual(result["phase"], "unknown")
        self.assertIsNone(result["state"])
        self.assertFalse(any(isinstance(event, tuple) and event[0] == "run" for event in self.events))


if __name__ == "__main__":
    unittest.main()
