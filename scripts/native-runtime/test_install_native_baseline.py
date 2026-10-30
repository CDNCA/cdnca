"""Fresh native layout tests: only temporary Git repositories and host paths.

Set NATIVE_BASELINE_GO_TEST_BINARY to a Go integration test binary to run the
same adversarial archives through ValidateNativeReleaseArchive (not a runner).
"""

import base64
import contextlib
import copy
import fcntl
import gzip
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import stat
import struct
import subprocess
import tarfile
import tempfile
import unittest
from unittest import mock

from ed25519_tool_testing import host_ed25519_tool


class NativeBaselineTests(unittest.TestCase):
    def setUp(self):
        path = Path(__file__).with_name("install-native-baseline.py")
        spec = importlib.util.spec_from_file_location("native_baseline", path)
        self.helper = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.helper)
        self.helper.ED25519_TOOL = host_ed25519_tool()
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.input = self.root / "input"
        self.host = self.root / "host"
        self.input.mkdir(mode=0o700)
        self.host.mkdir(mode=0o700)
        self.git = self.input / "source.git"
        self.git_env = {"PATH": os.environ["PATH"], "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_NOSYSTEM": "1",
                        "GIT_AUTHOR_NAME": "Native Test", "GIT_AUTHOR_EMAIL": "native@example.invalid",
                        "GIT_COMMITTER_NAME": "Native Test", "GIT_COMMITTER_EMAIL": "native@example.invalid"}
        self.git_run("init", "--bare", "--template=", str(self.git))
        migration_entries = []
        for name, body in [("001_initial.up.sql", b"SELECT 1;\n"), ("001_initial.down.sql", b"SELECT 2;\n")]:
            digest = self.git_run("hash-object", "-w", "--stdin", input=body).strip()
            migration_entries.append(b"100644 blob " + digest + b"\t" + name.encode() + b"\n")
        tree = self.git_run("mktree", input=b"".join(migration_entries)).strip()
        for name in ("migrations", "control-api", "services"):
            tree = self.git_run("mktree", input=b"040000 tree " + tree + b"\t" + name.encode() + b"\n").strip()
        previous = self.git_run("commit-tree", tree.decode(), "-m", "previous").strip()
        commit = self.git_run("commit-tree", tree.decode(), "-p", previous.decode(), "-m", "candidate").strip()
        self.git_run("update-ref", "refs/heads/baseline", commit.decode())
        self.git_run("symbolic-ref", "HEAD", "refs/heads/baseline")
        executable = bytearray(64)
        executable[:7] = b"\x7fELF\x02\x01\x01"
        struct.pack_into("<HH", executable, 16, 2, 62)
        struct.pack_into("<H", executable, 52, 64)
        self.elf = bytes(executable)
        self.contents = {"bin/control-api": self.elf, "bin/agent-gateway": self.elf,
                         "static/web/index.html": b'<script src="/runtime-config.js"></script>',
                         "static/web/runtime-config.js": b"// default\n",
                         "migrations/001_initial.up.sql": b"SELECT 1;\n",
                         "migrations/001_initial.down.sql": b"SELECT 2;\n",
                         "clickhouse/configure-clickhouse.py": b"# helper\n",
                         "clickhouse/migrations/001_initial.up.sql": b"SELECT 3;\n"}
        self.manifest = {"schema": "cdnca.native-management.release/v1", "version": "2026.10.8",
                         "built_at": "2026-10-08T01:00:00Z", "platform": {"os": "linux", "arch": "amd64"},
                         "source": {"commit": commit.decode(), "tree": tree.decode(), "previous_commit": previous.decode()},
                         "files": [{"path": name, "sha256": hashlib.sha256(body).hexdigest(), "bytes": len(body),
                                    "mode": 0o755 if name.startswith("bin/") else 0o644}
                                   for name, body in sorted(self.contents.items())]}
        self.paths = {"OWNER": os.geteuid(), "ROOT": self.host / "release", "STATE": self.host / "state",
                      "STATUS": self.host / "status", "MAINTENANCE": self.host / "maintenance",
                      "CONFIG": self.host / "config", "LOCK": self.host / "release.lock",
                      "RUNNER_BINARY": self.host / "libexec/runner",
                      "RUNNER_UNIT": self.host / "systemd/cdnca-native-control-upgrade-runner.service"}
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(mock.patch.multiple(self.helper, **self.paths))
        self.stack.enter_context(mock.patch.object(self.helper, "SYSTEMD_DIRS", (self.host / "vendor-units",)))
        self.stack.enter_context(mock.patch.object(self.helper.platform, "system", return_value="Linux"))
        self.stack.enter_context(mock.patch.object(self.helper.platform, "machine", return_value="x86_64"))
        self.stack.enter_context(mock.patch.object(self.helper, "os_release", return_value={"ID": "ubuntu", "VERSION_ID": "24.04"}))
        self.stack.enter_context(mock.patch.object(self.helper.os, "chown"))
        self.runner = self.input / "runner"
        self.private(self.runner, self.elf)
        os.chmod(self.runner, 0o700)

    def git_run(self, *args, input=None):
        command = [shutil.which("git"), "--no-replace-objects"]
        if args[0] != "init":
            command.append("--git-dir=" + str(self.git))
        return subprocess.run(command + list(args), input=input, env=self.git_env, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, check=True, timeout=15).stdout

    def private(self, path, body):
        path.write_bytes(body)
        os.chmod(path, 0o600)
        return path

    def package(self, name="valid", mutate=None, extras=(), suffix=b"", encoded=None, gzip_archive=False):
        manifest, contents = copy.deepcopy(self.manifest), self.contents.copy()
        if mutate:
            mutate(manifest, contents)
        encoded = encoded or (json.dumps(manifest, separators=(",", ":")) + "\n").encode()
        archive = self.input / (name + ".tar")
        with tarfile.open(archive, "w", format=tarfile.PAX_FORMAT if name == "pax" else tarfile.USTAR_FORMAT) as package:
            for filename, body in [("release.manifest.json", encoded), *sorted(contents.items())]:
                header = tarfile.TarInfo(filename)
                header.mode = next((item["mode"] for item in manifest["files"] if item["path"] == filename), 0o644)
                header.size = len(body)
                if name == "pax":
                    header.pax_headers = {"comment": "not plain ustar"}
                package.addfile(header, io.BytesIO(body))
            for header in extras:
                package.addfile(header)
        archive_bytes = archive.read_bytes() + suffix
        if gzip_archive:
            archive_bytes = gzip.compress(archive_bytes)
        self.private(archive, archive_bytes)
        sidecar = self.private(self.input / (name + ".manifest.json"), encoded)
        inputs = {"schema": "cdnca.native-management.baseline-input/v1", "archive": str(archive),
                  "archive_sha256": hashlib.sha256(archive_bytes).hexdigest(), "archive_bytes": len(archive_bytes),
                  "manifest": str(sidecar), "manifest_sha256": hashlib.sha256(encoded).hexdigest(),
                  "source_commit": manifest["source"]["commit"], "source_tree": manifest["source"]["tree"],
                  **({"previous_source_commit": manifest["source"]["previous_commit"]} if "previous_commit" in manifest["source"] else {}),
                  "version": "2026.10.8",
                  "source_git": str(self.git), "runner": str(self.runner), "runner_sha256": hashlib.sha256(self.elf).hexdigest(),
                  "installation_id_file": str(self.paths["CONFIG"] / "installation-id"),
                  "runner_environment_file": str(self.paths["CONFIG"] / "runner-input.env")}
        filename = self.private(self.input / (name + ".inputs.json"), json.dumps(inputs).encode())
        return filename, inputs

    def archive_cases(self):
        cases = [("valid", {}, True),
                 ("unknown", {"mutate": lambda m, f: m.update(extra=True)}, False),
                 ("nested_unknown", {"mutate": lambda m, f: m["source"].update(extra=True)}, False),
                 ("duplicate_json", {"encoded": json.dumps(self.manifest).replace('"schema":', '"schema":"duplicate","schema":', 1).encode()}, False),
                 ("unsorted", {"mutate": lambda m, f: m["files"].reverse()}, False),
                 ("bad_mode", {"mutate": lambda m, f: m["files"][0].update(mode=0o700)}, False),
                 ("bad_version", {"mutate": lambda m, f: m.update(version="01.2.3")}, False),
                 ("missing", {"mutate": lambda m, f: f.pop("bin/agent-gateway")}, False),
                 ("extra", {"mutate": lambda m, f: f.update(unlisted=b"not in manifest")}, False),
                 ("tampered", {"mutate": lambda m, f: f.update({"bin/control-api": b"tampered"})}, False),
                 ("trailing", {"suffix": b"nonzero trailing bytes"}, False),
                 ("gzip", {"gzip_archive": True}, False), ("pax", {}, False)]
        for name, member, kind in [("traversal", "../escape", tarfile.REGTYPE), ("duplicate", "bin/control-api", tarfile.REGTYPE),
                                   ("symlink", "link", tarfile.SYMTYPE), ("hardlink", "hard", tarfile.LNKTYPE)]:
            header = tarfile.TarInfo(member)
            header.type, header.mode = kind, 0o644
            if kind != tarfile.REGTYPE:
                header.linkname = "bin/control-api"
            cases.append((name, {"extras": [header]}, False))
        return [(name, *self.package(name, **kwargs), accept) for name, kwargs, accept in cases]

    def signed_package(self, name="signed", change_signature=None, change_trust=None, mutate=None):
        # The bundled tool, not OpenSSL: 1.1.1 hosts have no "pkeyutl -rawin".
        private = self.input / "artifact-fixture.key"
        if not private.exists():
            subprocess.run([host_ed25519_tool(), "genkey", str(private)], check=True,
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        public = subprocess.check_output([host_ed25519_tool(), "pubkey", str(private)]).decode()
        trust = {"version": 1, "keys": [{"key_id": "fixture", "public_key_pem": public}]}
        if change_trust:
            change_trust(trust)
        trust_path = self.private(self.input / (name + ".trust.json"), json.dumps(trust).encode())
        def signed(manifest, contents):
            manifest.update(schema="cdnca.native-management.release/v2", key_id="fixture")
            if mutate:
                mutate(manifest, contents)
            encoded = (json.dumps(manifest, separators=(",", ":")) + "\n").encode()
            message = self.private(self.input / (name + ".message"), b"cdnca.native-management.release/v2\n" + encoded)
            signature = base64.b64encode(subprocess.check_output([host_ed25519_tool(), "sign", str(private), str(message)])) + b"\n"
            if change_signature:
                signature = change_signature(signature)
            if signature is not None:
                contents["release.manifest.sig"] = signature
        filename, inputs = self.package(name, mutate=signed)
        inputs["schema"] = "cdnca.native-management.baseline-input/v2"
        del inputs["source_git"]
        inputs["artifact_trust_file"] = str(trust_path)
        self.private(filename, json.dumps(inputs).encode())
        return filename, inputs

    def test_signed_v2_checks_stages_and_installs_without_git(self):
        filename, inputs = self.signed_package()
        shutil.rmtree(self.git)
        with mock.patch.object(self.helper, "git_command", side_effect=AssertionError("v2 must not invoke Git")):
            stage = self.input / "signed-stage"
            self.assertEqual(self.helper.check(filename, stage)["status"], "baseline_checked_not_activated")
            self.assertTrue((stage / "release.manifest.sig").is_file())
            self.activate_fixture()
            self.assertEqual(self.helper.install(filename)["status"], "baseline_prepared_not_started")
        self.assertFalse((self.paths["STATE"] / "source.git").exists())
        trust = self.paths["STATE"] / "artifact-trust.json"
        self.assertEqual(trust.read_bytes(), Path(inputs["artifact_trust_file"]).read_bytes())
        self.assertEqual(stat.S_IMODE(trust.stat().st_mode), 0o600)

    def test_signed_v2_initial_baseline_without_predecessor_installs(self):
        filename, inputs = self.signed_package("baseline", mutate=lambda manifest, contents: manifest["source"].pop("previous_commit"))
        self.assertNotIn("previous_source_commit", inputs)
        shutil.rmtree(self.git)
        with mock.patch.object(self.helper, "git_command", side_effect=AssertionError("v2 must not invoke Git")):
            self.assertEqual(self.helper.check(filename, self.input / "baseline-stage")["status"], "baseline_checked_not_activated")
            self.activate_fixture()
            self.assertEqual(self.helper.install(filename)["status"], "baseline_prepared_not_started")
        # The sidecar pin and the manifest must agree on having no predecessor.
        forged = dict(inputs, previous_source_commit="c" * 40)
        self.private(filename, json.dumps(forged).encode())
        with self.assertRaisesRegex(ValueError, "manifest pin mismatch"):
            self.helper.verify_inputs(filename)

    def test_signed_v2_rejects_invalid_proof_before_staging_or_formal_state(self):
        cases = [
            ("missing", {"change_signature": lambda _: None}),
            ("invalid", {"change_signature": lambda _: base64.b64encode(bytes(64))}),
            ("extra_newline", {"change_signature": lambda value: value + b"\n"}),
            ("wrong_key", {"change_trust": lambda trust: trust["keys"][0].update(key_id="other")}),
            ("duplicate_key", {"change_trust": lambda trust: trust["keys"].append(trust["keys"][0])}),
            ("unknown_trust", {"change_trust": lambda trust: trust.update(extra=True)}),
            ("unknown_manifest", {"mutate": lambda manifest, _: manifest.update(extra=True)}),
            ("tampered_binary", {"mutate": lambda _, files: files.update({"bin/control-api": b"tampered"})}),
            ("unpaired_migration", {"mutate": lambda manifest, _: manifest.update(files=[
                item for item in manifest["files"] if item["path"] != "migrations/001_initial.down.sql"])}),
        ]
        for name, options in cases:
            filename, _ = self.signed_package(name, **options)
            destination = self.input / (name + "-stage")
            with self.subTest(name=name), self.assertRaises((ValueError, KeyError, OSError)):
                self.helper.check(filename, destination)
            self.assertFalse(destination.exists())
        self.assertEqual(list(self.host.iterdir()), [])

    def test_signed_v2_rejects_changed_raw_manifest_and_untrusted_matching_key_id(self):
        filename, inputs = self.signed_package()
        sidecar = Path(inputs["manifest"])
        changed = sidecar.read_bytes() + b" "
        self.private(sidecar, changed)
        inputs["manifest_sha256"] = hashlib.sha256(changed).hexdigest()
        self.private(filename, json.dumps(inputs).encode())
        with self.assertRaises(ValueError):
            self.helper.check(filename)
        filename, inputs = self.signed_package("other-key")
        other = self.input / "different-private.key"
        subprocess.run(["openssl", "genpkey", "-algorithm", "ED25519", "-out", str(other)], check=True,
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        public = subprocess.check_output(["openssl", "pkey", "-in", str(other), "-pubout"]).decode()
        self.private(Path(inputs["artifact_trust_file"]), json.dumps({"version": 1, "keys": [
            {"key_id": "fixture", "public_key_pem": public}]}).encode())
        with self.assertRaisesRegex(ValueError, "signature mismatch"):
            self.helper.check(filename)
        self.assertEqual(list(self.host.iterdir()), [])

    def test_signed_v2_input_cannot_downgrade_to_v1_or_smuggle_git(self):
        filename, inputs = self.signed_package()
        for changed in ({**inputs, "schema": "cdnca.native-management.baseline-input/v1"},
                        {**inputs, "source_git": str(self.git)}):
            self.private(filename, json.dumps(changed).encode())
            with self.assertRaises(ValueError):
                self.helper.check(filename)

    def test_signed_v2_archives_against_go_validator_with_independent_trust(self):
        binary = os.environ.get("NATIVE_BASELINE_GO_TEST_BINARY")
        if not binary:
            self.skipTest("requires explicit NATIVE_BASELINE_GO_TEST_BINARY")
        cases, trust = [], None
        for name, options in [
            ("signed_valid", {}),
            ("signed_missing", {"change_signature": lambda _: None}),
            ("signed_invalid", {"change_signature": lambda _: base64.b64encode(bytes(64))}),
            ("signed_newline", {"change_signature": lambda signature: signature + b"\n"}),
            ("signed_unknown", {"mutate": lambda manifest, _: manifest.update(extra=True)}),
            ("signed_unsorted", {"mutate": lambda manifest, _: manifest["files"].reverse()}),
            ("signed_platform", {"mutate": lambda manifest, _: manifest["platform"].update(arch="arm64")}),
            ("signed_time", {"mutate": lambda manifest, _: manifest.update(built_at="invalid")}),
            ("signed_tampered", {"mutate": lambda _, files: files.update({"bin/control-api": b"tampered"})}),
            ("signed_unlisted", {"mutate": lambda _, files: files.update(unlisted=b"forbidden")}),
        ]:
            filename, inputs = self.signed_package(name, **options)
            accept = name == "signed_valid"
            if accept:
                trust = inputs["artifact_trust_file"]
                self.helper.check(filename)
            else:
                with self.subTest(name=name), self.assertRaises((ValueError, KeyError, OSError)):
                    self.helper.check(filename)
            cases.append({"name": name, "version": inputs["version"], "digest": inputs["archive_sha256"],
                          "size": inputs["archive_bytes"], "accept": accept})
        self.private(self.input / "cases.json", json.dumps(cases).encode())
        result = subprocess.run([binary, "-test.run=^TestNativeBaselineArchiveCrossValidation$", "-test.v", "-test.count=1"],
                                env={"PATH": os.environ["PATH"], "NATIVE_BASELINE_ARCHIVE_FIXTURES": str(self.input),
                                     "NATIVE_BASELINE_ARTIFACT_TRUST_FILE": trust},
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn("executed 10 native baseline archive fixtures", result.stdout)
        self.assertNotIn("SKIP", result.stdout)
        print(result.stdout)

    def activate_fixture(self):
        config = self.paths["CONFIG"]
        config.mkdir(mode=0o700)
        self.private(config / "installation-id", b"3d519c71-4bdb-4e61-82a8-5312c6b47f21\n")
        self.private(config / "runner-input.env", b"CONTROL_UPGRADE_TARGET=native-standalone\n")

    def test_check_succeeds_before_activation_without_writing_formal_state(self):
        filename, inputs = self.package()
        self.assertFalse(self.paths["CONFIG"].exists())
        result = self.helper.check(filename)
        self.assertEqual(result["archive_sha256"], inputs["archive_sha256"])
        self.assertEqual(list(self.host.iterdir()), [])

    def test_archive_contract_rejects_malicious_complete_fixtures(self):
        for name, filename, _, accept in self.archive_cases():
            with self.subTest(name=name):
                if accept:
                    self.helper.check(filename)
                else:
                    with self.assertRaises((ValueError, OSError, tarfile.TarError)):
                        self.helper.check(filename)
        self.assertEqual(list(self.host.iterdir()), [])

    def test_first_baseline_accepts_only_known_clickhouse_components(self):
        for path in ("clickhouse/migrations/001_initial.down.sql", "clickhouse/other.py"):
            with self.subTest(path=path):
                def mutate(manifest, contents, path=path):
                    contents[path] = b"x\n"
                    manifest["files"].append({"path": path, "sha256": hashlib.sha256(b"x\n").hexdigest(), "bytes": 2, "mode": 0o644})
                    manifest["files"].sort(key=lambda item: item["path"])
                filename = self.package(path.replace("/", "_"), mutate=mutate)[0]
                with self.assertRaisesRegex(ValueError, "first-baseline"):
                    self.helper.check(filename)

    def with_file(self, path, body=b"# recovery\n", mode=0o644):
        def mutate(manifest, contents):
            contents[path] = body
            manifest["files"].append({"path": path, "sha256": hashlib.sha256(body).hexdigest(), "bytes": len(body), "mode": mode})
            manifest["files"].sort(key=lambda item: item["path"])
        return mutate

    def test_first_baseline_installs_recovery_runbook_where_installer_points(self):
        # install-control.sh prints ${NATIVE_ROOT}/current/docs/platform-admin-recovery.md; NATIVE_ROOT == ROOT.
        filename, _ = self.package("runbook", mutate=self.with_file("docs/platform-admin-recovery.md"))
        self.helper.check(filename)
        self.activate_fixture()
        self.helper.install(filename)
        runbook = self.paths["ROOT"] / "current/docs/platform-admin-recovery.md"
        self.assertEqual(runbook.read_bytes(), b"# recovery\n")
        self.assertEqual(stat.S_IMODE(runbook.stat().st_mode), 0o644)

    def test_first_baseline_rejects_other_docs_and_executable_runbook(self):
        for name, mutate in (("other", self.with_file("docs/other.md")),
                             ("nested", self.with_file("docs/runbooks/platform-admin-recovery.md")),
                             ("exec", self.with_file("docs/platform-admin-recovery.md", mode=0o755))):
            with self.subTest(name=name):
                filename = self.package("docs_" + name, mutate=mutate)[0]
                with self.assertRaisesRegex(ValueError, "first-baseline"):
                    self.helper.check(filename)

    def test_rejection_message_carries_reason(self):
        filename = self.package("docs_reason", mutate=self.with_file("docs/other.md"))[0]
        stderr = io.StringIO()
        with mock.patch.object(self.helper.sys, "argv", ["install-native-baseline.py", "check", "--inputs", str(filename)]), \
                contextlib.redirect_stderr(stderr):
            self.assertEqual(self.helper.main(), 1)
        self.assertIn("native baseline rejected", stderr.getvalue())
        self.assertIn("not a first-baseline component", stderr.getvalue())

    def test_same_archives_against_existing_go_validator(self):
        binary = os.environ.get("NATIVE_BASELINE_GO_TEST_BINARY")
        if not binary:
            self.skipTest("requires explicit NATIVE_BASELINE_GO_TEST_BINARY")
        cases = [{"name": name, "version": inputs["version"], "digest": inputs["archive_sha256"],
                  "size": inputs["archive_bytes"], "accept": accept}
                 for name, _, inputs, accept in self.archive_cases()]
        self.private(self.input / "cases.json", json.dumps(cases).encode())
        result = subprocess.run([binary, "-test.run=^TestNativeBaselineArchiveCrossValidation$", "-test.v", "-test.count=1"],
                                env={"PATH": os.environ["PATH"], "NATIVE_BASELINE_ARCHIVE_FIXTURES": str(self.input)},
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn("executed 17 native baseline archive fixtures", result.stdout)
        self.assertNotIn("SKIP", result.stdout)
        print(result.stdout)

    def test_source_tree_ancestry_and_complete_migrations_are_required(self):
        changes = {
            "tree": lambda value: value.update(source_tree="f" * 40),
            "same_source": lambda value: value.update(previous_source_commit=value["source_commit"]),
            "commit": lambda value: value.update(source_commit="e" * 40),
        }
        for name, change in changes.items():
            with self.subTest(name=name):
                filename, inputs = self.package(name)
                change(inputs)
                self.private(filename, json.dumps(inputs).encode())
                with self.assertRaises(ValueError):
                    self.helper.check(filename)
        for name in ("missing_migration", "changed_migration"):
            def mutate(manifest, files):
                target = "migrations/001_initial.down.sql"
                if name == "missing_migration":
                    files.pop(target)
                    manifest["files"] = [item for item in manifest["files"] if item["path"] != target]
                else:
                    files[target] = b"SELECT 9;\n"
                    for item in manifest["files"]:
                        if item["path"] == target:
                            item.update(sha256=hashlib.sha256(files[target]).hexdigest(), bytes=len(files[target]))
            filename, _ = self.package(name, mutate=mutate)
            with self.subTest(name=name), self.assertRaises(ValueError):
                self.helper.check(filename)
        # Mutate both authenticated pins and the manifest, so Git itself must
        # reject the source rather than an earlier sidecar/input mismatch.
        orphan = self.git_run("commit-tree", self.manifest["source"]["tree"], "-m", "unrelated").decode().strip()
        for name, key, value, message in [("actual_wrong_tree", "tree", "f" * 40, "source tree mismatch"),
                                           ("actual_nonancestor", "previous_commit", orphan, "offline Git validation failed")]:
            filename, inputs = self.package(name, mutate=lambda m, f: m["source"].update({key: value}))
            inputs["source_tree" if key == "tree" else "previous_source_commit"] = value
            self.private(filename, json.dumps(inputs).encode())
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, message):
                self.helper.check(filename)

    def test_git_cannot_delegate_objects_replace_history_or_fetch(self):
        filename, _ = self.package()
        for name, path, body in [("shallow", "shallow", self.manifest["source"]["commit"].encode()),
                                 ("alternates", "objects/info/alternates", b"/tmp/untrusted"),
                                 ("grafts", "info/grafts", b"untrusted"),
                                 ("promisor", "objects/pack/test.promisor", b""),
                                 ("replacement", "refs/replace/test", b"untrusted"),
                                 ("common_directory", "commondir", b"/tmp/untrusted"),
                                 ("external_git_directory", "gitdir", b"/tmp/untrusted"),
                                 ("worktree_config", "config.worktree", b"[core]\n")]:
            target = self.git / path
            target.parent.mkdir(parents=True, exist_ok=True)
            self.private(target, body)
            try:
                with self.subTest(name=name), mock.patch.object(self.helper, "git_command", wraps=self.helper.git_command) as git:
                    with self.assertRaises(ValueError):
                        self.helper.check(filename)
                    git.assert_not_called()
            finally:
                target.unlink()
                if name == "replacement":
                    target.parent.rmdir()

    def test_input_paths_must_be_canonical_before_pathlib_normalizes_them(self):
        filename, inputs = self.package()
        for name, value in [("archive", str(self.input) + "/./valid.tar"),
                            ("source_git", str(self.input) + "//source.git"),
                            ("runner", str(self.input) + "/../input/runner"),
                            ("installation_id_file", str(self.paths["CONFIG"]) + "/./installation-id")]:
            self.private(filename, json.dumps({**inputs, name: value}).encode())
            with self.subTest(name=name), self.assertRaises(ValueError):
                self.helper.check(filename)

    def test_stage_is_private_and_never_uses_an_existing_or_formal_path(self):
        filename, inputs = self.package()
        destination = self.input / "verified-stage"
        result = self.helper.check(filename, destination)
        self.assertEqual(result["stage_directory"], str(destination))
        self.assertEqual(stat.S_IMODE(destination.stat().st_mode), 0o700)
        self.assertEqual((destination / "bin/control-api").read_bytes(), self.elf)
        self.assertFalse(self.paths["ROOT"].exists())
        symlink = self.input / "stage-link"
        symlink.symlink_to(destination, target_is_directory=True)
        for path in (destination, symlink, self.paths["ROOT"], self.root / "outside-input"):
            with self.subTest(path=path.name), self.assertRaises((ValueError, OSError)):
                self.helper.check(filename, path)
        self.assertEqual((destination / "bin/control-api").read_bytes(), self.elf)
        for name in ("ROOT", "RUNNER_BINARY", "RUNNER_UNIT"):
            destination = self.input / ("formal-parent-" + name.lower())
            with mock.patch.object(self.helper, name, destination / "must-not-create"), self.subTest(name=name):
                with self.assertRaises(ValueError):
                    self.helper.check(filename, destination)
            self.assertFalse(destination.exists())

    def test_install_publishes_one_real_current_and_no_fake_runtime_state(self):
        filename, inputs = self.package()
        self.activate_fixture()
        result = self.helper.install(filename)
        current = self.paths["ROOT"] / "current"
        destination = self.paths["ROOT"] / "releases" / inputs["archive_sha256"]
        self.assertEqual(os.readlink(current), str(destination))
        self.assertEqual((destination / "bin/control-api").read_bytes(), self.elf)
        self.assertEqual(stat.S_IMODE(destination.stat().st_mode), 0o755)
        self.assertEqual(result["status"], "baseline_prepared_not_started")
        self.assertFalse((self.paths["ROOT"] / "previous").exists())
        self.assertEqual(list(self.paths["STATUS"].iterdir()), [])
        self.assertFalse((self.paths["STATE"] / "state.json").exists())
        self.assertFalse((self.paths["STATE"] / "last-known-plan.json").exists())
        self.assertFalse(self.paths["RUNNER_BINARY"].exists())
        self.assertFalse(self.paths["RUNNER_UNIT"].exists())
        self.assertEqual(stat.S_IMODE(self.paths["RUNNER_BINARY"].parent.stat().st_mode), 0o755)
        self.assertEqual(stat.S_IMODE(self.paths["RUNNER_UNIT"].parent.stat().st_mode), 0o755)
        maintenance = json.loads((self.paths["MAINTENANCE"] / "maintenance.json").read_bytes())
        self.assertEqual((maintenance["phase"], maintenance["plan_id"]), ("active", ""))
        self.assertEqual(stat.S_IMODE(self.paths["STATUS"].stat().st_mode), 0o2750)
        source_env = (self.paths["CONFIG"] / "native-baseline-source.env").read_text()
        self.assertIn("NATIVE_BASELINE_SOURCE_COMMIT=" + inputs["source_commit"], source_env)
        self.assertNotIn("ENABLED", source_env)
        with self.assertRaises(ValueError):
            self.helper.install(filename)

    def test_install_refuses_activation_missing_existing_state_and_lock_contention(self):
        filename, _ = self.package()
        with self.assertRaises((ValueError, OSError)):
            self.helper.install(filename)
        self.assertEqual(list(self.host.iterdir()), [])
        self.activate_fixture()
        root = self.paths["ROOT"]
        root.mkdir()
        keep = root / "previous"
        keep.symlink_to("preserve-unrelated-owner")
        with self.assertRaises(ValueError):
            self.helper.install(filename)
        self.assertEqual(os.readlink(keep), "preserve-unrelated-owner")
        keep.unlink()
        root.rmdir()
        with open(self.paths["LOCK"], "wb") as lock:
            os.chmod(self.paths["LOCK"], 0o600)
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with self.assertRaises((BlockingIOError, ValueError)):
                self.helper.install(filename)
        self.assertFalse(root.exists())

    def test_failed_sync_does_not_publish_current_or_remove_other_owners(self):
        filename, _ = self.package()
        self.activate_fixture()
        with mock.patch.object(self.helper, "sync_directory", side_effect=OSError("fixture fsync failure")):
            with self.assertRaises(OSError):
                self.helper.install(filename)
        self.assertFalse(os.path.lexists(self.paths["ROOT"] / "current"))
        self.assertFalse(os.path.lexists(self.paths["ROOT"] / "previous"))

    def test_existing_runner_units_dropins_and_enablement_reject_before_activation(self):
        filename, _ = self.package()
        directory = self.paths["RUNNER_UNIT"].parent
        directory.mkdir()
        for parent, relative in ((directory, "cdnca-native-control-upgrade-runner.service"),
                                 (directory, "cdnca-control-upgrade-runner.service.d"),
                                 (directory, "multi-user.target.wants/cdnca-native-control-upgrade-runner.service"),
                                 (directory, "test.target.requires/cdnca-control-upgrade-runner.service"),
                                 (self.helper.SYSTEMD_DIRS[0], "cdnca-control-upgrade-runner.service")):
            target = parent / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.symlink_to("preserve-unrelated-unit")
            try:
                with self.subTest(relative=relative), self.assertRaises(ValueError):
                    self.helper.check(filename)
                self.assertEqual(os.readlink(target), "preserve-unrelated-unit")
            finally:
                target.unlink()
        self.assertFalse(self.paths["ROOT"].exists())

    def test_late_directory_sync_failure_removes_only_owned_current(self):
        filename, _ = self.package()
        self.activate_fixture()
        current = self.paths["ROOT"] / "current"
        original = self.helper.sync_directory
        def fail_after_publication(directory):
            if directory == self.paths["ROOT"] and os.path.lexists(current):
                raise OSError("fixture late sync failure")
            return original(directory)
        with mock.patch.object(self.helper, "sync_directory", side_effect=fail_after_publication):
            with self.assertRaises(OSError):
                self.helper.install(filename)
        self.assertFalse(os.path.lexists(current))
        self.assertFalse(os.path.lexists(self.paths["ROOT"] / "previous"))

    def test_current_publication_never_overwrites_a_competing_current(self):
        filename, _ = self.package()
        self.activate_fixture()
        current = self.paths["ROOT"] / "current"
        original = self.helper.os.link
        def competing_link(source, destination, **options):
            if destination == current:
                current.symlink_to("preserve-competitor")
            return original(source, destination, **options)
        with mock.patch.object(self.helper.os, "link", side_effect=competing_link):
            with self.assertRaises(FileExistsError):
                self.helper.install(filename)
        self.assertEqual(os.readlink(current), "preserve-competitor")
        self.assertFalse(os.path.lexists(self.paths["ROOT"] / "previous"))

    def test_failure_immediately_after_publishing_current_does_not_leave_current(self):
        filename, _ = self.package()
        self.activate_fixture()
        current = self.paths["ROOT"] / "current"
        original = Path.lstat
        failed = False
        def fail_once_after_publication(path):
            nonlocal failed
            if path == current and os.path.lexists(path) and not failed:
                failed = True
                raise OSError("fixture post-publish stat failure")
            return original(path)
        with mock.patch.object(Path, "lstat", fail_once_after_publication):
            try:
                self.helper.install(filename)
            except OSError:
                self.assertFalse(os.path.lexists(current))
            else:
                self.assertFalse(failed)
        if not failed:
            self.assertTrue(current.is_symlink())

    def test_runner_and_control_elf_are_independently_required_after_correct_hashes(self):
        filename, inputs = self.package()
        self.private(self.runner, b"not a native runner")
        os.chmod(self.runner, 0o700)
        inputs["runner_sha256"] = hashlib.sha256(self.runner.read_bytes()).hexdigest()
        self.private(filename, json.dumps(inputs).encode())
        with self.assertRaisesRegex(ValueError, "runner ELF"):
            self.helper.check(filename)
        self.private(self.runner, self.elf)
        os.chmod(self.runner, 0o700)
        def wrong_elf(manifest, files):
            target = "bin/control-api"
            body = bytearray(files[target])
            struct.pack_into("<H", body, 18, 183)  # Correctly hashed ARM64 is not this profile.
            files[target] = bytes(body)
            for item in manifest["files"]:
                if item["path"] == target:
                    item["sha256"] = hashlib.sha256(body).hexdigest()
        filename, _ = self.package("arm64_control", mutate=wrong_elf)
        with self.assertRaisesRegex(ValueError, "native ELF"):
            self.helper.check(filename)

    def test_source_config_and_missing_reachable_history_fail_closed(self):
        filename, _ = self.package()
        config = self.git / "config"
        original = config.read_bytes()
        for section in (b'[remote "origin"]\nurl = https://example.invalid/source.git\n',
                        b'[include]\npath = /tmp/untrusted\n', b'[extensions]\nworktreeConfig = true\n'):
            self.private(config, original + section)
            with self.subTest(section=section.splitlines()[0]), mock.patch.object(self.helper, "git_command") as git:
                with self.assertRaisesRegex(ValueError, "self-contained bare"):
                    self.helper.check(filename)
                git.assert_not_called()
        self.private(config, original)
        previous = self.manifest["source"]["previous_commit"]
        (self.git / "objects" / previous[:2] / previous[2:]).unlink()
        with self.assertRaisesRegex(ValueError, "offline Git validation failed"):
            self.helper.check(filename)

    def test_install_directory_modes_survive_private_umask(self):
        filename, _ = self.package()
        self.activate_fixture()
        previous = os.umask(0o077)
        try:
            self.helper.install(filename)
        finally:
            os.umask(previous)
        for path in (self.paths["ROOT"], self.paths["ROOT"] / "current/static/web",
                     self.paths["ROOT"] / "current/bin", self.paths["RUNNER_BINARY"].parent):
            with self.subTest(path=path):
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o755)

    def test_input_duplicate_keys_symlinks_fifos_and_untrusted_modes_fail_closed(self):
        filename, inputs = self.package()
        encoded = filename.read_bytes()
        self.private(filename, encoded[:-1] + b',"version":"2026.10.8"}')
        with self.assertRaises(ValueError):
            self.helper.check(filename)
        self.private(filename, encoded)
        original = Path(inputs["archive"])
        original.rename(original.with_suffix(".saved"))
        for kind in ("symlink", "fifo"):
            if kind == "symlink":
                original.symlink_to(original.with_suffix(".saved"))
            else:
                os.mkfifo(original, 0o600)
            try:
                with self.subTest(kind=kind), self.assertRaises((ValueError, OSError)):
                    self.helper.check(filename)
            finally:
                original.unlink()
        original.with_suffix(".saved").rename(original)
        os.chmod(filename, 0o644)
        with self.assertRaises(ValueError):
            self.helper.check(filename)


if __name__ == "__main__":
    unittest.main()
