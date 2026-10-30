"""Isolated file fixtures only; no service, network, activation or database calls."""
import base64
import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

# control-api 的 Go 测试用 python3 -I 按文件路径加载本模块，-I 不把脚本目录放进 sys.path。
sys.path.insert(0, str(Path(__file__).resolve().parent))
from ed25519_tool_testing import host_ed25519_tool

CLICKHOUSE_MIGRATIONS = sorted((Path(__file__).resolve().parents[2] / "infra/clickhouse/migrations").glob("*.up.sql"))


def native_runtime_test_fixture(directory):
    source = Path(__file__).with_name("configure-control-runtime.py")
    spec = importlib.util.spec_from_file_location("native_control_runtime_fixture", source)
    runtime = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(runtime)
    runtime.ED25519_TOOL = host_ed25519_tool()
    directory = Path(directory).resolve()
    runtime.CONTROL = directory / "control"
    runtime.ANALYTICS = directory / "analytics"
    runtime.OBJECTSTORE = directory / "objectstore"
    runtime.LOOPBACK = directory / "clickhouse" / "cdnca-loopback.xml"
    runtime.TRUST = directory / "trust" / "cdnca-objectstore.crt"
    runtime.CA_BUNDLE = directory / "trust" / "ca-certificates.crt"
    runtime.OPENSSL = shutil.which("openssl")
    for path in (runtime.CONTROL, runtime.ANALYTICS, runtime.OBJECTSTORE,
                 runtime.LOOPBACK.parent, runtime.TRUST.parent):
        path.mkdir(mode=0o700)
    encoded = base64.b64encode(bytes(range(32))).decode()
    base = {
        "CONTROL_INSTALLATION_ID": "f31e4f7b-bc45-4dba-bdb9-644e507188ab",
        "CONTROL_INSTALLATION_NAME": "native isolated test",
        "EDGE_DEPLOYMENT_NATS_URL": "nats://127.0.0.1:4222",
        "NODE_PRESENCE_NATS_URL": "nats://127.0.0.1:4222",
        "NODE_PRESENCE_REDIS_URL": "redis://127.0.0.1:6379/0",
        "OPENRESTY_SECURITY_SECRET_KEY_BASE64": encoded,
        "DATABASE_URL": "postgresql://fixture@127.0.0.1/unused",
        "ACCESS_TOKEN_SECRET": "a" * 64,
        "API_KEY_PEPPER_VERSION": "fixture-v1", "API_KEY_PEPPER_BASE64": encoded,
        "DNS_CREDENTIAL_KEY_ID": "fixture-v1", "DNS_CREDENTIAL_KEY_BASE64": encoded,
        "CONTROL_INTERNAL_SERVER_CERT_FILE": "/unused/control.pem",
        "CONTROL_INTERNAL_SERVER_PRIVATE_KEY_FILE": "/unused/control.key",
        "CONTROL_INTERNAL_GATEWAY_CLIENT_CA_FILE": "/unused/gateway-ca.pem",
        "CONTROL_INTERNAL_GATEWAY_WORKLOAD_URI_SAN": "spiffe://cdn-platform/gateway/control",
        "NODE_CA_CERTIFICATE_CHAIN_FILE": "/unused/node-ca.pem",
        "NODE_CA_PRIVATE_KEY_FILE": "/unused/node-ca.key",
        "CONTROL_INSTALLATION_PRIVATE_KEY_FILE": "/unused/installation.key",
        "ANNOUNCEMENT_CURSOR_KEYS_JSON": "'{\"fixture\":\"" + encoded + "\"}'",
    }
    ch = {
        "CLICKHOUSE_URL": "http://127.0.0.1:8123", "CLICKHOUSE_DATABASE": "cdnca_analytics",
        "CLICKHOUSE_USERNAME": "cdnca_analytics_query", "CLICKHOUSE_PASSWORD": "a1" * 32,
        "ANALYTICS_INGEST_CLICKHOUSE_URL": "http://127.0.0.1:8123",
        "ANALYTICS_INGEST_CLICKHOUSE_DATABASE": "cdnca_analytics",
        "ANALYTICS_INGEST_CLICKHOUSE_USER": "cdnca_analytics_ingest",
        "ANALYTICS_INGEST_CLICKHOUSE_PASSWORD": "b2" * 32,
    }
    objects = {"endpoint": "https://127.0.0.1:19000", "region": "us-east-1", "bucket": "cdnca-assets",
               "users": {name: {"access_key": "cdnca-" + name, "secret_key": secret * 32, "prefix": name}
                         for name, secret in (("brand-assets", "c3"), ("error-pages", "d4"))}}
    ch_receipt = {"schema": "cdnca.native-clickhouse/v1", "version": "25.3.6.56",
                  "database": "cdnca_analytics", "rollup_definer": "cdnca_analytics_rollup",
                  "database_preflight": "passed", "rollups": runtime.ROLLUPS,
                  "migrations": [{"path": f"{index:03}_fixture.up.sql", "sha256": "ab" * 32}
                                 for index in range(1, len(CLICKHOUSE_MIGRATIONS) + 1)]}
    contents = {
        runtime.CONTROL / "control.env": "".join(f"{key}={value}\n" for key, value in base.items()),
        runtime.ANALYTICS / "runtime.env": "".join(f"{key}={value}\n" for key, value in ch.items()),
        runtime.ANALYTICS / "receipt.json": json.dumps(ch_receipt),
        runtime.ANALYTICS / "installed.json": json.dumps({"schema": "cdnca.native-clickhouse-install/v1", "version": "25.3.6.56"}),
        runtime.OBJECTSTORE / "runtime.json": json.dumps(objects),
        runtime.OBJECTSTORE / "installed.json": json.dumps(runtime.RUSTFS_RECEIPT),
    }
    certificate = subprocess.run([runtime.OPENSSL, "req", "-x509", "-newkey", "ed25519", "-nodes",
                                  "-subj", "/CN=Isolated runtime fixture/", "-days", "1", "-keyout", os.devnull],
                                 check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10).stdout
    for path, text in contents.items():
        path.write_text(text)
        path.chmod(0o600)
    for path, contents in ((runtime.OBJECTSTORE / "ca.crt", certificate), (runtime.TRUST, certificate),
                           (runtime.CA_BUNDLE, certificate), (runtime.LOOPBACK, runtime.LOOPBACK_CONTENT)):
        path.write_bytes(contents)
        path.chmod(0o600 if path == runtime.OBJECTSTORE / "ca.crt" else 0o644)
    return runtime


def runtime_receipt_fixture():
    return {"schema": "cdnca.native-rustfs/v1", "version": "1.0.1",
            "archive_sha256": "a834096dafa1f1a55825a2cdaf49d006a193978d344f2d508c2be475133738a3",
            "binary_sha256": "a5ac41209ca8eca6c591c1584cc108b308850e1b74955afd4af9fe1b0379f2eb",
            "endpoint": "https://127.0.0.1:19000"}


class NativeControlRuntimeTests(unittest.TestCase):
    def test_analytics_receipt_matches_configure_clickhouse(self):
        # The receipt configure-clickhouse.py writes on a fresh install must be
        # accepted as is: same rollups and the release's whole migration set
        # (a hand-copied ROLLUPS and a fixed count of 16 broke install-smoke S3).
        spec = importlib.util.spec_from_file_location("native_clickhouse_fixture", Path(__file__).with_name("configure-clickhouse.py"))
        clickhouse = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(clickhouse)
        with tempfile.TemporaryDirectory(prefix="cdnca-control-runtime-", dir="/tmp") as directory:
            runtime = native_runtime_test_fixture(directory)
            self.assertEqual(runtime.ROLLUPS, clickhouse.ROLLUPS)
            self.assertEqual(len(runtime.native_runtime_clickhouse_migrations()), len(CLICKHOUSE_MIGRATIONS))

    def test_object_store_receipt_accepts_static_musl_and_legacy_gnu_builds_only(self):
        legacy = {**json.loads(json.dumps(runtime_receipt_fixture())),
                  "archive_sha256": "9742e183cb0dfb0d48fa909797af572fe47b7f827569036baa4156e0d3958ee5",
                  "binary_sha256": "e6544a42a09a16d6fea47ad3d8aaa1a8793c9afa9c723bb8ae884f1238cd7c25"}
        mixed = {**legacy, "binary_sha256": runtime_receipt_fixture()["binary_sha256"]}
        for receipt, accepted in ((runtime_receipt_fixture(), True), (legacy, True), (mixed, False)):
            with self.subTest(binary=receipt["binary_sha256"][:8], accepted=accepted), \
                    tempfile.TemporaryDirectory(prefix="cdnca-control-runtime-", dir="/tmp") as directory:
                runtime = native_runtime_test_fixture(directory)
                path = runtime.OBJECTSTORE / "installed.json"
                path.write_text(json.dumps(receipt))
                path.chmod(0o600)
                if accepted:
                    runtime.native_runtime_inputs()
                else:
                    with self.assertRaisesRegex(ValueError, "object storage installation receipt mismatch"):
                        runtime.native_runtime_inputs()

    def test_native_runtime_contract(self):
        with tempfile.TemporaryDirectory(prefix="cdnca-control-runtime-", dir="/tmp") as directory:
            runtime = native_runtime_test_fixture(directory)
            base = runtime.CONTROL / "control.env"
            marker = Path(directory) / "must-not-execute"
            base.write_text(base.read_text().replace("native isolated test", f"$(touch {marker})"))
            before = base.read_bytes()
            with contextlib.redirect_stdout(io.StringIO()) as output, contextlib.redirect_stderr(io.StringIO()) as errors:
                runtime.native_control_runtime("install")
            self.assertEqual(output.getvalue() + errors.getvalue(), "")
            env = runtime.native_runtime_env((runtime.CONTROL / "runtime-extra.env").read_bytes())
            self.assertEqual(env.get("ANALYTICS_REALTIME_COVERAGE_FINALIZER_ENABLED"), "true")
            self.assertEqual(env.get("PACKAGE_TRAFFIC_ENFORCEMENT_ENABLED"), "true")
            # FX39: 更换节点通讯端口 works on a fresh native install (the two
            # NATS streams carry the gateway-port subjects, native-nats-profile.json).
            self.assertEqual(env.get("NODE_PORT_TRANSITION_RUNTIME_ENABLED"), "true")
            self.assertNotIn("PACKAGE_AUTO_RENEW_ENABLED", env)
            self.assertEqual(len(env), 51)
            self.assertEqual(env["ANALYTICS_REALTIME_RUNTIME_ENABLED"], "true")
            self.assertEqual(env["ANALYTICS_GEO_ARTIFACT_ENABLED"], "false")
            self.assertEqual(set(env), runtime.ENVIRONMENT_KEYS)
            self.assertEqual(env["EDGE_PUBLISH_RUNTIME_ENABLED"], "true")
            self.assertEqual(env["CDNCA_SECURITY_ACTIVATION_ENABLED"], "true")
            self.assertFalse(any(name.startswith(("PACKAGE_COMMERCE_", "PACKAGE_USAGE_")) for name in env))
            self.assertNotIn("CONTROL_INSTALLATION_PRIVATE_KEY_FILE", env)
            self.assertNotIn("OPENRESTY_SECURITY_SECRET_KEY_BASE64", env)
            self.assertEqual(base.read_bytes(), before)
            self.assertFalse(marker.exists())
            keys = [env[name] for name in runtime.SECRET_ENV_KEYS]
            keys.append(json.loads(env["EDGE_PUBLISH_CURSOR_KEYS_JSON"])[env["EDGE_PUBLISH_CURSOR_ACTIVE_KEY_ID"]])
            self.assertEqual(env["ANALYTICS_LOGS_CURSOR_ACTIVE_KEY_ID"], "native-analytics-logs-cursor-v1")
            logs_cursor = json.loads(env["ANALYTICS_LOGS_CURSOR_KEYS_JSON"])
            self.assertEqual(set(logs_cursor), {"native-analytics-logs-cursor-v1"})
            keys.append(logs_cursor[env["ANALYTICS_LOGS_CURSOR_ACTIVE_KEY_ID"]])
            self.assertEqual(len(set(keys)), 4)
            self.assertTrue(all(len(base64.b64decode(key, validate=True)) == 32 for key in keys))
            self.assertNotIn(runtime.native_runtime_env(before)["OPENRESTY_SECURITY_SECRET_KEY_BASE64"], keys)
            saved = {path: (path.read_bytes(), path.stat().st_mtime_ns)
                     for path in runtime.CONTROL.rglob("*") if path.is_file()}
            runtime.native_control_runtime("check")
            runtime.native_control_runtime("install")
            for path, original in saved.items():
                self.assertEqual((path.read_bytes(), path.stat().st_mtime_ns), original)
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o400 if path.name == "runtime-publisher-trust.json" else 0o600)
            self.assertEqual(stat.S_IMODE((runtime.CONTROL / "runtime-keys").stat().st_mode), 0o700)
            rejected = subprocess.run([sys.executable, "-I", "-B", str(Path(__file__).with_name("configure-control-runtime.py")),
                                       "check", "--secret", "SYNTHETIC-SECRET-MUST-NOT-PRINT"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
            self.assertNotEqual(rejected.returncode, 0)
            self.assertEqual(rejected.stdout, b"")
            self.assertNotIn(b"SYNTHETIC-SECRET", rejected.stderr)

        for failure in ("missing_receipt", "wrong_version", "duplicate_json", "duplicate_env", "wrong_query_role",
                        "shared_password", "wrong_endpoint", "wrong_prefix", "extra_provider", "missing_migration",
                        "world_readable", "hardlink", "symlink", "parent_symlink", "foreign_owner", "unsafe_parent",
                        "unsafe_loopback", "unsafe_trust", "unknown_state", "partial_state", "changed_dependency",
                        "changed_private_key", "tampered_extra", "changed_receipt", "extra_key_file", "wrong_key_mode",
                        "check_before_install", "openssl_failure", "reused_secret", "unknown_action", "fsync_failure",
                        "null_users", "list_users", "unknown_user_field", "null_migrations", "nul_environment",
                        "wrong_nats", "wrong_uuid", "wrong_existing_key", "wrong_bundle", "writable_trust"):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory(prefix="cdnca-control-runtime-", dir="/tmp") as directory:
                runtime = native_runtime_test_fixture(directory)
                source = runtime.ANALYTICS / "runtime.env"
                receipt = runtime.ANALYTICS / "receipt.json"
                if failure in {"changed_dependency", "changed_private_key", "tampered_extra", "changed_receipt", "extra_key_file", "wrong_key_mode"}:
                    runtime.native_control_runtime("install")
                if failure == "missing_receipt":
                    receipt.unlink()
                elif failure == "wrong_version":
                    receipt.write_text(receipt.read_text().replace("25.3.6.56", "25.3.6.55"))
                elif failure == "duplicate_json":
                    receipt.write_text(receipt.read_text().replace('{"schema":', '{"schema":"duplicate","schema":', 1))
                elif failure == "duplicate_env":
                    source.write_text(source.read_text() + "CLICKHOUSE_URL=http://127.0.0.1:8123\n")
                elif failure == "wrong_query_role":
                    source.write_text(source.read_text().replace("cdnca_analytics_query", "default"))
                elif failure == "shared_password":
                    source.write_text(source.read_text().replace("b2" * 32, "a1" * 32))
                elif failure == "wrong_endpoint":
                    source.write_text(source.read_text().replace("127.0.0.1", "192.0.2.4"))
                elif failure == "wrong_prefix":
                    path = runtime.OBJECTSTORE / "runtime.json"
                    path.write_text(path.read_text().replace('"prefix": "brand-assets"', '"prefix": "error-pages"'))
                elif failure == "extra_provider":
                    path = runtime.CONTROL / "control.env"
                    path.write_text(path.read_text() + "ANALYTICS_UNEXPECTED_SETTING=\n")
                elif failure == "missing_migration":
                    document = json.loads(receipt.read_text())
                    document["migrations"].pop()
                    receipt.write_text(json.dumps(document))
                elif failure == "null_migrations":
                    document = json.loads(receipt.read_text())
                    document["migrations"] = None
                    receipt.write_text(json.dumps(document))
                elif failure in {"null_users", "list_users", "unknown_user_field"}:
                    path = runtime.OBJECTSTORE / "runtime.json"
                    document = json.loads(path.read_text())
                    if failure == "unknown_user_field":
                        document["users"]["brand-assets"]["root-secret-key"] = "synthetic-forbidden"
                    else:
                        document["users"] = None if failure == "null_users" else ["brand-assets", "error-pages"]
                    path.write_text(json.dumps(document))
                elif failure == "nul_environment":
                    source.write_bytes(source.read_bytes() + b"BAD=\x00\n")
                elif failure in {"wrong_nats", "wrong_uuid", "wrong_existing_key"}:
                    path = runtime.CONTROL / "control.env"
                    old, new = {"wrong_nats": ("nats://127.0.0.1:4222", "nats://user:synthetic@127.0.0.1:4222"),
                                "wrong_uuid": ("f31e4f7b-bc45-4dba-bdb9-644e507188ab", "00000000-0000-0000-0000-000000000000"),
                                "wrong_existing_key": ("OPENRESTY_SECURITY_SECRET_KEY_BASE64=", "OPENRESTY_SECURITY_SECRET_KEY_BASE64=invalid")}[failure]
                    path.write_text(path.read_text().replace(old, new))
                elif failure == "world_readable":
                    source.chmod(0o644)
                elif failure in {"hardlink", "symlink"}:
                    target = source.with_name("kept.env")
                    source.rename(target)
                    if failure == "hardlink":
                        os.link(target, source)
                    else:
                        source.symlink_to(target)
                elif failure == "parent_symlink":
                    target = runtime.ANALYTICS.with_name("kept-analytics")
                    runtime.ANALYTICS.rename(target)
                    runtime.ANALYTICS.symlink_to(target)
                elif failure == "unsafe_parent":
                    runtime.ANALYTICS.chmod(0o777)
                elif failure == "unsafe_loopback":
                    runtime.LOOPBACK.write_bytes(runtime.LOOPBACK_CONTENT.replace(b"127.0.0.1", b"0.0.0.0"))
                elif failure == "unsafe_trust":
                    runtime.TRUST.write_bytes(b"not a certificate\n")
                elif failure == "wrong_bundle":
                    runtime.CA_BUNDLE.write_bytes(b"not a certificate\n")
                elif failure == "writable_trust":
                    runtime.TRUST.chmod(0o666)
                elif failure == "unknown_state":
                    (runtime.CONTROL / "runtime-extra.env").write_text("foreign data")
                elif failure == "partial_state":
                    (runtime.CONTROL / "runtime-keys").mkdir(mode=0o700)
                elif failure == "changed_dependency":
                    source.write_text(source.read_text().replace("a1" * 32, "a5" * 32))
                elif failure == "changed_private_key":
                    (runtime.CONTROL / "runtime-keys" / "edge-publish.pem").write_text("foreign key")
                elif failure == "tampered_extra":
                    path = runtime.CONTROL / "runtime-extra.env"
                    path.write_text(path.read_text().replace("ANALYTICS_INGEST_ENABLED='true'", "ANALYTICS_INGEST_ENABLED='false'"))
                elif failure == "changed_receipt":
                    path = runtime.CONTROL / "runtime-receipt.json"
                    path.write_text(path.read_text().replace("f31e4f7b-bc45-4dba-bdb9-644e507188ab", "another-installation"))
                elif failure == "extra_key_file":
                    (runtime.CONTROL / "runtime-keys" / "foreign.key").write_text("foreign")
                elif failure == "wrong_key_mode":
                    (runtime.CONTROL / "runtime-keys" / "edge-publish.pem").chmod(0o644)
                snapshots = {path: hashlib.sha256(path.read_bytes()).hexdigest()
                             for path in Path(directory).rglob("*") if path.is_file()}
                with contextlib.ExitStack() as stack:
                    if failure == "foreign_owner":
                        stack.enter_context(mock.patch.object(runtime.os, "geteuid", return_value=os.geteuid() + 1))
                    elif failure == "openssl_failure":
                        runtime.OPENSSL = "/nonexistent/openssl"
                    elif failure == "reused_secret":
                        stack.enter_context(mock.patch.object(runtime.secrets, "token_bytes", return_value=bytes(range(32))))
                    elif failure == "fsync_failure":
                        stack.enter_context(mock.patch.object(runtime.os, "fsync", side_effect=OSError("injected durability failure")))
                    action = "check" if failure == "check_before_install" else "unknown" if failure == "unknown_action" else "install"
                    with self.assertRaises((OSError, ValueError, KeyError, subprocess.SubprocessError)):
                        runtime.native_control_runtime(action)
                for path, digest in snapshots.items():
                    self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), digest)
                if failure not in {"changed_dependency", "changed_private_key", "tampered_extra", "changed_receipt", "extra_key_file", "wrong_key_mode", "unknown_state"}:
                    self.assertFalse((runtime.CONTROL / "runtime-extra.env").exists())


class TestNativeRuntimePortProfile(unittest.TestCase):
    def test_moved_clickhouse_ports_follow_the_host_profile(self):
        with tempfile.TemporaryDirectory() as directory:
            profile = Path(directory) / "runtime.env"
            profile.write_text("ENV=bt\nWEB_PORT=18443\nNODE_DOWNLOAD_PORT=19445\nCH_HTTP_PORT=18123\nCH_TCP_PORT=19100\n")
            source = Path(__file__).with_name("configure-clickhouse.py")
            spec = importlib.util.spec_from_file_location("native_clickhouse_profile_fixture", source)
            clickhouse = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(clickhouse)
            ports = clickhouse.native_clickhouse_ports(profile)
            self.assertEqual(clickhouse.native_clickhouse_http_url(ports), "http://127.0.0.1:18123")
            self.assertIn(b"<tcp_port>19100</tcp_port>", clickhouse.native_clickhouse_loopback_content(path=profile))
        runtime = importlib.util.module_from_spec(importlib.util.spec_from_file_location(
            "native_control_runtime_ports", Path(__file__).with_name("configure-control-runtime.py")))
        runtime.__spec__.loader.exec_module(runtime)
        # No profile on this host: the defaults stay byte-for-byte what earlier releases wrote.
        self.assertEqual(runtime.CLICKHOUSE_URL, "http://127.0.0.1:8123")
        self.assertEqual(runtime.LOOPBACK_CONTENT, runtime._clickhouse.LOOPBACK_DEFAULT)


if __name__ == "__main__":
    unittest.main()
