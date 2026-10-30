"""Isolated filesystem tests with real OpenSSL; no nginx/systemd/network calls."""

import base64
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import tempfile
import unittest
from unittest import mock


class NativeUpgradeConfigurationTests(unittest.TestCase):
    def setUp(self):
        path = Path(__file__).with_name("configure-native-upgrade.py")
        spec = importlib.util.spec_from_file_location("native_upgrade_config", path)
        self.helper = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.helper)
        self.temp = tempfile.TemporaryDirectory(prefix="native-upgrade-test-", dir=Path(__file__).resolve().parent)
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.config = self.root / "upgrade"
        self.trust = self.root / "entitlement-trusted-keys.json"
        self.public = base64.urlsafe_b64encode(bytes(range(32))).decode().rstrip("=")
        self.trust.write_text(json.dumps({"keys": [{"key_id": "fixture-key", "public_key": self.public}]}))
        os.chmod(self.trust, 0o644)
        self.installation = "3d519c71-4bdb-4e61-82a8-5312c6b47f21"
        self.url = "https://cdnca.example:8443/dashboard/"
        executable = shutil.which("openssl")
        self.assertIsNotNone(executable, "real OpenSSL 3 is required; do not count a skip as validation")
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(mock.patch.multiple(self.helper, OWNER=os.geteuid(), CONFIG=self.config,
                                                    TRUST_SOURCE=self.trust, OPENSSL=executable))
        self.stack.enter_context(mock.patch.object(self.helper.platform, "system", return_value="Linux"))
        self.stack.enter_context(mock.patch.object(self.helper.platform, "machine", return_value="x86_64"))
        self.stack.enter_context(mock.patch.object(self.helper, "os_release",
                                                   return_value={"ID": "ubuntu", "VERSION_ID": "24.04"}))

    def snapshot(self):
        return {path.name: (path.read_bytes(), path.stat().st_mode, path.stat().st_mtime_ns)
                for path in self.config.iterdir()}

    def replace_certificate(self, role, *, purpose="serverAuth", san="127.0.0.1", days="365"):
        # CSR + x509 -req -extfile: the same OpenSSL 1.0.2-3.x form as the helper.
        scratch = Path(tempfile.mkdtemp(prefix="native-upgrade-fixture-"))
        self.addCleanup(shutil.rmtree, scratch)
        (scratch / "req.cnf").write_text("[req]\ndistinguished_name = dn\n[dn]\nCN = Common Name\n")
        extensions = ["basicConstraints=critical,CA:FALSE", "keyUsage=critical,digitalSignature",
                      "subjectKeyIdentifier=hash", "authorityKeyIdentifier=keyid:always", "extendedKeyUsage=" + purpose]
        if san:
            extensions.append("subjectAltName=IP:" + san)
        (scratch / "cert.ext").write_text("".join(line + "\n" for line in extensions))
        key = str(self.config / ("plan-source-" + role + "-key.pem"))
        (scratch / "cert.csr").write_bytes(self.helper.openssl("req", "-new", "-batch", "-config", scratch / "req.cnf",
                                                                "-key", key, "-sha256", "-subj", "/CN=fixture"))
        body = self.helper.openssl("x509", "-req", "-in", scratch / "cert.csr", "-sha256", "-days", days, "-set_serial", "41",
                                   "-CA", str(self.config / "plan-source-ca.pem"),
                                   "-CAkey", str(self.config / "plan-source-ca-key.pem"), "-extfile", scratch / "cert.ext")
        (self.config / ("plan-source-" + role + ".pem")).write_bytes(body)

    def test_prepare_and_check_real_certificates_are_private_readonly_and_separate(self):
        self.assertEqual(self.helper.prepare(self.installation, self.url)["status"], "prepared_not_started")
        expected = {"installation-id", "trusted-keys.json", "plan-source-token", "runner-input.env", "api.env",
                    "plan-source-nginx.conf", *("plan-source-" + role + suffix for role in ("ca", "server", "client")
                                                for suffix in (".pem", "-key.pem"))}
        self.assertEqual(set(path.name for path in self.config.iterdir()), expected)
        self.assertEqual(stat.S_IMODE(self.config.stat().st_mode), 0o700)
        for path in self.config.iterdir():
            self.assertEqual((stat.S_IMODE(path.stat().st_mode), path.stat().st_nlink), (0o600, 1))
        before = self.snapshot()
        self.assertEqual(self.helper.check(self.installation, self.url)["status"], "configuration_checked")
        self.assertEqual(self.snapshot(), before)
        self.assertEqual(set(path.name for path in self.root.iterdir()), {"upgrade", self.trust.name})
        self.assertRegex((self.config / "plan-source-token").read_text(), r"^[0-9a-f]{64}\n$")
        self.assertEqual(len({before["plan-source-" + role + "-key.pem"][0] for role in ("ca", "server", "client")}), 3)

    def test_environment_contract_is_exact_and_separates_api_from_runner(self):
        self.helper.prepare(self.installation, self.url)
        runner = dict(line.split("=", 1) for line in (self.config / "runner-input.env").read_text().splitlines())
        api = dict(line.split("=", 1) for line in (self.config / "api.env").read_text().splitlines())
        runner_keys = {"CONTROL_UPGRADE_" + suffix for suffix in (
            "TARGET", "ONESHOT", "STATE_DIR", "RELEASE_ROOT", "PLAN_LKG_FILE", "INSTALLATION_ID_FILE", "TRUST_FILE",
            "INTERNAL_TOKEN_FILE", "PLAN_SOURCE_CA_FILE", "PLAN_SOURCE_CERT_FILE", "PLAN_SOURCE_KEY_FILE",
            "PLAN_SOURCE_TIMEOUT", "POLL_INTERVAL", "STEP_TIMEOUT", "HEALTH_TIMEOUT", "PROTOCOL_VERSION",
            "PLAN_SOURCE_MAX_BYTES", "PLAN_SOURCE_URL")}
        runner_keys |= {"CDNCA_NATIVE_UPGRADE_" + suffix for suffix in (
            "STATUS_FILE", "MAINTENANCE_FILE", "RELEASE_LOCK_FILE", "SOURCE_GIT_DIR", "CONTROL_UNIT", "GATEWAY_UNIT",
            "CONTROL_HEALTH_URL", "GATEWAY_HEALTH_URL", "WEB_INDEX_URL")}
        api_keys = {"CDNCA_NATIVE_UPGRADE_" + suffix for suffix in ("ENABLED", "STATUS_FILE", "STATE_FILE", "MAINTENANCE_FILE")}
        api_keys |= {"CONTROL_UPGRADE_" + suffix for suffix in (
            "PLAN_WRITER_ENABLED", "SYSTEMD_PLAN_SOURCE_ENABLED", "INTERNAL_TOKEN_FILE", "PROTOCOL_VERSION")}
        self.assertEqual(set(runner), runner_keys)
        self.assertEqual(set(api), api_keys)
        self.assertEqual(runner["CONTROL_UPGRADE_PROTOCOL_VERSION"], "1")
        self.assertEqual(api["CONTROL_UPGRADE_PROTOCOL_VERSION"], "1")
        self.assertEqual(runner["CONTROL_UPGRADE_HEALTH_TIMEOUT"], "2m")
        self.assertEqual(runner["CONTROL_UPGRADE_PLAN_SOURCE_URL"], "https://127.0.0.1:9445/v1/internal/control-upgrade/plan")
        self.assertEqual(runner["CDNCA_NATIVE_UPGRADE_WEB_INDEX_URL"], self.url)
        self.assertEqual(api["CDNCA_NATIVE_UPGRADE_STATE_FILE"], "/run/cdnca-upgrade/status.json.state.json")
        for filename in ("api.env", "runner-input.env"):
            for line in (self.config / filename).read_text().splitlines():
                self.assertRegex(line, r"^[A-Z0-9_]+=[A-Za-z0-9_./:@%?=+\[\]\-]+$")

    def test_signed_artifact_profile_selects_independent_trust_not_git(self):
        artifact = self.root / "artifact-trust.json"
        der = bytes.fromhex("302a300506032b6570032100") + bytes(range(32))
        pem = "-----BEGIN PUBLIC KEY-----\n" + base64.b64encode(der).decode() + "\n-----END PUBLIC KEY-----\n"
        body = json.dumps({"version": 1, "keys": [{"key_id": "artifact-fixture", "public_key_pem": pem}]}).encode()
        artifact.write_bytes(body)
        os.chmod(artifact, 0o600)
        self.assertEqual(self.helper.prepare(self.installation, self.url, artifact)["status"], "prepared_not_started")
        environment = (self.config / "runner-input.env").read_text()
        self.assertIn("CDNCA_NATIVE_UPGRADE_ARTIFACT_TRUST_FILE=/var/lib/cdnca-upgrade/artifact-trust.json\n", environment)
        self.assertNotIn("SOURCE_GIT_DIR", environment)
        self.assertEqual(artifact.read_bytes(), body)
        self.assertEqual(self.helper.check(self.installation, self.url, artifact)["status"], "configuration_checked")
        with self.assertRaises(ValueError):
            self.helper.check(self.installation, self.url)
        artifact.write_text('{"version":1,"keys":[]}')
        with self.assertRaises(ValueError):
            self.helper.check(self.installation, self.url, artifact)

    def self_signed(self, name):
        scratch = Path(tempfile.mkdtemp(prefix="native-upgrade-webca-"))
        self.addCleanup(shutil.rmtree, scratch)
        subprocess.run([self.helper.OPENSSL, "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
                        "-nodes", "-days", "2", "-subj", "/CN=" + name, "-keyout", str(scratch / "key.pem"),
                        "-out", str(scratch / "cert.pem")], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return (scratch / "cert.pem").read_bytes()

    def test_web_ca_is_copied_readonly_and_bound_in_runner_environment(self):
        # 10-22 73: an operator certificate the system store cannot verify left the
        # runner's console index check failing; the runner gets it as its web CA.
        source = self.root / "public-cert.pem"
        body = self.self_signed("cdnca.example")
        source.write_bytes(body)
        os.chmod(source, 0o444)
        self.assertEqual(self.helper.prepare(self.installation, self.url, web_ca_file=source)["status"], "prepared_not_started")
        copied = self.config / "web-ca.pem"
        self.assertEqual(copied.read_bytes(), body)
        self.assertEqual((stat.S_IMODE(copied.stat().st_mode), copied.stat().st_nlink), (0o444, 1))
        runner = dict(line.split("=", 1) for line in (self.config / "runner-input.env").read_text().splitlines())
        self.assertEqual(runner["CDNCA_NATIVE_UPGRADE_WEB_CA_FILE"], str(copied))
        self.assertEqual(self.helper.check(self.installation, self.url, web_ca_file=source)["status"], "configuration_checked")
        # The runner contract is bound both ways: check without the CA, or against a different one, fails.
        with self.assertRaises(ValueError):
            self.helper.check(self.installation, self.url)
        other = self.root / "other-cert.pem"
        other.write_bytes(self.self_signed("other.example"))
        os.chmod(other, 0o444)
        with self.assertRaises(ValueError):
            self.helper.check(self.installation, self.url, web_ca_file=other)
        os.chmod(copied, 0o644)
        with self.assertRaises(ValueError):
            self.helper.check(self.installation, self.url, web_ca_file=source)

    def test_web_ca_without_option_is_absent_and_invalid_or_unsafe_files_refuse_preparation(self):
        self.helper.prepare(self.installation, self.url)
        self.assertFalse((self.config / "web-ca.pem").exists())
        self.assertNotIn("WEB_CA_FILE", (self.config / "runner-input.env").read_text())
        shutil.rmtree(self.config)
        source = self.root / "public-cert.pem"
        valid = self.self_signed("cdnca.example")
        for body, mode in ((b"not a certificate\n", 0o444), (valid + b"-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n", 0o444),
                           (valid.replace(b"MI", b"QQ", 1), 0o444), (valid, 0o666)):
            source.unlink(missing_ok=True)
            source.write_bytes(body)
            os.chmod(source, mode)
            with self.subTest(mode=oct(mode), body=body[:40]), self.assertRaises((ValueError, OSError)):
                self.helper.prepare(self.installation, self.url, web_ca_file=source)
            self.assertFalse(self.config.exists())

    def test_artifact_trust_rejects_unknown_keys_duplicates_and_non_ed25519_before_preparation(self):
        artifact = self.root / "artifact-trust.json"
        der = bytes.fromhex("302a300506032b6570032100") + bytes(range(32))
        pem = "-----BEGIN PUBLIC KEY-----\n" + base64.b64encode(der).decode() + "\n-----END PUBLIC KEY-----\n"
        key = {"key_id": "artifact-fixture", "public_key_pem": pem}
        for body in ({"version": True, "keys": [key]}, {"version": 1, "keys": []},
                     {"version": 1, "keys": [key, key]}, {"version": 1, "keys": [key], "extra": True},
                     {"version": 1, "keys": [{**key, "secret": "never"}]},
                     {"version": 1, "keys": [{**key, "public_key_pem": "not a PEM"}]}):
            artifact.write_text(json.dumps(body))
            os.chmod(artifact, 0o600)
            with self.subTest(body=body), self.assertRaises(ValueError):
                self.helper.prepare(self.installation, self.url, artifact)
            self.assertFalse(self.config.exists())

    def test_nginx_is_only_fixed_loopback_tls13_exact_get_and_never_embeds_token(self):
        self.helper.prepare(self.installation, self.url)
        config = (self.config / "plan-source-nginx.conf").read_text()
        self.assertIn("listen 127.0.0.1:9445 ssl;", config)
        self.assertIn("ssl_protocols TLSv1.3;", config)
        self.assertIn("ssl_verify_client on;", config)
        self.assertIn("location = /v1/internal/control-upgrade/plan", config)
        self.assertIn('if ($request_method != GET) { return 405; }', config)
        self.assertIn('if ($request_uri != "/v1/internal/control-upgrade/plan") { return 404; }', config)
        self.assertIn("proxy_pass http://127.0.0.1:8080;", config)
        self.assertIn("location / { return 404; }", config)
        self.assertIn("proxy_set_header Authorization $http_authorization;", config)
        self.assertNotIn((self.config / "plan-source-token").read_text().strip(), config)
        self.assertNotIn("listen 0.0.0.0", config)

    def test_prepare_replay_existing_file_directory_or_symlink_never_overwrites(self):
        self.helper.prepare(self.installation, self.url)
        before = self.snapshot()
        with self.assertRaises(ValueError):
            self.helper.prepare(self.installation, self.url)
        self.assertEqual(self.snapshot(), before)
        empty = self.root / "existing-empty"
        empty.mkdir(mode=0o700)
        with mock.patch.object(self.helper, "CONFIG", empty), self.assertRaises(ValueError):
            self.helper.prepare(self.installation, self.url)
        link = self.root / "linked-config"
        link.symlink_to(self.config)
        with mock.patch.object(self.helper, "CONFIG", link), self.assertRaises((ValueError, OSError)):
            self.helper.prepare(self.installation, self.url)
        self.assertEqual(self.snapshot(), before)

    def test_invalid_uuid_urls_or_platform_never_create_configuration(self):
        for value in ("", "00000000-0000-0000-0000-000000000000", self.installation.upper(), "not-an-id"):
            with self.subTest(uuid=value), self.assertRaises(ValueError):
                self.helper.prepare(value, self.url)
        for value in ("http://cdnca.example/", "https://u:p@cdnca.example/", "https://cdnca.example/?token=x",
                      "https://cdnca.example/#fragment", "https://cdnca.example:65536/", "https://cdnca.example:0/",
                      "https://cdnca.example:bad/", "https://cdnca.example:/", "https://cdnca.example\nBAD=x", "https://cdnca.example/$(id)",
                      "https://cdnca.example/%0A", "https://cdnca.example/../index.html", " https://cdnca.example/"):
            with self.subTest(url=value), self.assertRaises(ValueError):
                self.helper.prepare(self.installation, value)
        with mock.patch.object(self.helper.platform, "machine", return_value="aarch64"), self.assertRaises(ValueError):
            self.helper.prepare(self.installation, self.url)
        self.assertFalse(self.config.exists())

    def test_trust_rejects_unknown_duplicate_noncanonical_or_private_fields(self):
        good = {"keys": [{"key_id": "fixture-key", "public_key": self.public}]}
        bad = [{**good, "private_key": "must-not-copy"}, {"keys": []},
               {"keys": good["keys"] * 2}, {"keys": [{"key_id": "fixture-key", "public_key": self.public + "="}]},
               {"keys": [{"key_id": "fixture-key", "public_key": self.public[:-1] + "B"}]},
               {"keys": [{"key_id": "unsafe\n", "public_key": self.public}]},
               {"keys": [{**good["keys"][0], "private_key": "must-not-copy"}]}]
        bodies = [json.dumps(value) for value in bad]
        bodies.append(json.dumps(good).replace('"keys":', '"keys":[],"keys":', 1))
        for body in bodies:
            self.trust.write_text(body)
            with self.subTest(body=body), self.assertRaises(ValueError):
                self.helper.prepare(self.installation, self.url)
            self.assertFalse(self.config.exists())

    def test_check_rejects_permissions_links_fifos_changed_inputs_and_config(self):
        with self.assertRaises((ValueError, OSError)):
            self.helper.check(self.installation, self.url)
        self.assertFalse(self.config.exists())
        self.helper.prepare(self.installation, self.url)
        key = self.config / "plan-source-client-key.pem"
        os.chmod(key, 0o644)
        with self.assertRaises(ValueError):
            self.helper.check(self.installation, self.url)
        os.chmod(key, 0o600)
        original = key.read_bytes()
        key.unlink()
        for kind in ("symlink", "fifo", "hardlink"):
            if kind == "symlink":
                key.symlink_to(self.config / "plan-source-server-key.pem")
            elif kind == "fifo":
                os.mkfifo(key, 0o600)
            else:
                os.link(self.config / "plan-source-server-key.pem", key)
            with self.subTest(kind=kind), self.assertRaises((ValueError, OSError)):
                self.helper.check(self.installation, self.url)
            key.unlink()
        key.write_bytes(original)
        os.chmod(key, 0o600)
        for installation, url in (("4d519c71-4bdb-4e61-82a8-5312c6b47f21", self.url), (self.installation, "https://other.example/")):
            with self.assertRaises(ValueError):
                self.helper.check(installation, url)
        path = self.config / "api.env"
        path.write_text(path.read_text() + "CDNCA_NATIVE_UPGRADE_UNEXPECTED=true\n")
        with self.assertRaises(ValueError):
            self.helper.check(self.installation, self.url)

    def test_real_certificate_wrong_san_purpose_remaining_lifetime_or_key_fails(self):
        self.helper.prepare(self.installation, self.url)
        certificate = self.config / "plan-source-server.pem"
        original = certificate.read_bytes()
        for options in ({"san": "127.0.0.2"}, {"purpose": "clientAuth"}, {"days": "1"}):
            self.replace_certificate("server", **options)
            with self.subTest(options=options), self.assertRaises(ValueError):
                self.helper.check(self.installation, self.url)
            certificate.write_bytes(original)
        client = self.config / "plan-source-client.pem"
        original_client = client.read_bytes()
        self.replace_certificate("client", purpose="serverAuth", san="")
        with self.assertRaises(ValueError):
            self.helper.check(self.installation, self.url)
        client.write_bytes(original_client)
        key = self.config / "plan-source-server-key.pem"
        key.write_bytes((self.config / "plan-source-client-key.pem").read_bytes())
        with self.assertRaises(ValueError):
            self.helper.check(self.installation, self.url)

    def test_failed_generation_is_secret_safe_and_does_not_overwrite_partial_state(self):
        original = self.helper.openssl
        def fail_generation(*arguments):
            if arguments[0] == "genpkey":
                raise ValueError("fixture")
            return original(*arguments)
        with mock.patch.object(self.helper, "openssl", side_effect=fail_generation):
            with self.assertRaises(ValueError):
                self.helper.prepare(self.installation, self.url)
        before = self.snapshot()
        self.assertEqual(set(before), {"installation-id", "trusted-keys.json", "plan-source-token"})
        with self.assertRaises(ValueError):
            self.helper.prepare(self.installation, self.url)
        self.assertEqual(self.snapshot(), before)
        error = io.StringIO()
        with mock.patch.object(self.helper, "check", side_effect=ValueError("DO_NOT_PRINT_SECRET")), \
                mock.patch("sys.argv", ["configure-native-upgrade.py", "check", "--installation-id", self.installation,
                                       "--web-index-url", self.url]), contextlib.redirect_stderr(error):
            self.assertEqual(self.helper.main(), 1)
        self.assertNotIn("DO_NOT_PRINT_SECRET", error.getvalue())

    def test_no_secret_in_openssl_argv_environment_or_cli_output(self):
        real_run = subprocess.run
        calls = []
        def record(command, **options):
            calls.append((command, options.get("env", {})))
            self.assertEqual(command[0], self.helper.OPENSSL)
            return real_run(command, **options)
        output = io.StringIO()
        with mock.patch.object(self.helper.subprocess, "run", side_effect=record), \
                mock.patch("sys.argv", ["configure-native-upgrade.py", "prepare", "--installation-id", self.installation,
                                       "--web-index-url", self.url]), contextlib.redirect_stdout(output):
            self.assertEqual(self.helper.main(), 0)
        token = (self.config / "plan-source-token").read_text().strip()
        self.assertNotIn(token, repr(calls) + output.getvalue())
        self.assertNotIn("BEGIN PRIVATE KEY", repr(calls) + output.getvalue())
        self.assertTrue(calls)


if __name__ == "__main__":
    unittest.main()
