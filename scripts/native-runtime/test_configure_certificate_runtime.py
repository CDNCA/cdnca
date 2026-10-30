"""Private isolated file fixtures; never starts services or contacts a CA."""
import base64
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from test_configure_control_runtime import native_runtime_test_fixture


class NativeCertificateRuntimeTests(unittest.TestCase):
    def test_native_certificate_runtime(self):
        source = Path(__file__).resolve().with_name("configure-certificate-runtime.py")
        spec = importlib.util.spec_from_file_location("certificate_runtime_fixture", source)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        installer = source.parents[1] / "install-control.sh"
        self.assertTrue("EnvironmentFile=${CONFIG_DIR}/certificate-runtime/environment.env" in installer.read_text())
        self.assertTrue('configure-certificate-runtime.py" install "$CERTIFICATE_EMAIL"' in installer.read_text())
        self.assertTrue("configure-certificate-runtime.py" in (source.parents[1] / "native-control-install-package.mjs").read_text())
        prompt = "prompt_certificate_email() {" + installer.read_text().split("prompt_certificate_email() {", 1)[1].split("\n}", 1)[0] + "\n}"
        for email, expected in (("certificates@example.com", 0), ("", 1), ("admin@local", 1), ("a@example.INVALID", 1),
                                ("a@example.com\nEXTRA=true", 1), ("a..b@example.com", 1)):
            result = module.runtime.subprocess.run(["bash", "-c", "set -Eeuo pipefail\nfail() { exit 1; }\n" + prompt + "\nprompt_certificate_email"],
                                                   env={"PATH": os.environ["PATH"], "CERTIFICATE_EMAIL": email}, stdout=module.runtime.subprocess.PIPE, stderr=module.runtime.subprocess.PIPE)
            self.assertEqual(result.returncode, expected)
        for failure in (None, "check_missing", "bad_email", "local_email", "email_injection", "shared_key",
                        "partial", "symlink", "extra_file", "wrong_mode", "changed_base", "changed_email",
                        "changed_environment", "changed_receipt", "existing_configuration", "fsync_failure", "file_fsync_failure"):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory(prefix="cdnca-certificate-runtime-", dir="/tmp") as directory:
                runtime = native_runtime_test_fixture(directory)
                runtime.native_control_runtime("install")
                module.runtime = runtime
                target = runtime.CONTROL / "certificate-runtime"
                email = "certificates@example.com"
                originals = {path: path.read_bytes() for path in runtime.CONTROL.rglob("*") if path.is_file()}
                if failure == "check_missing":
                    with self.assertRaises(ValueError):
                        module.native_certificate_runtime("check", email)
                    continue
                if failure in ("bad_email", "local_email", "email_injection"):
                    email = {"bad_email": "not-an-email", "local_email": "admin@local",
                             "email_injection": "a@example.com\nACME_RUNTIME_ENABLED=false"}[failure]
                if failure == "existing_configuration":
                    base = runtime.CONTROL / "control.env"
                    base.write_bytes(base.read_bytes() + b"ACME_RUNTIME_ENABLED=true\n")
                if failure in ("partial", "symlink"):
                    if failure == "partial":
                        target.mkdir(mode=0o700)
                    else:
                        target.symlink_to(runtime.CONTROL / "runtime-keys", target_is_directory=True)
                with contextlib.ExitStack() as stack:
                    if failure == "shared_key":
                        stack.enter_context(mock.patch.object(module.secrets, "token_bytes", return_value=bytes(range(32))))
                    if failure == "fsync_failure":
                        stack.enter_context(mock.patch.object(runtime.os, "fsync", side_effect=OSError("fixture")))
                    if failure == "file_fsync_failure":
                        stack.enter_context(mock.patch.object(runtime.os, "fsync", side_effect=[None, OSError("fixture")]))
                    if failure in ("bad_email", "local_email", "email_injection", "shared_key", "partial", "symlink", "existing_configuration", "fsync_failure", "file_fsync_failure"):
                        with self.assertRaises((ValueError, OSError)):
                            module.native_certificate_runtime("install", email)
                        if failure != "existing_configuration":
                            for path, content in originals.items():
                                self.assertEqual(path.read_bytes(), content)
                        continue
                    synced = []
                    original_fsync = module.os.fsync
                    with contextlib.redirect_stdout(io.StringIO()) as output, mock.patch.object(module.os, "fsync",
                            side_effect=lambda descriptor: (synced.append(os.fstat(descriptor).st_ino), original_fsync(descriptor))[1]):
                        module.native_certificate_runtime("install", email)
                    self.assertEqual(output.getvalue(), "")
                    self.assertIn(runtime.CONTROL.stat().st_ino, synced, "new key directory entry must be durable")
                environment = target / "environment.env"
                receipt = target / "receipt.json"
                env = runtime.native_runtime_env(environment.read_bytes())
                self.assertEqual(env["ACME_RUNTIME_ENABLED"], "true")
                self.assertEqual(env["ACME_CONTACTS"], "mailto:" + email)
                self.assertEqual(env["ACME_DIRECTORY_URL"], "https://acme-v02.api.letsencrypt.org/directory")
                keys = [env["ACME_WRAPPING_KEY_BASE64"], env["ACME_DNS_HANDLE_ACTIVE_KEY_BASE64"],
                        json.loads(env["CERTIFICATE_PUBLICATION_CURSOR_KEYS_JSON"])[env["CERTIFICATE_PUBLICATION_CURSOR_ACTIVE_KEY_ID"]]]
                self.assertEqual(len(set(keys)), 3)
                self.assertTrue(all(len(base64.b64decode(key, validate=True)) == 32 for key in keys))
                self.assertEqual(target.stat().st_mode & 0o777, 0o700)
                for path in (environment, receipt):
                    self.assertEqual(path.stat().st_mode & 0o777, 0o600)
                saved = {path: (path.read_bytes(), path.stat().st_mtime_ns) for path in (environment, receipt)}
                if failure == "extra_file":
                    (target / "unknown").touch()
                elif failure == "wrong_mode":
                    environment.chmod(0o644)
                elif failure == "changed_base":
                    base = runtime.CONTROL / "control.env"
                    base.write_bytes(base.read_bytes() + b"# changed\n")
                elif failure == "changed_environment":
                    environment.write_bytes(environment.read_bytes().replace(b"ENABLED='true'", b"ENABLED='false'"))
                elif failure == "changed_receipt":
                    receipt.write_text("{}\n")
                elif failure == "changed_email":
                    email = "other@example.com"
                if failure:
                    with self.assertRaises((ValueError, OSError)):
                        module.native_certificate_runtime("install", email)
                    continue
                module.native_certificate_runtime("check", email)
                module.native_certificate_runtime("install", email)
                for path, original in saved.items():
                    self.assertEqual((path.read_bytes(), path.stat().st_mtime_ns), original)
                for path, content in originals.items():
                    self.assertEqual(path.read_bytes(), content)


if __name__ == "__main__":
    unittest.main()
