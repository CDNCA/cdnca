"""DNS runtime convergence tests; temporary files only, no systemd or services."""
import importlib.util
import os
from pathlib import Path
import re
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location('converge_dns', HERE / 'converge-dns-runtime.py')
C = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(C)
INSTALLER = (HERE.parent / 'install-control.sh').read_text()
KEY = 'AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8='


def installer_values():
    """The DNS lines install-control.sh writes, with the generated key bound."""
    block = re.search(r'(?ms)^write_environment\(\) \{.*?^\}\n', INSTALLER)[0]
    constants = {'CNAME_ALLOCATION_HMAC_KEY_BASE64': KEY}
    values = {}
    for line in block.split('\n'):
        if line.startswith(C.OWNED):
            name, _, value = line.partition('=')
            values[name] = re.sub(r'\$\{([A-Z_0-9]+)\}', lambda match: constants[match[1]], value)
    return values


class Completed:
    def __init__(self, code):
        self.returncode = code


class ConvergeDNSRuntimeTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        root = Path(self.directory.name)
        self.sources = (root / 'control.env', root / 'runtime-extra.env', root / 'missing.env')
        self.env_file, self.dropin, self.lock = root / 'dns-runtime.env', root / 'unit.d' / '50-dns.conf', root / 'lock'
        self.write(self.sources[0], b'HTTP_ADDR=127.0.0.1:8080\nDNS_CREDENTIAL_KEY_ID=dns-credentials-v1\n')
        self.write(self.sources[1], b"EDGE_PUBLISH_RUNTIME_ENABLED='true'\n")
        self.calls = []

    def tearDown(self):
        self.directory.cleanup()

    @staticmethod
    def write(path, content, mode=0o600):
        path.write_bytes(content)
        os.chmod(path, mode)

    def state(self):
        return C.state(self.sources, self.env_file, self.dropin)

    def run_fake(self, health):
        """health[n] is the probe answer after the n-th restart of this call."""
        restarts = []

        def run(command, **_):
            self.calls.append(command[1])
            if command[1] == 'restart':
                restarts.append(command)
            return Completed(0)
        return run, lambda: health[len(restarts) - 1]

    def apply(self, *health):
        run, check = self.run_fake(health)
        return C.apply(self.sources, self.env_file, self.dropin, self.lock, run, check, wait=5)

    def test_converge_settings_equal_fresh_installer_settings(self):
        installed = installer_values()
        self.assertEqual(installed, {**C.FIXED, C.SECRET: KEY})
        self.assertTrue(C.valid_runtime(installed))
        self.assertEqual(C.parse_env(C.render(bytes(range(32)))), {**C.FIXED, C.SECRET: KEY})

    def test_fresh_install_is_reported_and_left_alone(self):
        content = self.sources[0].read_bytes() + C.render(bytes(range(32)))
        self.write(self.sources[0], content)
        self.assertEqual(self.state(), 'installer')
        self.assertEqual(self.apply(), 'already enabled (installer)')
        self.assertFalse(self.env_file.exists() or self.dropin.exists())

    def test_apply_writes_root_only_key_and_dropin_then_is_idempotent(self):
        self.assertEqual(self.state(), 'pending')
        self.assertIn('enabled', self.apply(True))
        self.assertEqual(self.calls, ['daemon-reload', 'restart'])
        self.assertEqual(os.stat(self.env_file).st_mode & 0o777, 0o400)
        self.assertTrue(C.valid_runtime(C.parse_env(self.env_file.read_bytes())))
        self.assertEqual(self.dropin.read_bytes(), C.DROPIN_CONTENT)
        key = self.env_file.read_bytes()
        self.assertEqual(self.apply(), 'already enabled (converged)')
        self.assertEqual(self.env_file.read_bytes(), key)

    def test_failed_restart_removes_dropin_and_keeps_key(self):
        with self.assertRaisesRegex(ValueError, 'drop-in removed and service healthy'):
            self.apply(False, True)
        self.assertFalse(self.dropin.exists())
        key = self.env_file.read_bytes()
        self.assertIn('enabled', self.apply(True))
        self.assertEqual(self.env_file.read_bytes(), key, 'a retry must reuse the CNAME key')

    def test_rollback_removes_only_the_dropin(self):
        self.apply(True)
        run, check = self.run_fake([True])
        self.assertIn('retained', C.rollback(self.env_file, self.dropin, self.lock, run, check, wait=5))
        self.assertFalse(self.dropin.exists())
        self.assertTrue(self.env_file.exists())
        self.assertEqual(self.state(), 'pending')

    def test_refuses_foreign_or_partial_settings(self):
        for content in (b'DNS_RECONCILE_ENABLED=false\n', b'CNAME_ALLOCATION_HMAC_KEY_ID=other\n'):
            self.write(self.sources[1], content)
            with self.assertRaisesRegex(ValueError, 'already exist'):
                self.state()
        self.write(self.sources[1], b'')
        self.write(self.env_file, b'DNS_RECONCILE_ENABLED=true\n', 0o400)
        with self.assertRaisesRegex(ValueError, 'refusing to replace'):
            self.state()
        os.chmod(self.env_file, 0o644)
        with self.assertRaisesRegex(ValueError, 'unsafe file'):
            self.state()

    def test_rejects_weak_or_non_canonical_key(self):
        for key in ('AAECAwQFBgcICQoLDA0ODw==', KEY.rstrip('='), 'not base64!'):
            self.assertFalse(C.valid_runtime({**C.FIXED, C.SECRET: key}))
        self.assertFalse(C.valid_runtime({**C.FIXED, C.SECRET: KEY, 'DNS_RECONCILE_EXTRA': 'x'}))


if __name__ == '__main__':
    unittest.main()
