"""Isolated tests: no system service, user, CA store, or network is changed."""

import contextlib
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock
import warnings
import zipfile


class NativeRustFSTests(unittest.TestCase):
    def setUp(self):
        path = Path(__file__).with_name("install-rustfs.py")
        spec = importlib.util.spec_from_file_location("native_rustfs", path)
        self.helper = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.helper)
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        os.chmod(self.root, 0o700)

    def test_manifest_pins_official_static_musl_archive_and_binary(self):
        manifest = json.loads(Path(__file__).with_name("rustfs-1.0.1.json").read_text())
        self.assertEqual(manifest["version"], "1.0.1")
        self.assertTrue(manifest["archive_url"].endswith("/rustfs-linux-x86_64-musl-v1.0.1.zip"))
        self.assertEqual(manifest["archive_sha256"], "a834096dafa1f1a55825a2cdaf49d006a193978d344f2d508c2be475133738a3")
        self.assertEqual(manifest["binary_sha256"], "a5ac41209ca8eca6c591c1584cc108b308850e1b74955afd4af9fe1b0379f2eb")
        self.assertEqual((manifest["archive_sha256"], manifest["binary_sha256"]), (self.helper.ARCHIVE_SHA, self.helper.BINARY_SHA))
        # Earlier installations (official gnu build) keep a valid receipt.
        self.assertEqual([(entry["archive_sha256"], entry["binary_sha256"]) for entry in manifest["legacy_receipts"]],
                         [("9742e183cb0dfb0d48fa909797af572fe47b7f827569036baa4156e0d3958ee5", "e6544a42a09a16d6fea47ad3d8aaa1a8793c9afa9c723bb8ae884f1238cd7c25")])

    def test_receipts_accept_musl_and_legacy_gnu_only(self):
        receipts = self.helper.accepted_receipts()
        self.assertEqual([receipt["binary_sha256"] for receipt in receipts],
                         [self.helper.BINARY_SHA, "e6544a42a09a16d6fea47ad3d8aaa1a8793c9afa9c723bb8ae884f1238cd7c25"])
        self.assertTrue(all(receipt["schema"] == "cdnca.native-rustfs/v1" and receipt["endpoint"] == "https://127.0.0.1:19000" for receipt in receipts))

    def test_digest_and_os_release_fallbacks_match_newer_python(self):
        payload = self.root / "payload"
        payload.write_bytes(b"x" * (3 << 20) + b"tail")
        with payload.open("rb") as stream:
            expected = self.helper.sha256_stream(stream).hexdigest()
        self.assertEqual(expected, hashlib.sha256(payload.read_bytes()).hexdigest())
        release = self.root / "os-release"
        release.write_text('PRETTY_NAME="Ubuntu 22.04.5 LTS"\nID=ubuntu\nVERSION_ID="22.04"\n# comment\nID_LIKE=debian\n')
        real_open = open
        with mock.patch.object(self.helper, "hashlib", SimpleNamespace(sha256=hashlib.sha256)), \
                mock.patch.object(self.helper, "platform", SimpleNamespace()), \
                mock.patch("builtins.open", lambda path, *args, **kwargs: real_open(release if path == "/etc/os-release" else path, *args, **kwargs)):
            with payload.open("rb") as stream:
                self.assertEqual(self.helper.sha256_stream(stream).hexdigest(), expected)
            values = self.helper.os_release()
        self.assertEqual((values["ID"], values["VERSION_ID"], values["PRETTY_NAME"]), ("ubuntu", "22.04", "Ubuntu 22.04.5 LTS"))

    def test_private_write_is_exclusive_and_private(self):
        path = self.root / "credential"
        self.helper.write_private(path, b"test-only")
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        with self.assertRaises((OSError, ValueError)):
            self.helper.write_private(path, b"replacement")
        self.assertEqual(path.read_bytes(), b"test-only")

    def test_private_read_rejects_fifo_links_and_public_permissions(self):
        fifo = self.root / "fifo"
        os.mkfifo(fifo, 0o600)
        with self.assertRaises(ValueError):
            self.helper.read_private(fifo)
        original = self.root / "original"
        self.helper.write_private(original, b"private")
        linked = self.root / "linked"
        os.link(original, linked)
        with self.assertRaises(ValueError):
            self.helper.read_private(original)
        symbolic = self.root / "symbolic"
        symbolic.symlink_to(original)
        with self.assertRaises((OSError, ValueError)):
            self.helper.read_private(symbolic)
        public = self.root / "public"
        public.write_bytes(b"not-private")
        os.chmod(public, 0o644)
        with self.assertRaises(ValueError):
            self.helper.read_private(public)

    def test_policy_has_exact_separate_bucket_and_prefix_actions(self):
        policy = self.helper.iam_policy("brand-assets")
        versioning, listing, objects = policy["Statement"]
        self.assertEqual(versioning["Action"], ["s3:GetBucketVersioning"])
        self.assertNotIn("Condition", versioning)
        self.assertEqual(listing["Action"], ["s3:ListBucketVersions"])
        self.assertEqual(listing["Condition"]["StringLike"]["s3:prefix"], ["brand-assets/*"])
        self.assertEqual(objects["Resource"], ["arn:aws:s3:::cdnca-assets/brand-assets/*"])
        self.assertEqual(set(objects["Action"]), {"s3:GetObject", "s3:GetObjectVersion", "s3:PutObject", "s3:DeleteObject", "s3:DeleteObjectVersion"})
        with self.assertRaises(ValueError):
            self.helper.iam_policy("*")

    def test_sigv4_matches_the_aws_s3_get_object_example(self):
        # docs.aws.amazon.com/AmazonS3/latest/API/sig-v4-header-based-auth.html, "GET Object".
        headers = {"Host": "examplebucket.s3.amazonaws.com", "Range": "bytes=0-9",
                   "x-amz-content-sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                   "x-amz-date": "20130524T000000Z"}
        authorization = self.helper.sigv4_authorization(
            "GET", "/test.txt", "", headers, headers["x-amz-content-sha256"],
            ("AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"), "20130524T000000Z")
        self.assertEqual(authorization, "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, "
                         "SignedHeaders=host;range;x-amz-content-sha256;x-amz-date, "
                         "Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41")

    def test_request_signs_in_process_without_proxy_files_or_secret_arguments(self):
        secret = "unimportant-unit-test-secret"
        sent = {}

        class Response:
            status = 200
            def read(self, limit):
                return b"{}"
            def getheaders(self):
                return [("X-Amz-Version-Id", "v1")]

        class Connection:
            def __init__(self, host, port, timeout, context):
                sent.update(host=host, port=port, timeout=timeout)
                sent["headers"] = []
            def putrequest(self, method, path, skip_host, skip_accept_encoding):
                sent.update(method=method, path=path, skip_host=skip_host)
            def putheader(self, name, value):
                sent["headers"].append((name, value))
            def endheaders(self, body):
                sent["body"] = body
            def getresponse(self):
                return Response()
            def close(self):
                sent["closed"] = True

        with mock.patch.object(self.helper.http.client, "HTTPSConnection", Connection), \
                mock.patch.object(self.helper.ssl, "create_default_context") as context, \
                mock.patch.object(self.helper, "run") as command:
            status, headers, body = self.helper.request(self.root, "https://127.0.0.1:19000", ("unit-user", secret), self.root / "ca.crt",
                                                        "PUT", "/rustfs/admin/v3/add-user?accessKey=runtime", b'{"status":"enabled"}', ("If-None-Match: *",))
        command.assert_not_called()
        context.assert_called_once_with(cafile=str(self.root / "ca.crt"))
        self.assertEqual((status, headers, body), (200, {"x-amz-version-id": "v1"}, b"{}"))
        self.assertEqual((sent["host"], sent["port"], sent["method"], sent["path"], sent["skip_host"], sent["closed"]),
                         ("127.0.0.1", 19000, "PUT", "/rustfs/admin/v3/add-user?accessKey=runtime", True, True))
        names = dict(sent["headers"])
        self.assertEqual(names["Host"], "127.0.0.1:19000")
        self.assertEqual(names["x-amz-content-sha256"], hashlib.sha256(b'{"status":"enabled"}').hexdigest())
        self.assertIn("SignedHeaders=content-type;host;if-none-match;x-amz-content-sha256;x-amz-date,", names["Authorization"])
        self.assertNotIn(secret, repr(sent))
        self.assertEqual(list(self.root.iterdir()), [])

    def test_request_refuses_remote_http_and_path_in_endpoint(self):
        with mock.patch.object(self.helper, "run") as command:
            for endpoint in ("http://127.0.0.1:19000", "https://example.com", "https://127.0.0.1/x", "https://u:p@127.0.0.1", "https://127.0.0.1?x=1"):
                with self.subTest(endpoint=endpoint), self.assertRaises(ValueError):
                    self.helper.request(self.root, endpoint, ("x", "y"), self.root / "ca.crt", "GET", "/")
            command.assert_not_called()

    def test_unit_is_nonroot_uses_credentials_and_disables_external_exports(self):
        unit = self.helper.service_unit()
        self.assertIn("User=cdnca-objectstore", unit)
        self.assertIn("Group=cdnca-objectstore", unit)
        self.assertIn("LoadCredential=rustfs_key.pem:/etc/cdnca-objectstore/rustfs_key.pem", unit)
        self.assertIn("RUSTFS_TLS_PATH=%d", unit)
        self.assertIn("RUSTFS_ACCESS_KEY_FILE=%d/root-access-key", unit)
        self.assertNotIn("RUSTFS_SECRET_KEY=", unit)
        self.assertIn("RUSTFS_ADDRESS=127.0.0.1:19000", unit)
        self.assertIn("RUSTFS_CONSOLE_ENABLE=false", unit)
        self.assertIn("IPAddressDeny=any", unit)
        self.assertIn("IPAddressAllow=localhost", unit)

    def test_existing_state_is_never_overwritten(self):
        existing = self.root / "data"
        existing.mkdir()
        (existing / "customer-data").write_bytes(b"preserve")
        with mock.patch.object(self.helper, "FRESH_PATHS", [existing]):
            with self.assertRaises(ValueError):
                self.helper.reject_existing_state()
        self.assertEqual((existing / "customer-data").read_bytes(), b"preserve")

    def test_existing_system_ca_link_is_also_protected(self):
        self.assertIn(Path("/etc/ssl/certs/cdnca-objectstore.pem"), self.helper.FRESH_PATHS)

    def test_logs_use_protected_var_lib_not_group_writable_var_log(self):
        def ubuntu_directory(path):
            mode = 0o775 if path == Path("/var/log") else 0o755
            return SimpleNamespace(st_uid=0, st_mode=stat.S_IFDIR | mode)

        with mock.patch.object(Path, "lstat", autospec=True, side_effect=ubuntu_directory):
            self.helper.secure_parents(self.helper.LOGS)
            with self.assertRaisesRegex(ValueError, "unsafe parent directory"):
                self.helper.secure_parents(Path("/var/log/cdnca-objectstore"))
        self.assertEqual(self.helper.LOGS, Path("/var/lib/cdnca-objectstore-logs"))
        self.assertIn(self.helper.LOGS, self.helper.FRESH_PATHS)
        self.assertIn("RUSTFS_OBS_LOG_DIRECTORY=/var/lib/cdnca-objectstore-logs", self.helper.service_unit())

    def test_wrong_archive_digest_fails_before_extract_or_execution(self):
        archive = self.root / "archive.zip"
        self.helper.write_private(archive, b"not an official release")
        with mock.patch.object(self.helper, "run") as command:
            with self.assertRaises(ValueError):
                self.helper.verify_archive(archive)
            command.assert_not_called()

    @contextlib.contextmanager
    def official_archive_fixture(self, change=None):
        entries = [("rustfs", stat.S_IFREG | 0o755), ("rustfs-cli", stat.S_IFREG | 0o755)]
        if change is not None:
            change(entries)
        with tempfile.TemporaryDirectory(dir=self.root) as directory:
            directory = Path(directory)
            archive = directory / "official-layout.zip"
            with zipfile.ZipFile(archive, "w") as package, warnings.catch_warnings():
                warnings.simplefilter("ignore", UserWarning)
                for name, mode in entries:
                    entry = zipfile.ZipInfo(name)
                    entry.create_system = 3
                    entry.external_attr = mode << 16
                    package.writestr(entry, b"fixture-" + name.encode())
            os.chmod(archive, 0o600)
            archive_sha = hashlib.sha256(archive.read_bytes()).hexdigest()
            binary_sha = hashlib.sha256(b"fixture-rustfs").hexdigest()
            (directory / "rustfs-1.0.1.json").write_text(json.dumps({"version": "1.0.1", "archive_sha256": archive_sha, "binary_sha256": binary_sha,
                                                                   "legacy_receipts": list(self.helper.LEGACY_RECEIPTS)}))
            with mock.patch.multiple(self.helper, __file__=str(directory / "install-rustfs.py"), ARCHIVE_SHA=archive_sha, BINARY_SHA=binary_sha):
                yield archive

    def test_archive_accepts_exact_official_two_members(self):
        with self.official_archive_fixture() as archive:
            self.helper.verify_archive(archive)

    def test_archive_rejects_unexpected_duplicate_nested_and_link_members(self):
        changes = {
            "unexpected": lambda entries: entries.append(("extra", stat.S_IFREG | 0o644)),
            "missing": lambda entries: entries.pop(),
            "duplicate": lambda entries: entries.__setitem__(1, entries[0]),
            "nested": lambda entries: entries.__setitem__(1, ("path/rustfs-cli", stat.S_IFREG | 0o755)),
            "traversal": lambda entries: entries.__setitem__(1, ("../rustfs-cli", stat.S_IFREG | 0o755)),
            "symlink": lambda entries: entries.__setitem__(1, ("rustfs-cli", stat.S_IFLNK | 0o755)),
            "directory": lambda entries: entries.__setitem__(1, ("rustfs-cli", stat.S_IFDIR | 0o755)),
        }
        for name, change in changes.items():
            with self.subTest(name=name), self.official_archive_fixture(change) as archive:
                with self.assertRaisesRegex(ValueError, "archive (layout|entry)"):
                    self.helper.verify_archive(archive)

    def test_archive_checks_executable_hash_in_official_layout(self):
        with self.official_archive_fixture() as archive:
            manifest = archive.with_name("rustfs-1.0.1.json")
            content = json.loads(manifest.read_text())
            content["binary_sha256"] = "0" * 64
            manifest.write_text(json.dumps(content))
            with mock.patch.object(self.helper, "BINARY_SHA", "0" * 64):
                with self.assertRaisesRegex(ValueError, "binary SHA256 mismatch"):
                    self.helper.verify_archive(archive)

    def test_preflight_is_not_an_iam_writer(self):
        with mock.patch.object(self.helper, "provision_iam") as provision:
            with mock.patch.object(self.helper, "verify_installed") as installed:
                with mock.patch.object(self.helper, "probe_runtime") as probe:
                    self.helper.native_rustfs_preflight(self.root / "archive.zip")
            installed.assert_called_once()
            probe.assert_called_once()
            provision.assert_not_called()

    @contextlib.contextmanager
    def isolated_install(self, fail_probe=False, load_credential=True):
        paths = {"CONFIG": self.root / "config", "DATA": self.root / "data", "LOGS": self.root / "logs", "BINARY": self.root / "bin-parent/rustfs", "UNIT": self.root / "systemd/cdnca-objectstore.service", "TRUST": self.root / "ca-store/cdnca-objectstore.crt",
                 "COMPAT_CREDENTIALS": self.root / "compat-credentials", "COMPAT_DROPIN": self.root / "systemd/cdnca-objectstore.service.d/zz-cdnca-systemd-compat.conf"}
        paths["UNIT"].parent.mkdir()
        paths["TRUST"].parent.mkdir()
        unrelated = paths["TRUST"].with_name("unrelated.crt")
        unrelated.write_bytes(b"preserve unrelated CA")
        archive = self.root / "fixture.zip"
        with zipfile.ZipFile(archive, "w") as package:
            package.writestr("rustfs", b"unit-test executable fixture")
        os.chmod(archive, 0o600)
        calls = []

        def command(args, **kwargs):
            calls.append(args)
            return b"rustfs 1.0.1\n" if args[0] == str(paths["BINARY"]) else b""

        with contextlib.ExitStack() as stack:
            stack.enter_context(mock.patch.multiple(self.helper, **paths, BINARY_SHA=hashlib.sha256(b"unit-test executable fixture").hexdigest()))
            for name in ("native_rustfs_check", "provision_iam", "verify_installed"):
                stack.enter_context(mock.patch.object(self.helper, name))
            stack.enter_context(mock.patch.object(self.helper, "systemd_credentials_usable", return_value=load_credential))
            def tls(directory):
                for name, content in (("ca.crt", b"isolated CA"), ("rustfs_cert.pem", b"isolated cert"), ("rustfs_key.pem", b"isolated key")):
                    self.helper.write_private(directory / name, content)
            stack.enter_context(mock.patch.object(self.helper, "create_tls", side_effect=tls))
            stack.enter_context(mock.patch.object(self.helper, "request", return_value=(200, {}, b"")))
            stack.enter_context(mock.patch.object(self.helper, "run", side_effect=command))
            stack.enter_context(mock.patch.object(self.helper.pwd, "getpwnam", return_value=SimpleNamespace(pw_uid=os.geteuid(), pw_gid=os.getegid())))
            stack.enter_context(mock.patch.object(self.helper, "probe_runtime", side_effect=[None, ValueError("test probe failure")] if fail_probe else None))
            previous = os.umask(0o077)
            try:
                yield archive, paths, calls
            finally:
                os.umask(previous)
        self.assertEqual(unrelated.read_bytes(), b"preserve unrelated CA")

    def test_private_umask_does_not_make_nonroot_binary_parent_untraversable(self):
        with self.isolated_install() as (archive, paths, _):
            self.helper.native_rustfs_install(archive)
            self.assertEqual(stat.S_IMODE(paths["BINARY"].parent.stat().st_mode), 0o755)
            self.assertEqual(stat.S_IMODE(paths["BINARY"].stat().st_mode), 0o755)
            self.assertEqual(stat.S_IMODE(paths["CONFIG"].stat().st_mode), 0o700)
            self.assertEqual(stat.S_IMODE((paths["CONFIG"] / "root-secret-key").stat().st_mode), 0o600)

    def test_old_systemd_gets_owned_credential_copies_and_an_environment_dropin(self):
        with self.isolated_install(load_credential=False) as (archive, paths, calls):
            self.helper.native_rustfs_install(archive)
            directory, dropin = paths["COMPAT_CREDENTIALS"], paths["COMPAT_DROPIN"]
            self.assertEqual(stat.S_IMODE(directory.stat().st_mode), 0o500)
            self.assertEqual(sorted(os.listdir(directory)), sorted(self.helper.CREDENTIAL_NAMES))
            for name in self.helper.CREDENTIAL_NAMES:
                self.assertEqual((directory / name).read_bytes(), (paths["CONFIG"] / name).read_bytes())
                self.assertEqual(stat.S_IMODE((directory / name).stat().st_mode), 0o400)
            self.assertEqual(dropin.read_text(), self.helper.compat_dropin())
            self.assertIn("RUSTFS_TLS_PATH=" + str(directory), dropin.read_text())
            # The main unit stays byte-identical; the drop-in exists before the first start.
            self.assertEqual(paths["UNIT"].read_text(), self.helper.service_unit())
            self.assertLess(calls.index(["systemctl", "daemon-reload"]), calls.index(["systemctl", "enable", "--now", paths["UNIT"].name]))
            with mock.patch.object(self.helper.pwd, "getpwnam", return_value=SimpleNamespace(pw_uid=os.geteuid(), pw_gid=os.getegid())):
                self.helper.verify_compat_credentials()
                (directory / "root-secret-key").chmod(0o600)
                (directory / "root-secret-key").write_bytes(b"tampered")
                (directory / "root-secret-key").chmod(0o400)
                with self.assertRaisesRegex(ValueError, "compatibility credential mismatch"):
                    self.helper.verify_compat_credentials()

    def test_credentials_need_load_credential_and_the_248_percent_d_specifier(self):
        # Debian 11 (systemd 247) knows LoadCredential= but rejects %d ("Invalid slot"),
        # so RustFS would start without its keys; it must take the compatibility path.
        for knows, version, usable in ((True, b"systemd 247 (247.3-7+deb11u7)\n+PAM", False),
                                       (True, b"systemd 248 (248)\n", True),
                                       (True, b"systemd 252 (252.39-1.el9)\n", True),
                                       (False, b"systemd 239 (239-82.el8)\n", False),
                                       (True, b"unexpected\n", False)):
            with mock.patch.object(self.helper, "systemd_knows", return_value=knows), \
                    mock.patch.object(self.helper, "run", return_value=version):
                self.assertEqual(self.helper.systemd_credentials_usable(), usable, version)

    def test_new_systemd_installs_no_compatibility_files(self):
        with self.isolated_install() as (archive, paths, _):
            self.helper.native_rustfs_install(archive)
            self.assertFalse(os.path.lexists(paths["COMPAT_CREDENTIALS"]))
            self.assertFalse(os.path.lexists(paths["COMPAT_DROPIN"].parent))

    def test_failure_stops_own_unit_removes_only_added_ca_and_keeps_state(self):
        with self.isolated_install(fail_probe=True) as (archive, paths, calls):
            with self.assertRaises(ValueError):
                self.helper.native_rustfs_install(archive)
            self.assertFalse(paths["TRUST"].exists())
            self.assertTrue(paths["DATA"].is_dir())
            self.assertTrue((paths["CONFIG"] / "root-secret-key").is_file())
            self.assertIn(["systemctl", "disable", "--now", paths["UNIT"].name], calls)
            self.assertEqual(calls.count(["update-ca-certificates"]), 2)


if __name__ == "__main__":
    unittest.main()
