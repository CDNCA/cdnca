import copy
from contextlib import redirect_stderr, redirect_stdout
import importlib.util
import io
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import time
import unittest
from unittest.mock import Mock, patch


SPEC = importlib.util.spec_from_file_location("native_nats", Path(__file__).with_name("configure-nats.py"))
NATS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(NATS)


class NativeNATSContractTests(unittest.TestCase):
    def test_only_exact_unauthenticated_numeric_loopback_url(self):
        self.assertEqual(NATS.native_nats_url("nats://127.0.0.1:4222"), 4222)
        for server in ["nats://localhost:4222", "nats://127.0.0.2:4222", "nats://[::1]:4222",
                       "nats://user:secret@127.0.0.1:4222", "nats://127.0.0.1:4222/",
                       "nats://127.0.0.1:4222?x=1", "nats://127.0.0.1:4222#x",
                       "nats://127.0.0.1:04222", "nats://127.0.0.1:0", "nats://127.0.0.1:65536",
                       "tls://127.0.0.1:4222", "nats://127.0.0.1:4222\n"]:
            with self.subTest(server=server), self.assertRaises(ValueError):
                NATS.native_nats_url(server)

    def test_profile_covers_all_fixed_runtime_contracts(self):
        profile = NATS.load_native_nats_profile()
        streams = {config["name"]: config for config in profile["streams"]}
        self.assertEqual(len(streams), 17)
        self.assertEqual(len(profile["consumers"]), 10)
        consumers = {item["config"]["durable_name"]: item for item in profile["consumers"]}
        # Mirrors acmehttp01.DefaultStatusConfig and the consumer NewNodeStatusConsumer self-creates.
        self.assertEqual(consumers["control_api_acme_http01_status"], {
            "stream": "AGENT_DEPLOYMENT_STATUS",
            "config": {**profile["consumer_defaults"], "durable_name": "control_api_acme_http01_status",
                       "filter_subject": "cdnca.agent.deployment-status.acme-http01.*"}})
        self.assertEqual((profile["server_version"], profile["cli_version"]), ("2.12.15-cdnca.1", "0.2.4"))
        self.assertEqual(profile["min_max_payload"], 2162688)
        self.assertEqual(streams["PACKAGE_COMMERCE"]["subjects"], [
            "cdnca.package_commerce.order.awaiting_payment", "cdnca.package_commerce.order.fulfilled",
            "cdnca.package_commerce.order.refund_applied", "cdnca.package_commerce.order.void_applied",
            "cdnca.package_commerce.callback.applied", "cdnca.package_commerce.callback.rejected_signature",
            "cdnca.package_commerce.callback.rejected_mismatch", "cdnca.package_commerce.callback.ignored_out_of_order",
            "cdnca.package_commerce.callback.ignored_terminal", "cdnca.package_commerce.callback.failed_fulfillment"])
        self.assertEqual(streams["KV_AILEASE_2dcd3c381ead92f3"]["max_age"], 40000000000)
        self.assertEqual(streams["KV_AIEVIDENCE_2dcd3c381ead92f3"]["max_msg_size"], 2162688)
        self.assertTrue(streams["KV_AIEVIDENCE_2dcd3c381ead92f3"]["deny_delete"])
        self.assertTrue(all(config["num_replicas"] == 1 for config in streams.values()))
        self.assertTrue(all(config["storage"] == "file" for config in streams.values()))
        self.assertEqual(streams["AGENT_DEPLOYMENT_STATUS"]["max_age"], 0)
        self.assertTrue(streams["CONNECTIONS_INGEST_V1"]["discard_new_per_subject"])

    def test_projection_accepts_only_known_server_defaults_and_metadata(self):
        profile = NATS.load_native_nats_profile()
        expected = profile["streams"][0]
        actual = copy.deepcopy(expected)
        actual["subjects"].reverse()
        actual["metadata"] = {"_nats.ver": "2.11.4", "_nats.level": "1", "_nats.req.level": "0"}
        actual["consumer_limits"] = {}
        self.assertEqual(NATS.project_native_nats_config(actual, "stream"),
                         NATS.project_native_nats_config(expected, "stream"))
        for key, value in [("republish", {"dest": "foreign"}), ("sealed", True),
                           ("no_ack", True), ("subjects", ["cdnca.>"]),
                           ("metadata", {"owner": "foreign"}), ("num_replicas", 2)]:
            changed = {**expected, key: value}
            self.assertNotEqual(NATS.project_native_nats_config(changed, "stream"),
                                NATS.project_native_nats_config(expected, "stream"))
        for changed in [{**expected, "unknown": False}, {**expected, "subjects": ["x", "x"]},
                        {**expected, "consumer_limits": {"unknown": 0}}]:
            with self.assertRaises(ValueError):
                NATS.project_native_nats_config(changed, "stream")
        consumer = profile["consumers"][0]["config"]
        for key, value in [("deliver_subject", "unexpected.push"), ("headers_only", True),
                           ("pause_until", "2099-01-01T00:00:00Z"), ("max_ack_pending", 1)]:
            self.assertNotEqual(NATS.project_native_nats_config({**consumer, key: value}, "consumer"),
                                NATS.project_native_nats_config(consumer, "consumer"))

    def test_cli_is_explicit_context_free_and_errors_do_not_leak(self):
        client = NATS.NativeNATS("nats://127.0.0.1:4222")
        with patch.dict(os.environ, {"NATS_CONTEXT": "private", "NATS_PASSWORD": "secret",
                                     "NATS_URL": "nats://untrusted:4222"}), patch.object(NATS.subprocess, "run") as run:
            run.return_value.returncode = 0
            run.return_value.stdout = '{"config": {}}'
            client.request("$JS.API.STREAM.INFO.AGENT_COMMANDS")
            args = run.call_args[0][0]
            self.assertEqual(args[0], "/usr/local/bin/nats")
            self.assertIn("--no-context", args)
            self.assertEqual(args[args.index("--server") + 1], "nats://127.0.0.1:4222")
            self.assertNotIn("NATS_PASSWORD", run.call_args[1]["env"])
            self.assertNotIn("NATS_CONTEXT", run.call_args[1]["env"])
            run.return_value.returncode = 1
            run.return_value.stdout = "secret server output"
            with self.assertRaisesRegex(RuntimeError, "NATS request failed") as result:
                client.request("$JS.API.INFO")
            self.assertNotIn("secret", str(result.exception))
            run.return_value.returncode = 0
            for value in ["", "[]", "not JSON", '{"error":{"err_code":99999,"description":"secret"}}']:
                run.return_value.stdout = value
                with self.assertRaises((ValueError, RuntimeError)) as result:
                    client.request("$JS.API.INFO")
                self.assertNotIn("secret", str(result.exception))

    def test_receipt_is_exclusive_private_and_no_symlinks(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "receipt.json"
            NATS.write_native_nats_receipt(target, {"status": "contract_verified"})
            self.assertEqual(target.stat().st_mode & 0o777, 0o600)
            with self.assertRaises(FileExistsError):
                NATS.write_native_nats_receipt(target, {"status": "replacement"})
            self.assertEqual(json.loads(target.read_text())["status"], "contract_verified")
            link = Path(directory) / "link.json"
            link.symlink_to(target)
            with self.assertRaises(FileExistsError):
                NATS.write_native_nats_receipt(link, {})

    def test_failed_receipt_write_leaves_no_success_receipt(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "receipt.json"
            with patch.object(NATS.os, "fsync", side_effect=OSError("storage failure")):
                with self.assertRaises(OSError):
                    NATS.write_native_nats_receipt(target, {"status": "contract_verified"})
            self.assertFalse(target.exists())

    def test_readonly_check_and_failed_install_never_write_receipt(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cli, profile = root / "nats", root / "profile.json"
            cli.write_text("fixture")
            cli.chmod(0o700)
            profile.write_text("{}")
            result = {"profile_sha256": "a" * 64}
            with patch.object(NATS, "CLI", cli), patch.object(NATS, "PROFILE", profile), \
                    patch.object(NATS.os, "geteuid", return_value=0), \
                    patch.object(NATS.Path, "lstat") as lstat, \
                    patch.object(NATS, "provision_native_nats", return_value=result) as provision, \
                    patch.object(NATS, "write_native_nats_receipt") as write, \
                    redirect_stderr(io.StringIO()), redirect_stdout(io.StringIO()):
                lstat.return_value = Mock(st_mode=0o100600, st_uid=0)
                self.assertEqual(NATS.native_nats_main(["check", "--server", "nats://127.0.0.1:4222"]), 0)
                write.assert_not_called()
                provision.assert_called_once()
                self.assertFalse(provision.call_args[1]["install"])
                self.assertEqual(NATS.native_nats_main(["check", "--server", "nats://127.0.0.1:4222",
                                                       "--receipt", str(root / "new")]), 1)
                self.assertEqual(NATS.native_nats_main(["install", "--server", "nats://127.0.0.1:4222"]), 1)
                write.assert_not_called()

    def test_main_refuses_invalid_receipt_and_partial_failure_publishes_none(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            cli, profile = root / "nats", root / "profile.json"
            cli.write_text("fixture")
            cli.chmod(0o700)
            profile.write_text("{}")
            target = root / "receipt.json"
            original_lstat = Path.lstat

            def root_owned(path, *args, **kwargs):
                info = original_lstat(path, *args, **kwargs)
                return Mock(st_mode=info.st_mode, st_uid=0)

            with patch.object(NATS, "CLI", cli), patch.object(NATS, "PROFILE", profile), \
                    patch.object(NATS.os, "geteuid", return_value=0), \
                    patch.object(NATS.Path, "lstat", root_owned), \
                    patch.object(NATS, "provision_native_nats") as provision, \
                    redirect_stderr(io.StringIO()), redirect_stdout(io.StringIO()):
                args = ["install", "--server", "nats://127.0.0.1:4222", "--receipt", str(target)]
                target.write_text("preserved")
                self.assertEqual(NATS.native_nats_main(args), 1)
                provision.assert_not_called()
                self.assertEqual(target.read_text(), "preserved")
                target.unlink()
                root.chmod(0o755)
                self.assertEqual(NATS.native_nats_main(args), 1)
                provision.assert_not_called()
                root.chmod(0o700)
                provision.side_effect = RuntimeError("partial create failed")
                self.assertEqual(NATS.native_nats_main(args), 1)
                provision.assert_called_once()
                self.assertFalse(target.exists())

    def test_preflight_rejects_version_auth_or_non_jetstream_before_requests(self):
        client = NATS.NativeNATS("nats://127.0.0.1:4222")
        profile = NATS.load_native_nats_profile()
        valid = {"version": "2.12.15-cdnca.1", "max_payload": 4194304, "jetstream": True}
        with patch.object(NATS.subprocess, "run") as run, \
                patch.object(NATS.socket, "create_connection") as connection, \
                patch.object(client, "request") as request:
            run.return_value.returncode = 0
            run.return_value.stdout = "0.2.4\n"
            line = connection.return_value.__enter__.return_value.makefile.return_value.__enter__.return_value.readline
            for info in [{**valid, "version": "2.11.4"}, {**valid, "version": "2.12.15"}, {**valid, "auth_required": True},
                         {**valid, "tls_required": True}, {**valid, "jetstream": False},
                         {**valid, "max_payload": 1048576}, {**valid, "max_payload": "4194304"}, []]:
                line.return_value = b"INFO " + json.dumps(info).encode() + b"\r\n"
                with self.assertRaises(ValueError):
                    client.preflight(profile)
                request.assert_not_called()
            line.return_value = b"INFO " + json.dumps(valid).encode() + b"\r\n"
            run.return_value.stdout = "0.2.5\n"
            with self.assertRaisesRegex(ValueError, "CLI version"):
                client.preflight(profile)
            request.assert_not_called()

    def test_missing_api_error_is_not_confused_with_permission_or_server_failure(self):
        client = NATS.NativeNATS("nats://127.0.0.1:4222")
        with patch.object(NATS.subprocess, "run") as run:
            run.return_value.returncode = 0
            run.return_value.stdout = '{"error":{"err_code":10059}}'
            self.assertIsNone(client.request("$JS.API.STREAM.INFO.A", missing=10059))
            for body in ['{"error":{"err_code":10014}}', '{"error":{"code":503}}', '{"error":null}']:
                run.return_value.stdout = body
                with self.assertRaises(RuntimeError):
                    client.request("$JS.API.STREAM.INFO.A", missing=10059)

    def test_check_never_creates_missing_resources(self):
        client = NATS.NativeNATS("nats://127.0.0.1:4222")
        with patch.object(client, "preflight"), patch.object(client, "request", return_value=None) as request:
            with self.assertRaisesRegex(ValueError, "missing"):
                NATS.provision_native_nats(client, install=False)
            self.assertTrue(request.call_args_list)
            self.assertTrue(all(".INFO." in call[0][0] for call in request.call_args_list))

    def test_existing_drift_aborts_before_any_create(self):
        client = NATS.NativeNATS("nats://127.0.0.1:4222")
        profile = NATS.load_native_nats_profile()
        drift = {**profile["streams"][-1], "max_bytes": 1}
        with patch.object(client, "preflight"), patch.object(client, "request") as request:
            request.side_effect = lambda subject, *args, **kwargs: {"config": drift} if subject.endswith(drift["name"]) else None
            with self.assertRaisesRegex(ValueError, "configuration drift"):
                NATS.provision_native_nats(client, install=True)
            self.assertFalse(any(".CREATE." in call[0][0] for call in request.call_args_list))


@unittest.skipUnless(os.environ.get("NATIVE_NATS_TEST_SERVER") and os.environ.get("NATIVE_NATS_TEST_CLI"),
                     "requires isolated real NATS 2.12.15-cdnca.1 and CLI 0.2.4 binaries")
class NativeNATSIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="cdnca-native-nats-test-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            self.port = reservation.getsockname()[1]
        self.server = f"nats://127.0.0.1:{self.port}"
        self.config = self.root / "nats.json"
        self.config.write_text(json.dumps({"host": "127.0.0.1", "port": self.port, "max_payload": 2162688,
                                           "jetstream": {"store_dir": str(self.root / "store")}}))
        self.start_server()
        self.client = NATS.NativeNATS(self.server, cli=Path(os.environ["NATIVE_NATS_TEST_CLI"]))

    def start_server(self):
        self.process = subprocess.Popen([os.environ["NATIVE_NATS_TEST_SERVER"], "-c", str(self.config)],
                                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.addCleanup(self.stop_server)
        for _ in range(100):
            try:
                with socket.create_connection(("127.0.0.1", self.port), timeout=0.1):
                    return
            except OSError:
                if self.process.poll() is not None:
                    self.fail("isolated NATS server failed to start")
                time.sleep(0.02)
        self.fail("isolated NATS server did not become ready")

    def stop_server(self):
        if self.process.poll() is None:
            self.process.terminate()
            self.process.wait(timeout=10)

    def test_fresh_exact_17_streams_10_durables_check_and_restart(self):
        with self.assertRaisesRegex(ValueError, "missing"):
            NATS.provision_native_nats(self.client, install=False)
        result = NATS.provision_native_nats(self.client, install=True)
        self.assertEqual((len(result["streams"]), len(result["consumers"])), (17, 10))
        names = self.client.request("$JS.API.STREAM.NAMES")["streams"]
        self.assertEqual(sorted(names), sorted(item["name"] for item in result["streams"]))
        before = {name: self.client.request(f"$JS.API.STREAM.INFO.{name}")["created"] for name in names}
        consumer_epochs = {item["name"]: self.client.request(f"$JS.API.CONSUMER.INFO.{item['name']}")["created"]
                           for item in result["consumers"]}
        repeated = NATS.provision_native_nats(self.client, install=True)
        self.assertEqual(result["streams"], repeated["streams"])
        NATS.provision_native_nats(self.client, install=False)
        self.stop_server()
        self.start_server()
        NATS.provision_native_nats(self.client, install=False)
        self.assertEqual(before, {name: self.client.request(f"$JS.API.STREAM.INFO.{name}")["created"] for name in names})
        self.assertEqual(consumer_epochs,
                         {name: self.client.request(f"$JS.API.CONSUMER.INFO.{name}")["created"] for name in consumer_epochs})

    def test_default_payload_limit_rejects_before_create(self):
        self.stop_server()
        config = json.loads(self.config.read_text())
        del config["max_payload"]
        self.config.write_text(json.dumps(config))
        self.start_server()
        with self.assertRaisesRegex(ValueError, "max_payload"):
            NATS.provision_native_nats(self.client, install=True)
        self.assertEqual(self.client.request("$JS.API.STREAM.NAMES").get("streams") or [], [])

    def test_existing_stream_drift_preserved_and_no_missing_stream_created(self):
        config = copy.deepcopy(NATS.load_native_nats_profile()["streams"][-1])
        config["max_bytes"] = 12345678
        self.client.request(f"$JS.API.STREAM.CREATE.{config['name']}", config)
        with self.assertRaisesRegex(ValueError, "configuration drift"):
            NATS.provision_native_nats(self.client, install=True)
        self.assertEqual(self.client.request("$JS.API.STREAM.NAMES")["streams"], [config["name"]])
        self.assertEqual(self.client.request(f"$JS.API.STREAM.INFO.{config['name']}")["config"]["max_bytes"], 12345678)

    def test_racing_consumer_create_cannot_overwrite_foreign_configuration(self):
        profile = NATS.load_native_nats_profile()
        target = profile["consumers"][0]
        subject = f"$JS.API.CONSUMER.CREATE.{target['stream']}.{target['config']['durable_name']}"
        original = self.client.request

        def race(actual_subject, payload=None, **kwargs):
            if actual_subject == subject:
                changed = copy.deepcopy(payload)
                changed["config"]["ack_wait"] += 1000000000
                original(actual_subject, changed)
            return original(actual_subject, payload, **kwargs)

        with patch.object(self.client, "request", side_effect=race), self.assertRaises(RuntimeError):
            NATS.provision_native_nats(self.client, install=True)
        info = original(subject.replace(".CREATE.", ".INFO."))
        self.assertEqual(info["config"]["ack_wait"], target["config"]["ack_wait"] + 1000000000)
        self.assertEqual(len(original("$JS.API.STREAM.NAMES")["streams"]), 17)

    def test_racing_stream_create_cannot_overwrite_foreign_configuration(self):
        target = NATS.load_native_nats_profile()["streams"][0]
        subject = f"$JS.API.STREAM.CREATE.{target['name']}"
        original = self.client.request

        def race(actual_subject, payload=None, **kwargs):
            if actual_subject == subject:
                original(actual_subject, {**payload, "max_msgs": 42})
            return original(actual_subject, payload, **kwargs)

        with patch.object(self.client, "request", side_effect=race), self.assertRaises(RuntimeError):
            NATS.provision_native_nats(self.client, install=True)
        self.assertEqual(original(subject.replace(".CREATE.", ".INFO."))["config"]["max_msgs"], 42)
        self.assertEqual(original("$JS.API.STREAM.NAMES")["streams"], [target["name"]])


if __name__ == "__main__":
    unittest.main()
