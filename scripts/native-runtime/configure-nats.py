#!/usr/bin/env python3
"""Create-only, fixed-contract JetStream provisioning for a local native install."""

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import stat
import subprocess
import sys


PROFILE = Path(__file__).with_name("native-nats-profile.json")
CLI = Path("/usr/local/bin/nats")
COMMAND_ENV = {"PATH": "/usr/bin:/bin", "LC_ALL": "C"}
STREAM_OPTIONAL = {
    "description": "", "discard_new_per_subject": False, "no_ack": False, "template_owner": "",
    "placement": None, "mirror": None, "sources": None, "sealed": False, "deny_delete": False,
    "deny_purge": False, "allow_rollup_hdrs": False, "first_seq": 0, "subject_transform": None,
    "republish": None, "allow_direct": False, "mirror_direct": False,
    "consumer_limits": {"inactive_threshold": 0, "max_ack_pending": 0},
    "allow_msg_ttl": False, "subject_delete_marker_ttl": 0, "metadata": {"_nats.req.level": "0"},
}
CONSUMER_OPTIONAL = {
    "description": "", "opt_start_seq": 0, "opt_start_time": None, "backoff": [],
    "filter_subject": "", "filter_subjects": [], "rate_limit_bps": 0, "sample_freq": "",
    "flow_control": False, "headers_only": False, "max_bytes": 0, "deliver_subject": "",
    "deliver_group": "", "idle_heartbeat": 0, "inactive_threshold": 0, "mem_storage": False,
    "direct": False, "metadata": {"_nats.req.level": "0"}, "pause_until": None,
    "priority_groups": [], "priority_policy": "none", "priority_timeout": 0,
}


def native_nats_url(server):
    match = re.fullmatch(r"nats://127\.0\.0\.1:([1-9][0-9]{0,4})", server)
    if not match or int(match[1]) > 65535:
        raise ValueError("NATS server must be an uncredentialed numeric loopback URL")
    return int(match[1])


def load_native_nats_profile():
    raw = PROFILE.read_bytes()
    profile = json.loads(raw)
    if (profile["schema"] != "cdnca.native-nats.profile/v1" or profile["server_version"] != "2.12.15-cdnca.1"
            or profile["cli_version"] != "0.2.4" or profile["min_max_payload"] != 2162688):
        raise ValueError("invalid native NATS profile")
    profile["streams"] = [{**profile["stream_defaults"], **item} for item in profile["streams"]]
    profile["consumers"] = [{**item, "config": {**profile["consumer_defaults"], **item["config"]}}
                            for item in profile["consumers"]]
    names = [item["name"] for item in profile["streams"]]
    durables = [(item["stream"], item["config"]["durable_name"]) for item in profile["consumers"]]
    if len(set(names)) != 17 or len(names) != 17 or len(set(durables)) != 10 or len(durables) != 10:
        raise ValueError("invalid native NATS resource inventory")
    if any(not re.fullmatch(r"[A-Za-z0-9_-]+", name) for name in names + [item[1] for item in durables]):
        raise ValueError("invalid native NATS resource name")
    if any(stream not in names for stream, _ in durables):
        raise ValueError("invalid native NATS consumer stream")
    profile["profile_sha256"] = hashlib.sha256(raw).hexdigest()
    return profile


def project_native_nats_config(config, kind):
    if not isinstance(config, dict):
        raise ValueError("invalid NATS resource configuration")
    optional = STREAM_OPTIONAL if kind == "stream" else CONSUMER_OPTIONAL
    required = ("name subjects retention max_consumers max_msgs max_bytes discard max_age "
                "max_msgs_per_subject max_msg_size storage num_replicas duplicate_window compression"
                if kind == "stream" else
                "durable_name deliver_policy ack_policy replay_policy ack_wait max_deliver max_waiting "
                "max_ack_pending max_batch max_expires num_replicas").split()
    permitted = set(required) | set(optional) | ({"name"} if kind == "consumer" else set())
    if set(required) - config.keys() or config.keys() - permitted:
        raise ValueError("unknown or missing NATS resource configuration field")
    value = {**optional, **config}
    metadata = value["metadata"]
    if not isinstance(metadata, dict):
        raise ValueError("invalid NATS resource metadata")
    value["metadata"] = {key: val for key, val in metadata.items() if key not in {"_nats.ver", "_nats.level"}}
    if kind == "stream":
        limits = value["consumer_limits"]
        if not isinstance(limits, dict) or limits.keys() - STREAM_OPTIONAL["consumer_limits"].keys():
            raise ValueError("invalid NATS consumer limits")
        value["consumer_limits"] = {**STREAM_OPTIONAL["consumer_limits"], **limits}
    else:
        value.setdefault("name", value["durable_name"])
    for field in ("subjects",) if kind == "stream" else ("filter_subjects",):
        subjects = value[field]
        if (not isinstance(subjects, list) or any(not isinstance(item, str) for item in subjects)
                or len(subjects) != len(set(subjects))):
            raise ValueError("invalid NATS subject set")
        value[field] = sorted(subjects)
    return value


class NativeNATS:
    def __init__(self, server, cli=CLI):
        self.port = native_nats_url(server)
        self.server, self.cli = server, cli

    def preflight(self, profile):
        try:
            result = subprocess.run([str(self.cli), "--no-context", "--version"], env=COMMAND_ENV,
                                    universal_newlines=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=8)
            with socket.create_connection(("127.0.0.1", self.port), timeout=5) as connection:
                with connection.makefile("rb") as stream:
                    line = stream.readline(16385)
            if not line.startswith(b"INFO ") or not line.endswith(b"\r\n") or len(line) > 16384:
                raise ValueError("invalid NATS server greeting")
            info = json.loads(line[5:])
        except (OSError, subprocess.TimeoutExpired, json.JSONDecodeError):
            raise RuntimeError("NATS preflight failed") from None
        if result.returncode or result.stdout.strip() not in {profile["cli_version"], "v" + profile["cli_version"]}:
            raise ValueError("NATS CLI version mismatch")
        if not isinstance(info, dict) or info.get("version") != profile["server_version"]:
            raise ValueError("NATS server version mismatch")
        if info.get("auth_required", False) or info.get("tls_required", False) or not info.get("jetstream"):
            raise ValueError("NATS server does not match the local native profile")
        if type(info.get("max_payload")) is not int or info["max_payload"] < profile["min_max_payload"]:
            raise ValueError("NATS max_payload is below the evidence contract")
        self.request("$JS.API.INFO")

    def request(self, subject, payload=None, missing=None):
        try:
            result = subprocess.run([str(self.cli), "--no-context", "--server", self.server, "--timeout", "5s",
                                     "request", "--raw", subject, json.dumps(payload or {})],
                                    env=COMMAND_ENV, universal_newlines=True, stdout=subprocess.PIPE,
                                    stderr=subprocess.DEVNULL, timeout=8)
        except (OSError, subprocess.TimeoutExpired):
            raise RuntimeError("NATS request failed") from None
        if result.returncode or len(result.stdout) > 1048576:
            raise RuntimeError("NATS request failed")
        try:
            response = json.loads(result.stdout)
        except json.JSONDecodeError:
            raise ValueError("invalid NATS response") from None
        if not isinstance(response, dict) or not response:
            raise ValueError("invalid NATS response")
        if "error" in response:
            error = response["error"]
            if isinstance(error, dict) and missing is not None and error.get("err_code") == missing:
                return None
            raise RuntimeError("NATS API rejected request")
        return response


def provision_native_nats(client, install=False):
    profile = load_native_nats_profile()
    client.preflight(profile)
    resources = [("stream", item["name"], item, item, 10059) for item in profile["streams"]]
    resources += [("consumer", item["stream"] + "." + item["config"]["durable_name"], item["config"],
                   {"stream_name": item["stream"], "config": item["config"], "action": "create"}, 10014)
                  for item in profile["consumers"]]
    missing = []
    missing_streams = set()
    # Inspect every existing target before any writes; never migrate drift in place.
    for kind, name, expected, payload, missing_code in resources:
        response = (None if kind == "consumer" and payload["stream_name"] in missing_streams else
                    client.request(f"$JS.API.{kind.upper()}.INFO.{name}", missing=missing_code))
        if response is None:
            missing.append((kind, name, payload))
            if kind == "stream":
                missing_streams.add(name)
        elif json.dumps(project_native_nats_config(response.get("config"), kind), sort_keys=True, allow_nan=False) != json.dumps(
                project_native_nats_config(expected, kind), sort_keys=True, allow_nan=False):
            raise ValueError(f"NATS configuration drift: {name}")
    if missing and not install:
        raise ValueError("NATS contract resources missing")
    for kind, name, payload in missing:
        client.request(f"$JS.API.{kind.upper()}.CREATE.{name}", payload)
    receipt = {"schema": "cdnca.native-nats.receipt/v1", "status": "contract_verified",
               "profile_sha256": profile["profile_sha256"], "server_version": profile["server_version"],
               "cli_version": profile["cli_version"], "verified_at": datetime.now(timezone.utc).isoformat(),
               "streams": [], "consumers": []}
    for kind, name, expected, _, _ in resources:
        response = client.request(f"$JS.API.{kind.upper()}.INFO.{name}")
        actual = json.dumps(project_native_nats_config(response.get("config"), kind), sort_keys=True, allow_nan=False)
        if actual != json.dumps(project_native_nats_config(expected, kind), sort_keys=True, allow_nan=False):
            raise ValueError(f"NATS configuration drift after provisioning: {name}")
        receipt[kind + "s"].append({"name": name, "config_sha256": hashlib.sha256(actual.encode()).hexdigest()})
    return receipt


def write_native_nats_receipt(path, receipt):
    # O_EXCL also rejects symlinks; an existing receipt is never replaced.
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    created = os.fstat(descriptor)
    try:
        with os.fdopen(descriptor, "w") as output:
            json.dump(receipt, output, sort_keys=True)
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
    except BaseException:
        current = path.lstat()
        if (current.st_dev, current.st_ino) == (created.st_dev, created.st_ino):
            path.unlink()
        raise


def native_nats_main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("install", "check"))
    parser.add_argument("--server", required=True)
    parser.add_argument("--receipt", type=Path)
    args = parser.parse_args(argv)
    try:
        if os.geteuid() != 0:
            raise ValueError("native NATS provisioning requires root")
        if (args.action == "install") != bool(args.receipt):
            raise ValueError("only install requires a new private receipt")
        native_nats_url(args.server)
        for path in (CLI, PROFILE):
            info = path.lstat()
            if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
                raise ValueError("native NATS inputs must be root-owned regular files without group/other writes")
        if not os.access(CLI, os.X_OK):
            raise ValueError("native NATS CLI is not executable")
        if args.receipt:
            parent = args.receipt.parent
            info = parent.lstat()
            if (not args.receipt.is_absolute() or parent != parent.resolve()
                    or not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o700):
                raise ValueError("receipt parent must be an existing root-private directory")
            if os.path.lexists(args.receipt):
                raise FileExistsError("receipt already exists")
        receipt = provision_native_nats(NativeNATS(args.server), install=args.action == "install")
        if args.receipt:
            write_native_nats_receipt(args.receipt, receipt)
        print(json.dumps({"status": "contract_verified", "streams": 17, "durables": 10,
                          "profile_sha256": receipt["profile_sha256"]}))
        return 0
    except (OSError, ValueError, RuntimeError, KeyError, TypeError):
        # No response bodies, CLI stderr, host context, or credentials enter receipts/logs.
        print("native NATS contract check failed; existing resources were not updated or deleted", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(native_nats_main())
