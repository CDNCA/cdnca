#!/usr/bin/env python3
"""Offline first-baseline layout only, supported amd64 hosts (os-support-matrix); never starts services.

The caller authenticates the input pins and activates the installation before
install. check needs no activation and leaves no state unless --stage-directory
explicitly requests a new private child of the inputs directory. Existing state
is never replaced; failed preparation is retained for diagnosis. The runner is
verified, not executed or installed. Its separate install-only tool follows this.
"""

import argparse
import base64
import configparser
import contextlib
import datetime
import fcntl
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import posixpath
import re
import stat
import struct
import subprocess
import sys
import tarfile
import tempfile
import uuid

OWNER = 0
ROOT = Path("/data/cdnca-native-root/cdnca")
STATE = Path("/var/lib/cdnca-upgrade")
STATUS = Path("/run/cdnca-upgrade")
MAINTENANCE = Path("/var/lib/cdnca-native-upgrade-maintenance")
CONFIG = Path("/etc/cdnca-upgrade")
LOCK = Path("/run/lock/cdnca-management-release.lock")
RUNNER_BINARY = Path("/usr/local/libexec/cdnca/native-control-upgrade-runner")
RUNNER_UNIT = Path("/etc/systemd/system/cdnca-native-control-upgrade-runner.service")
SYSTEMD_DIRS = tuple(Path(path) for path in ("/run/systemd/system", "/usr/lib/systemd/system", "/lib/systemd/system"))
MANIFEST = "release.manifest.json"
SIGNATURE = "release.manifest.sig"
SIGNED_SCHEMA = "cdnca.native-management.release/v2"
# The existing install-only runner profile is narrower than the Go 1 GiB limit.
ARCHIVE_LIMIT = 285229182
JSON_LIMIT = 8 << 20
HEX40 = r"[0-9a-f]{40}"
HEX64 = r"[0-9a-f]{64}"
VERSION = r"(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})"
MIGRATION = r"[0-9]{3}_[a-z0-9_]+\.(up|down)\.sql"


def sha256_stream(stream):
    """hashlib.file_digest (3.11+) with the same streaming semantics on older Python."""
    if hasattr(hashlib, "file_digest"):
        return hashlib.file_digest(stream, "sha256")
    digest = hashlib.sha256()
    for chunk in iter(lambda: stream.read(1 << 20), b""):
        digest.update(chunk)
    return digest


def os_release():
    """platform.freedesktop_os_release (3.10+), parsed without evaluation on older Python."""
    if hasattr(platform, "freedesktop_os_release"):
        return platform.freedesktop_os_release()
    values = {}
    with open("/etc/os-release", encoding="utf-8") as source:
        for line in source:
            name, separator, value = line.strip().partition("=")
            if separator and re.fullmatch(r"[A-Z][A-Z0-9_]*", name):
                values[name] = value[1:-1] if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'" else value
    return values


# Installed (after hash pinning) by install-control.sh; never the host OpenSSL.
ED25519_TOOL = "/usr/local/libexec/cdnca/cdnca-ed25519"
# Hosts from docs/install/os-support-matrix.md. RHEL-family VERSION_ID carries
# the point release (9.4); only the major version is compared.
SUPPORTED_HOSTS = {("ubuntu", "24.04"), ("ubuntu", "22.04"), ("ubuntu", "20.04"), ("debian", "10"), ("debian", "11"), ("debian", "12"), ("debian", "13"),
                   ("rocky", "8"), ("rocky", "9"), ("rocky", "10"), ("almalinux", "8"), ("almalinux", "9"), ("almalinux", "10"),
                   ("rhel", "8"), ("rhel", "9"), ("rhel", "10")}
RHEL_FAMILY = {"rocky", "almalinux", "rhel"}


def supported_host(release):
    identity, version = release.get("ID"), release.get("VERSION_ID", "")
    if identity in RHEL_FAMILY:
        version = version.split(".", 1)[0]
    return (identity, version) in SUPPORTED_HOSTS


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def secure_directory(path, allow_missing=False):
    require(path.is_absolute() and str(path) == os.path.normpath(path), "noncanonical directory")
    for parent in reversed((path, *path.parents)):
        if allow_missing and not os.path.lexists(parent):
            continue
        info = parent.lstat()
        sticky = parent in (Path("/tmp"), Path("/run/lock")) and info.st_uid == 0 and info.st_mode & stat.S_ISVTX
        require(stat.S_ISDIR(info.st_mode) and info.st_uid in (0, OWNER) and
                (not info.st_mode & 0o022 or sticky), "unsafe directory")


@contextlib.contextmanager
def read_regular(path, maximum, private=False):
    require(path.is_absolute() and str(path) == os.path.normpath(path), "noncanonical file")
    secure_directory(path.parent)
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), "rb") as source:
        before = os.fstat(source.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_uid == OWNER and before.st_nlink == 1 and
                not before.st_mode & 0o7022 and 0 <= before.st_size <= maximum and
                (not private or stat.S_IMODE(before.st_mode) == 0o600), "unsafe file")
        yield source
        after = os.fstat(source.fileno())
        require(all(getattr(before, key) == getattr(after, key) for key in
                    ("st_dev", "st_ino", "st_mode", "st_uid", "st_gid", "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns")), "input changed")


def decode_json(encoded):
    def members(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, "duplicate JSON member")
            result[key] = value
        return result
    return json.loads(encoded, object_pairs_hook=members)


def load_inputs(filename):
    require(os.geteuid() == OWNER and platform.system() == "Linux" and platform.machine() == "x86_64" and
            supported_host(os_release()),
            "requires root amd64 Ubuntu 24.04/22.04/20.04, Debian 10-13 or Rocky/AlmaLinux/RHEL 8/9/10")
    with read_regular(filename, 16384, private=True) as source:
        values = decode_json(source.read())
    require(isinstance(values, dict) and values.get("schema") in (
        "cdnca.native-management.baseline-input/v1", "cdnca.native-management.baseline-input/v2"), "invalid input schema")
    proof = "artifact_trust_file" if values["schema"].endswith("/v2") else "source_git"
    names = {"schema", "archive", "archive_sha256", "archive_bytes", "manifest", "manifest_sha256", "source_commit",
             "source_tree", "version", proof, "runner", "runner_sha256",
             "installation_id_file", "runner_environment_file"}
    # An initial baseline release (1.0.35) names no predecessor at all.
    if "previous_source_commit" in values:
        names.add("previous_source_commit")
    require(set(values) == names, "invalid input schema")
    for key in names - {"archive_bytes"}:
        require(isinstance(values[key], str), "invalid input type")
    for key in ("archive_sha256", "manifest_sha256", "runner_sha256"):
        require(re.fullmatch(HEX64, values[key]), "invalid digest pin")
    for key in ("source_commit", "source_tree", "previous_source_commit"):
        require(key not in values or re.fullmatch(HEX40, values[key]), "invalid source pin")
    for key in ("archive", "manifest", proof, "runner", "installation_id_file", "runner_environment_file"):
        value = values[key]
        require(value.startswith("/") and str(Path(value)) == value == os.path.normpath(value) and
                not any(ord(char) < 32 for char in value), "noncanonical input path")
    require(re.fullmatch(VERSION, values["version"]) and values["source_commit"] != values.get("previous_source_commit") and
            type(values["archive_bytes"]) is int and 1024 <= values["archive_bytes"] <= ARCHIVE_LIMIT, "invalid release pin")
    require(stat.S_IMODE(filename.parent.stat().st_mode) == 0o700, "inputs directory must be private")
    for key in ("installation_id_file", "runner_environment_file"):
        value = Path(values[key])
        require(value.parent == CONFIG and value.name not in ("native-baseline-source.env", "native-control-upgrade-runner.env") and
                str(value) == os.path.normpath(value), "configuration must be prepared separately under fixed config directory")
    return values


def validate_manifest(encoded, inputs):
    manifest = decode_json(encoded)
    signed = inputs["schema"] == "cdnca.native-management.baseline-input/v2"
    fields = {"schema", "version", "built_at", "source", "platform", "files"} | ({"key_id"} if signed else set())
    require(isinstance(manifest, dict) and set(manifest) == fields, "invalid manifest schema")
    require(not signed or (isinstance(manifest["key_id"], str) and re.fullmatch(r"[A-Za-z0-9._-]{1,128}", manifest["key_id"])), "invalid artifact key ID")
    require(manifest["schema"] == (SIGNED_SCHEMA if signed else "cdnca.native-management.release/v1") and manifest["version"] == inputs["version"] and
            manifest["platform"] == {"os": "linux", "arch": "amd64"} and manifest["source"] == {
                "commit": inputs["source_commit"], "tree": inputs["source_tree"],
                **({"previous_commit": inputs["previous_source_commit"]} if "previous_source_commit" in inputs else {})}, "manifest pin mismatch")
    date = manifest["built_at"]
    require(isinstance(date, str) and re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]+)?(Z|[+-][0-9]{2}:[0-9]{2})", date), "invalid build time")
    # fromisoformat (3.7+) on Python 3.6: the regex fixed the shape, check the values.
    datetime.datetime(*map(int, re.match(r"(\d+)-(\d+)-(\d+)T(\d+):(\d+):(\d+)", date).groups()))
    require(isinstance(manifest["files"], list) and 4 <= len(manifest["files"]) <= 65535, "invalid file count")
    previous, files = "", {}
    for entry in manifest["files"]:
        require(isinstance(entry, dict) and set(entry) == {"path", "sha256", "bytes", "mode"}, "invalid file record")
        name = entry["path"]
        require(isinstance(name, str) and name not in ("", ".", "..", MANIFEST) and len(name.encode("utf-8")) <= 1024 and
                posixpath.normpath(name) == name and not name.startswith(("/", "../")) and
                not any(ord(char) < 32 or char == "\\" for char in name) and name > previous, "invalid file path")
        require(type(entry["mode"]) is int and entry["mode"] in (0o644, 0o755) and type(entry["bytes"]) is int and
                0 <= entry["bytes"] <= ARCHIVE_LIMIT and isinstance(entry["sha256"], str) and
                re.fullmatch(HEX64, entry["sha256"]), "invalid file metadata")
        require(name in ("bin/control-api", "bin/agent-gateway", "clickhouse/configure-clickhouse.py") or
                (name == "docs/platform-admin-recovery.md" and entry["mode"] == 0o644) or
                name.startswith("static/web/") or re.fullmatch("migrations/" + MIGRATION, name) or
                re.fullmatch(r"clickhouse/migrations/[0-9]{3}_[a-z0-9_]+\.up\.sql", name), "not a first-baseline component")
        files[name], previous = entry, name
    for name in ("bin/control-api", "bin/agent-gateway", "static/web/index.html"):
        require(name in files and files[name]["bytes"] > 0 and (not name.startswith("bin/") or files[name]["mode"] == 0o755), "incomplete native baseline")
    require(any(name.startswith("migrations/") for name in files), "missing migrations")
    for name, item in files.items():
        if name.startswith("migrations/"):
            peer = re.sub(r"\.(up|down)\.sql$", lambda match: "." + ("down" if match[1] == "up" else "up") + ".sql", name)
            require(item["mode"] == 0o644 and peer in files, "incomplete migration pair")
    return manifest


def verify_artifact_signature(trust_path, manifest, encoded, signature):
    with read_regular(trust_path, 65536) as source:
        trust = decode_json(source.read())
    require(isinstance(trust, dict) and set(trust) == {"version", "keys"} and type(trust["version"]) is int and
            trust["version"] == 1 and isinstance(trust["keys"], list) and 1 <= len(trust["keys"]) <= 32, "invalid artifact trust")
    keys = {}
    for key in trust["keys"]:
        require(isinstance(key, dict) and set(key) == {"key_id", "public_key_pem"} and isinstance(key["key_id"], str) and
                re.fullmatch(r"[A-Za-z0-9._-]{1,128}", key["key_id"]) and key["key_id"] not in keys and
                isinstance(key["public_key_pem"], str) and 0 < len(key["public_key_pem"]) <= 4096, "invalid artifact trust key")
        match = re.fullmatch(r"-----BEGIN PUBLIC KEY-----\n([A-Za-z0-9+/=\n]+)-----END PUBLIC KEY-----\n?", key["public_key_pem"])
        require(match is not None, "invalid artifact public key")
        public = base64.b64decode(match[1].replace("\n", ""), validate=True)
        require(len(public) == 44 and public[:12] == bytes.fromhex("302a300506032b6570032100"), "artifact key must be Ed25519")
        keys[key["key_id"]] = key["public_key_pem"]
    require(manifest["key_id"] in keys and len(signature) <= 128, "unknown artifact signing key")
    encoded_signature = signature[:-1] if signature.endswith(b"\n") else signature
    decoded = base64.b64decode(encoded_signature, validate=True)
    require(len(decoded) == 64 and base64.b64encode(decoded) == encoded_signature, "invalid artifact signature")
    with tempfile.TemporaryDirectory(prefix=".artifact-verify-", dir=trust_path.parent) as directory:
        directory = Path(directory)
        keyfile, signaturefile, message = (directory / name for name in ("public.pem", "signature", "message"))
        keyfile.write_text(keys[manifest["key_id"]], encoding="ascii")
        signaturefile.write_bytes(decoded)
        message.write_bytes((SIGNED_SCHEMA + "\n").encode() + encoded)
        result = subprocess.run([ED25519_TOOL, "verify", str(keyfile), str(message), str(signaturefile)], stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL, timeout=15, env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"})
        require(result.returncode == 0, "artifact signature mismatch")


def validate_archive(inputs, manifest, encoded, destination=None):
    expected = {item["path"]: item for item in manifest["files"]}
    expected[MANIFEST] = {"mode": 0o644, "bytes": len(encoded), "sha256": hashlib.sha256(encoded).hexdigest()}
    signed, signature = manifest["schema"] == SIGNED_SCHEMA, None
    with read_regular(Path(inputs["archive"]), ARCHIVE_LIMIT, private=True) as source:
        require(os.fstat(source.fileno()).st_size == inputs["archive_bytes"] and
                sha256_stream(source).hexdigest() == inputs["archive_sha256"], "archive digest mismatch")
        source.seek(0)
        seen = set()
        with tarfile.open(fileobj=source, mode="r:") as package:
            for member in package:
                require((member.name in expected or (signed and member.name == SIGNATURE)) and member.name not in seen and member.type == tarfile.REGTYPE and
                        not member.linkname and not member.pax_headers, "unsafe archive member")
                position = source.tell()
                source.seek(member.offset)
                header = source.read(512)
                source.seek(position)
                require(header[156:157] in (b"0", b"\0") and header[257:263] == b"ustar\0", "archive must be plain ustar")
                stream = package.extractfile(member)
                if signed and member.name == SIGNATURE:
                    require(member.mode == 0o644 and 0 < member.size <= 128, "invalid signature member")
                    signature = stream.read()
                    verify_artifact_signature(Path(inputs["artifact_trust_file"]), manifest, encoded, signature)
                    expected[SIGNATURE] = {"mode": 0o644, "bytes": len(signature), "sha256": hashlib.sha256(signature).hexdigest()}
                    stream.seek(0)
                item = expected[member.name]
                require(member.mode == item["mode"] and member.size == item["bytes"], "archive metadata mismatch")
                first = stream.read(64)
                if member.name in ("bin/control-api", "bin/agent-gateway"):
                    require(len(first) == 64 and first[:7] == b"\x7fELF\x02\x01\x01" and
                            struct.unpack_from("<H", first, 16)[0] in (2, 3) and struct.unpack_from("<H", first, 18)[0] == 62, "invalid native ELF")
                stream.seek(0)
                if destination is not None:
                    target = destination / member.name
                    target.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
                    size, digest = write_exclusive(target, stream, item["mode"])
                else:
                    digest = sha256_stream(stream).hexdigest()
                    size = stream.tell()
                require(size == item["bytes"] and digest == item["sha256"], "archive content mismatch")
                seen.add(member.name)
            require(seen == set(expected), "incomplete archive files")
            require(not signed or signature is not None, "missing artifact signature")
            source.seek(package.offset)
            remaining = source.read()
            require(len(remaining) >= 1024 and len(remaining) % 512 == 0 and not any(remaining), "invalid archive trailer")


def git_command(directory, *arguments):
    environment = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C", "GIT_CONFIG_NOSYSTEM": "1",
                   "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_TERMINAL_PROMPT": "0", "GIT_OPTIONAL_LOCKS": "0", "GIT_NO_LAZY_FETCH": "1"}
    result = subprocess.run(["git", "--no-replace-objects", "--git-dir=" + str(directory), "-c", "protocol.allow=never",
                             "-c", "core.hooksPath=/dev/null", "-c", "core.commitGraph=false", *arguments],
                            env=environment, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=60)
    require(result.returncode == 0, "offline Git validation failed")
    return result.stdout


def owned_tree(directory):
    secure_directory(directory)
    files = []
    for parent, children, names in os.walk(directory, followlinks=False):
        for name in children:
            secure_directory(Path(parent) / name)
        for name in names:
            path = Path(parent) / name
            info = path.lstat()
            require(stat.S_ISREG(info.st_mode) and info.st_uid == OWNER and info.st_nlink == 1 and not info.st_mode & 0o7022, "unsafe source file")
            files.append(path)
    return sorted(files)


def validate_source(inputs, manifest):
    directory = Path(inputs["source_git"])
    files = owned_tree(directory)
    for relative in ("shallow", "commondir", "gitdir", "config.worktree", "objects/info/alternates", "objects/info/http-alternates", "info/grafts", "refs/replace",
                     "objects/info/commit-graph", "objects/info/commit-graphs", "objects/pack/multi-pack-index"):
        require(not os.path.lexists(directory / relative), "delegated or rewritten Git history")
    require(not any(path.name.endswith(".promisor") for path in files), "partial Git source is forbidden")
    with read_regular(directory / "config", 4096) as source:
        configuration = configparser.ConfigParser(interpolation=None, strict=True)
        configuration.read_string(source.read().decode("ascii"))
    allowed = {"repositoryformatversion": {"0"}, "bare": {"true"},
               **{key: {"true", "false"} for key in ("filemode", "logallrefupdates", "ignorecase", "precomposeunicode")}}
    require(not configuration.defaults() and configuration.sections() == ["core"] and
            all(key in allowed and value in allowed[key] for key, value in configuration["core"].items()) and
            configuration["core"].get("bare") == "true" and configuration["core"].get("repositoryformatversion") == "0", "source must be a self-contained bare Git repository")
    require(not git_command(directory, "for-each-ref", "refs/replace"), "replacement Git references are forbidden")
    lineage = [key for key in ("source_commit", "previous_source_commit") if key in inputs]
    for key in lineage:
        require(git_command(directory, "rev-parse", "--verify", inputs[key] + "^{commit}").decode().strip() == inputs[key], "invalid source commit")
    require(git_command(directory, "rev-parse", "--verify", inputs["source_commit"] + "^{tree}").decode().strip() == inputs["source_tree"], "source tree mismatch")
    if "previous_source_commit" in inputs:
        git_command(directory, "merge-base", "--is-ancestor", inputs["previous_source_commit"], inputs["source_commit"])
    git_command(directory, "fsck", "--full", "--strict", "--no-reflogs", inputs["source_commit"])
    migrations = {}
    for entry in git_command(directory, "ls-tree", "-z", inputs["source_commit"] + ":services/control-api/migrations").split(b"\0"):
        if not entry:
            continue
        metadata, name = entry.decode("ascii").split("\t", 1)
        if re.fullmatch(MIGRATION, name):
            mode, kind, object_id = metadata.split()
            require(mode == "100644" and kind == "blob" and re.fullmatch(HEX40, object_id), "invalid migration source")
            migrations["migrations/" + name] = git_command(directory, "cat-file", "blob", object_id)
    expected = {item["path"]: item for item in manifest["files"] if item["path"].startswith("migrations/")}
    require(migrations and set(migrations) == set(expected), "incomplete source migration set")
    for name, body in migrations.items():
        peer = re.sub(r"\.(up|down)\.sql$", lambda match: "." + ("down" if match[1] == "up" else "up") + ".sql", name)
        require(peer in migrations and len(body) == expected[name]["bytes"] and
                hashlib.sha256(body).hexdigest() == expected[name]["sha256"], "migration differs from source")


def fresh_paths():
    for path in (ROOT, STATE, STATUS, MAINTENANCE, RUNNER_BINARY, RUNNER_UNIT,
                 CONFIG / "native-control-upgrade-runner.env", CONFIG / "native-baseline-source.env"):
        require(not os.path.lexists(path), "existing native state; fresh install refused")
        secure_directory(path.parent, allow_missing=True)
    for directory in (RUNNER_UNIT.parent, *SYSTEMD_DIRS):
        for name in (RUNNER_UNIT.name, "cdnca-control-upgrade-runner.service"):
            # glob() drops dangling enablement links before Python 3.8; lexists does not.
            require(not os.path.lexists(directory / name) and not os.path.lexists(directory / (name + ".d")) and
                    not any(os.path.lexists(parent / name) for parent in directory.glob("*.wants")) and
                    not any(os.path.lexists(parent / name) for parent in directory.glob("*.requires")), "existing runner unit state")


def verify_inputs(filename):
    inputs = load_inputs(filename)
    with read_regular(Path(inputs["manifest"]), JSON_LIMIT) as source:
        encoded = source.read()
    require(hashlib.sha256(encoded).hexdigest() == inputs["manifest_sha256"], "sidecar digest mismatch")
    manifest = validate_manifest(encoded, inputs)
    validate_archive(inputs, manifest, encoded)
    if manifest["schema"] != SIGNED_SCHEMA:
        validate_source(inputs, manifest)
    with read_regular(Path(inputs["runner"]), ARCHIVE_LIMIT) as source:
        first = source.read(64)
        require(len(first) == 64 and first[:7] == b"\x7fELF\x02\x01\x01" and struct.unpack_from("<H", first, 16)[0] in (2, 3) and
                struct.unpack_from("<H", first, 18)[0] == 62 and stat.S_IMODE(os.fstat(source.fileno()).st_mode) in (0o700, 0o755), "invalid standalone runner ELF")
        source.seek(0)
        require(sha256_stream(source).hexdigest() == inputs["runner_sha256"], "runner digest mismatch")
    fresh_paths()
    return inputs, manifest, encoded


def sync_directory(directory):
    descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def write_exclusive(filename, source, mode):
    if isinstance(source, bytes):
        source = io.BytesIO(source)
    digest, size = hashlib.sha256(), 0
    with os.fdopen(os.open(filename, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode), "wb") as target:
        os.fchmod(target.fileno(), mode)
        for chunk in iter(lambda: source.read(1 << 20), b""):
            target.write(chunk)
            digest.update(chunk)
            size += len(chunk)
        target.flush()
        os.fsync(target.fileno())
    sync_directory(filename.parent)
    return size, digest.hexdigest()


def extract_release(inputs, manifest, encoded, destination, mode):
    destination.mkdir(mode=0o700)
    validate_archive(inputs, manifest, encoded, destination)
    directories = [Path(parent) for parent, _, _ in os.walk(destination)]
    for directory in reversed(directories):
        os.chmod(directory, mode if directory == destination else 0o755)
        sync_directory(directory)
    sync_directory(destination.parent)


def copy_source(inputs, manifest):
    original, destination = Path(inputs["source_git"]), STATE / "source.git"
    destination.mkdir(mode=0o700)
    for source in owned_tree(original):
        target = destination / source.relative_to(original)
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        with read_regular(source, source.stat().st_size) as content:
            write_exclusive(target, content, stat.S_IMODE(source.stat().st_mode))
    copied = {**inputs, "source_git": str(destination)}
    validate_source(copied, manifest)
    for parent, _, _ in os.walk(destination, topdown=False):
        sync_directory(Path(parent))
    sync_directory(STATE)


def relative_to(path, base):
    """Path.is_relative_to (3.9+): lexical containment, base included."""
    return path == base or base in path.parents


def check(filename, stage_directory=None):
    inputs, manifest, encoded = verify_inputs(filename)
    result = {"status": "baseline_checked_not_activated", "archive_sha256": inputs["archive_sha256"]}
    if stage_directory is not None:
        require(stage_directory.parent == filename.parent and not os.path.lexists(stage_directory) and
                not any(relative_to(stage_directory, path) or relative_to(path, stage_directory)
                        for path in (ROOT, STATE, STATUS, MAINTENANCE, CONFIG, RUNNER_BINARY, RUNNER_UNIT, LOCK)), "unsafe staging directory")
        secure_directory(stage_directory.parent)
        extract_release(inputs, manifest, encoded, stage_directory, 0o700)
        result["stage_directory"] = str(stage_directory)
    return result


def install(filename):
    inputs, manifest, encoded = verify_inputs(filename)
    secure_directory(CONFIG)
    with read_regular(Path(inputs["installation_id_file"]), 128, private=True) as source:
        installation_id = source.read().decode("ascii").strip()
    require(str(uuid.UUID(installation_id)) == installation_id and uuid.UUID(installation_id).int != 0, "invalid activated installation ID")
    with read_regular(Path(inputs["runner_environment_file"]), 16384, private=True) as source:
        require(source.read(), "missing separately prepared runner environment")
    secure_directory(LOCK.parent)
    with os.fdopen(os.open(LOCK, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600), "r+b") as lock:
        info = os.fstat(lock.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_uid == OWNER and info.st_nlink == 1 and stat.S_IMODE(info.st_mode) in (0o600, 0o640), "unsafe release lock")
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        fresh_paths()
        for target in (ROOT.parent, RUNNER_BINARY.parent, RUNNER_UNIT.parent):
            for parent in reversed((target, *target.parents)):
                if not os.path.lexists(parent):
                    parent.mkdir(mode=0o755)
                    os.chmod(parent, 0o755)
                    sync_directory(parent.parent)
        for directory, mode in ((ROOT, 0o755), (ROOT / "releases", 0o755), (ROOT / "artifacts", 0o755),
                                (STATE, 0o700), (STATUS, 0o2750), (MAINTENANCE, 0o2750)):
            directory.mkdir(mode=0o700)
            os.chown(directory, OWNER, 0)
            os.chmod(directory, mode)
            sync_directory(directory.parent)
        artifact = ROOT / "artifacts" / (inputs["archive_sha256"] + ".tar")
        with read_regular(Path(inputs["archive"]), ARCHIVE_LIMIT, private=True) as source:
            size, digest = write_exclusive(artifact, source, 0o600)
        require((size, digest) == (inputs["archive_bytes"], inputs["archive_sha256"]), "copied artifact changed")
        destination = ROOT / "releases" / digest
        extract_release({**inputs, "archive": str(artifact)}, manifest, encoded, destination, 0o755)
        if manifest["schema"] == SIGNED_SCHEMA:
            with read_regular(Path(inputs["artifact_trust_file"]), 65536) as source:
                write_exclusive(STATE / "artifact-trust.json", source, 0o600)
            # Revalidate against the durable independent trust before publication.
            validate_archive({**inputs, "archive": str(artifact), "artifact_trust_file": str(STATE / "artifact-trust.json")}, manifest, encoded)
        else:
            copy_source(inputs, manifest)
        maintenance = {"schema": "cdnca.native-management.maintenance/v1", "installation_id": installation_id,
                       "phase": "active", "plan_id": "", "observed_at": datetime.datetime.now(datetime.timezone.utc).isoformat()}
        write_exclusive(MAINTENANCE / "maintenance.json", json.dumps(maintenance).encode(), 0o640)
        write_exclusive(MAINTENANCE / "maintenance.json.lock", b"", 0o640)
        provenance = {"CONTROL_VERSION": inputs["version"], "NATIVE_BASELINE_SOURCE_COMMIT": inputs["source_commit"],
                      "NATIVE_BASELINE_SOURCE_TREE": inputs["source_tree"], "NATIVE_BASELINE_ARCHIVE_SHA256": digest,
                      "NATIVE_BASELINE_CONTROL_BINARY": str(ROOT / "current/bin/control-api"),
                      "NATIVE_BASELINE_GATEWAY_BINARY": str(ROOT / "current/bin/agent-gateway"),
                      "NATIVE_BASELINE_WEB_ROOT": str(ROOT / "current/static/web")}
        write_exclusive(CONFIG / "native-baseline-source.env", "".join(key + "=" + value + "\n" for key, value in provenance.items()).encode("ascii"), 0o600)
        current, temporary, published = ROOT / "current", ROOT / ".initial-current", None
        try:
            os.symlink(destination, temporary)
            published = temporary.lstat()
            os.link(temporary, current, follow_symlinks=False)  # Atomic no-replace; never invent previous.
            temporary.unlink()
            sync_directory(ROOT)
        except Exception:
            for path in (current, temporary):
                if published is not None and os.path.lexists(path):
                    actual = path.lstat()
                    if (actual.st_dev, actual.st_ino) == (published.st_dev, published.st_ino):
                        path.unlink()
            sync_directory(ROOT)
            raise
    return {"status": "baseline_prepared_not_started", "archive_sha256": digest}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("check", "install"))
    parser.add_argument("--inputs", required=True, type=Path)
    parser.add_argument("--stage-directory", type=Path)
    args = parser.parse_args()
    try:
        require(args.action == "check" or args.stage_directory is None, "staging is check-only")
        result = check(args.inputs, args.stage_directory) if args.action == "check" else install(args.inputs)
        print(json.dumps(result))
    except Exception as error:
        print("native baseline rejected (%s: %s); no service was started; preserve partial preparation for inspection" %
              (type(error).__name__, error), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
