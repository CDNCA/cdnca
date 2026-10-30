#!/usr/bin/env python3
"""Create/check the fixed fresh native Control runtime environment.

The verified installer must first run the real dependency preflights, complete
PG migrations and enforce its fresh-install guard. This helper does not start
workers, activate an installation, modify business data or publish node trust.
Existing or partial state is never replaced. Secrets never enter argv/output.
"""
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import secrets
import shlex
import stat
import subprocess
import sys
import tempfile
import uuid

CONTROL = Path("/etc/cdnca-control")
ANALYTICS = Path("/etc/cdnca-analytics")
OBJECTSTORE = Path("/etc/cdnca-objectstore")
LOOPBACK = Path("/etc/clickhouse-server/config.d/cdnca-loopback.xml")
# The analytics receipt is written by configure-clickhouse.py from the same
# verified support tree: take its rollups and migration set, never a copy.
_spec = importlib.util.spec_from_file_location("native_clickhouse", Path(__file__).with_name("configure-clickhouse.py"))
_clickhouse = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_clickhouse)
ROLLUPS = _clickhouse.ROLLUPS


def native_runtime_clickhouse_migrations():
    return _clickhouse.native_clickhouse_migrations(Path(__file__).resolve().parents[2] / "infra/clickhouse/migrations")


def native_runtime_host_family(release_file=Path("/etc/os-release")):
    """rhel for Rocky/AlmaLinux/RHEL (dnf layout), otherwise the Debian layout."""
    try:
        text = release_file.read_text(encoding="utf-8")
    except OSError:
        return "debian"
    match = re.search(r"""^ID=["']?([a-z]+)["']?$""", text, re.M)
    return "rhel" if match and match.group(1) in ("rocky", "almalinux", "rhel") else "debian"


HOST_FAMILY = native_runtime_host_family()
# CA anchor and bundle (a regular file, read without following links) and the
# clamd socket installed by install-ubuntu-dependencies.sh for this family.
if HOST_FAMILY == "rhel":
    TRUST = Path("/etc/pki/ca-trust/source/anchors/cdnca-objectstore.crt")
    CA_BUNDLE = Path("/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem")
    CLAMD_SOCKET = "/run/clamd.scan/clamd.sock"
else:
    TRUST = Path("/usr/local/share/ca-certificates/cdnca-objectstore.crt")
    CA_BUNDLE = Path("/etc/ssl/certs/ca-certificates.crt")
    CLAMD_SOCKET = "/var/run/clamav/clamd.ctl"
OPENSSL = "/usr/bin/openssl"
# Installed (after hash pinning) by install-control.sh; all Ed25519 keys use it.
ED25519_TOOL = "/usr/local/libexec/cdnca/cdnca-ed25519"
COMMAND_ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"}
# Loopback file and ClickHouse URL follow the host port profile (fix-btenv),
# from the same parser configure-clickhouse.py and the dependency helper use.
LOOPBACK_CONTENT = _clickhouse.native_clickhouse_loopback_content()
CLICKHOUSE_URL = _clickhouse.native_clickhouse_http_url(_clickhouse.PORTS)
# install-rustfs.py receipts: the static musl build (fresh installs since
# 2026-10-15) and the gnu build of earlier installations, both RustFS 1.0.1.
RUSTFS_RECEIPT = {
    "schema": "cdnca.native-rustfs/v1", "version": "1.0.1",
    "archive_sha256": "a834096dafa1f1a55825a2cdaf49d006a193978d344f2d508c2be475133738a3",
    "binary_sha256": "a5ac41209ca8eca6c591c1584cc108b308850e1b74955afd4af9fe1b0379f2eb",
    "endpoint": "https://127.0.0.1:19000",
}
RUSTFS_RECEIPTS = (RUSTFS_RECEIPT, {
    **RUSTFS_RECEIPT,
    "archive_sha256": "9742e183cb0dfb0d48fa909797af572fe47b7f827569036baa4156e0d3958ee5",
    "binary_sha256": "e6544a42a09a16d6fea47ad3d8aaa1a8793c9afa9c723bb8ae884f1238cd7c25",
})
CH_KEYS = {"CLICKHOUSE_URL", "CLICKHOUSE_DATABASE", "CLICKHOUSE_USERNAME", "CLICKHOUSE_PASSWORD",
           "ANALYTICS_INGEST_CLICKHOUSE_URL", "ANALYTICS_INGEST_CLICKHOUSE_DATABASE",
           "ANALYTICS_INGEST_CLICKHOUSE_USER", "ANALYTICS_INGEST_CLICKHOUSE_PASSWORD"}
OBJECT_FIELDS = ("ENDPOINT", "REGION", "BUCKET", "ACCESS_KEY_ID", "SECRET_ACCESS_KEY", "PREFIX")
SECRET_ENV_KEYS = ("ANALYTICS_INGEST_ISOLATION_WRAPPING_KEY_BASE64", "ANALYTICS_REALTIME_CURSOR_KEY_BASE64")
FIXED_ENV = {
    "SYSTEM_CONFIGURATION_RUNTIME_ENABLED": "true",
    "EDGE_PUBLISH_RUNTIME_ENABLED": "true", "EDGE_PUBLISH_SIGNER_PROVIDER": "file",
    "CDNCA_SECURITY_ACTIVATION_ENABLED": "true",
    "CDNCA_SECURITY_ACTIVATION_RECONCILE_INTERVAL": "2s",
    "CDNCA_SECURITY_ACTIVATION_CANDIDATE_TTL": "15m",
    "CDNCA_SECURITY_ACTIVATION_REQUIRED_WAF_API_VERSION": "1",
    "CDNCA_SECURITY_ACTIVATION_REQUIRED_CC_API_VERSION": "2",
    "BRAND_ASSET_RUNTIME_ENABLED": "true", "ERROR_PAGE_RUNTIME_ENABLED": "true",
    "ERROR_PAGE_CLAMD_SOCKET": CLAMD_SOCKET,
    "ANALYTICS_QUERY_ENABLED": "true", "ANALYTICS_INGEST_ENABLED": "true",
    "ANALYTICS_INGEST_NATS_URL": "nats://127.0.0.1:4222",
    "ANALYTICS_INGEST_ISOLATION_WRAPPING_KEY_ID": "native-analytics-isolation-v1",
    "ANALYTICS_CONNECTIONS_RUNTIME_ENABLED": "true",
    "ANALYTICS_CONNECTIONS_NATS_URL": "nats://127.0.0.1:4222",
    "ANALYTICS_REALTIME_COVERAGE_FINALIZER_ENABLED": "true",
    # Realtime API (/v1/analytics/realtime) reads the same ClickHouse query identity.
    "ANALYTICS_REALTIME_RUNTIME_ENABLED": "true",
    # The geo artifact publisher needs an operator-supplied IP source catalog and
    # publisher key; without them control-api would not start.
    "ANALYTICS_GEO_ARTIFACT_ENABLED": "false",
    # Websites' own traffic caps (ge-analytics) read site traffic from ClickHouse;
    # the community edition has no package traffic enforcement (variable names kept).
    "PACKAGE_TRAFFIC_ENFORCEMENT_ENABLED": "true", "PACKAGE_TRAFFIC_ENFORCEMENT_WORKER_ID": "package-traffic-1",
    # 更换节点通讯端口 (FX39): AGENT_COMMANDS / AGENT_DEPLOYMENT_STATUS already
    # carry the gateway-port subjects (native-nats-profile.json); without this the
    # API only records transitions and never runs them.
    "NODE_PORT_TRANSITION_RUNTIME_ENABLED": "true",
}
ENVIRONMENT_KEYS = set(FIXED_ENV) | CH_KEYS | set(SECRET_ENV_KEYS) | {
    prefix + "_OBJECT_STORE_" + name for prefix in ("BRAND_ASSET", "ERROR_PAGE") for name in OBJECT_FIELDS
} | {"EDGE_PUBLISH_CURSOR_ACTIVE_KEY_ID", "EDGE_PUBLISH_CURSOR_KEYS_JSON", "EDGE_PUBLISH_SIGNING_KEY_ID",
     "EDGE_PUBLISH_SIGNING_PRIVATE_KEY_FILE",
     "ANALYTICS_LOGS_CURSOR_ACTIVE_KEY_ID", "ANALYTICS_LOGS_CURSOR_KEYS_JSON"}


def native_runtime_pairs(pairs):
    result = {}
    for name, value in pairs:
        if name in result:
            raise ValueError("duplicate configuration key")
        result[name] = value
    return result


def native_runtime_directory(path, mode=None):
    if not path.is_absolute() or ".." in path.parts:
        raise ValueError("expected absolute runtime directory")
    for parent in (*reversed(path.parents), path):
        info = parent.lstat()
        sticky = parent in (Path("/tmp"), Path("/private/tmp")) and info.st_uid == 0 and info.st_mode & stat.S_ISVTX
        if not stat.S_ISDIR(info.st_mode) or info.st_uid not in (0, os.geteuid()) or (info.st_mode & 0o022 and not sticky):
            raise ValueError("unsafe runtime parent directory")
    if path.stat().st_uid != os.geteuid() or mode is not None and stat.S_IMODE(path.stat().st_mode) != mode:
        raise ValueError("unsafe runtime directory ownership or mode")


def native_runtime_read(path, modes=(0o600,)):
    native_runtime_directory(path.parent)
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as source:
        info = os.fstat(source.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) not in modes:
            raise ValueError("unsafe runtime file")
        content = source.read(1024 * 1024 + 1)
    if len(content) > 1024 * 1024:
        raise ValueError("runtime input exceeds size limit")
    return content


def native_runtime_env(content):
    if b"\x00" in content or b"\r" in content:
        raise ValueError("invalid environment encoding")
    pairs = []
    for line in content.decode("utf-8").split("\n"):
        if not line or line.startswith("#"):
            continue
        name, separator, value = line.partition("=")
        if not separator or not re.fullmatch(r"[A-Z][A-Z0-9_]*", name) or any(ord(character) < 32 for character in value):
            raise ValueError("invalid environment entry")
        if value.startswith(("'", '"')):
            decoded = shlex.split(value, comments=False, posix=True)
            if len(decoded) != 1:
                raise ValueError("invalid quoted environment entry")
            value = decoded[0]
        pairs.append((name, value))
    return native_runtime_pairs(pairs)


def native_runtime_inputs():
    for path in (CONTROL, ANALYTICS, OBJECTSTORE):
        native_runtime_directory(path, 0o700)
    inputs = {
        "control": native_runtime_read(CONTROL / "control.env"),
        "analytics_env": native_runtime_read(ANALYTICS / "runtime.env"),
        "analytics_receipt": native_runtime_read(ANALYTICS / "receipt.json"),
        "analytics_installed": native_runtime_read(ANALYTICS / "installed.json"),
        "objects": native_runtime_read(OBJECTSTORE / "runtime.json"),
        "objects_installed": native_runtime_read(OBJECTSTORE / "installed.json"),
        "objects_ca": native_runtime_read(OBJECTSTORE / "ca.crt"),
        "objects_trust": native_runtime_read(TRUST, (0o644,)),
        "analytics_loopback": native_runtime_read(LOOPBACK, (0o640, 0o644)),
    }
    base, ch = native_runtime_env(inputs["control"]), native_runtime_env(inputs["analytics_env"])
    installation = uuid.UUID(base["CONTROL_INSTALLATION_ID"])
    if installation.int == 0 or str(installation) != base["CONTROL_INSTALLATION_ID"]:
        raise ValueError("noncanonical installation identity")
    for name in ("EDGE_DEPLOYMENT_NATS_URL", "NODE_PRESENCE_NATS_URL"):
        if base[name] != "nats://127.0.0.1:4222":
            raise ValueError("native NATS endpoint mismatch")
    if any(base.get(name) for name in ("EDGE_DEPLOYMENT_NATS_CREDS_FILE", "EDGE_DEPLOYMENT_NATS_CA_FILE")):
        raise ValueError("unexpected native NATS authentication profile")
    for name in base:
        if name.startswith(("SYSTEM_CONFIGURATION_RUNTIME_", "EDGE_PUBLISH_", "CDNCA_SECURITY_ACTIVATION_",
                            "BRAND_ASSET_", "ERROR_PAGE_", "ANALYTICS_", "CLICKHOUSE_")) and name not in ENVIRONMENT_KEYS:
            raise ValueError("unsupported native runtime setting in base environment")
    base_key = base64.b64decode(base["OPENRESTY_SECURITY_SECRET_KEY_BASE64"], validate=True)
    if len(base_key) != 32 or base64.b64encode(base_key).decode() != base["OPENRESTY_SECURITY_SECRET_KEY_BASE64"]:
        raise ValueError("invalid existing OpenResty key")
    if set(ch) != CH_KEYS:
        raise ValueError("unexpected analytics environment fields")
    database = ch["CLICKHOUSE_DATABASE"]
    if not re.fullmatch(r"(?:cdnca_|cdnca_ch_acceptance_)[a-z0-9_]{1,36}", database):
        raise ValueError("unexpected analytics database")
    if (ch["CLICKHOUSE_URL"] != CLICKHOUSE_URL or ch["ANALYTICS_INGEST_CLICKHOUSE_URL"] != ch["CLICKHOUSE_URL"]
            or ch["ANALYTICS_INGEST_CLICKHOUSE_DATABASE"] != database or ch["CLICKHOUSE_USERNAME"] != database + "_query"
            or ch["ANALYTICS_INGEST_CLICKHOUSE_USER"] != database + "_ingest"):
        raise ValueError("analytics runtime identity mismatch")
    passwords = [ch[name] for name in ("CLICKHOUSE_PASSWORD", "ANALYTICS_INGEST_CLICKHOUSE_PASSWORD")]
    if any(not re.fullmatch(r"[0-9a-f]{64}", password) for password in passwords) or len(set(passwords)) != 2:
        raise ValueError("analytics runtime credentials must be separate")
    installed = json.loads(inputs["analytics_installed"], object_pairs_hook=native_runtime_pairs)
    receipt = json.loads(inputs["analytics_receipt"], object_pairs_hook=native_runtime_pairs)
    if installed != {"schema": "cdnca.native-clickhouse-install/v1", "version": "25.3.6.56"}:
        raise ValueError("analytics installation receipt mismatch")
    if (not isinstance(receipt, dict) or set(receipt) != {"schema", "version", "database", "migrations", "rollup_definer", "rollups", "database_preflight"}
            or receipt["schema"] != "cdnca.native-clickhouse/v1" or receipt["version"] != "25.3.6.56"
            or receipt["database"] != database or receipt["rollup_definer"] != database + "_rollup"
            or receipt["rollups"] != ROLLUPS or receipt["database_preflight"] != "passed"
            or not isinstance(receipt["migrations"], list) or len(receipt["migrations"]) != len(native_runtime_clickhouse_migrations())):
        raise ValueError("analytics runtime receipt mismatch")
    for index, migration in enumerate(receipt["migrations"], 1):
        if (not isinstance(migration, dict) or set(migration) != {"path", "sha256"} or not re.fullmatch(f"{index:03}_[a-z0-9_]+[.]up[.]sql", migration["path"])
                or not re.fullmatch(r"[0-9a-f]{64}", migration["sha256"])):
            raise ValueError("analytics migration inventory mismatch")
    objects = json.loads(inputs["objects"], object_pairs_hook=native_runtime_pairs)
    if json.loads(inputs["objects_installed"], object_pairs_hook=native_runtime_pairs) not in RUSTFS_RECEIPTS:
        raise ValueError("object storage installation receipt mismatch")
    if (not isinstance(objects, dict) or set(objects) != {"endpoint", "region", "bucket", "users"} or objects["endpoint"] != RUSTFS_RECEIPT["endpoint"]
            or objects["region"] != "us-east-1" or objects["bucket"] != "cdnca-assets"
            or not isinstance(objects["users"], dict) or set(objects["users"]) != {"brand-assets", "error-pages"}):
        raise ValueError("object storage profile mismatch")
    for prefix, identity in objects["users"].items():
        if (not isinstance(identity, dict) or set(identity) != {"access_key", "secret_key", "prefix"} or identity["access_key"] != "cdnca-" + prefix
                or identity["prefix"] != prefix or not re.fullmatch(r"[0-9a-f]{64}", identity["secret_key"])):
            raise ValueError("object storage least-privilege identity mismatch")
        passwords.append(identity["secret_key"])
    if len(set(passwords)) != 4:
        raise ValueError("runtime identities must not share credentials")
    if inputs["analytics_loopback"] != LOOPBACK_CONTENT or inputs["objects_ca"] != inputs["objects_trust"]:
        raise ValueError("dependency isolation or trust mismatch")
    native_runtime_read(CA_BUNDLE, (0o644, 0o444))
    verified = subprocess.run([OPENSSL, "verify", "-CAfile", str(CA_BUNDLE), str(TRUST)],
                              env=COMMAND_ENV, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
    if verified.returncode:
        raise ValueError("object storage CA is not trusted by the system bundle")
    return base, ch, objects, {name: hashlib.sha256(content).hexdigest() for name, content in inputs.items()}


def native_runtime_keypair(private=None):
    # Key material only passes through a private scratch directory; the static
    # tool replaces OpenSSL genpkey/pkey (docs/install/ed25519-tool-security.md).
    with tempfile.TemporaryDirectory(prefix="cdnca-publisher-key-") as scratch:
        keyfile = Path(scratch) / "key.pem"
        if private is None:
            if subprocess.run([ED25519_TOOL, "genkey", str(keyfile)], env=COMMAND_ENV, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10).returncode:
                raise ValueError("failed to generate publisher key")
            private = keyfile.read_bytes()
        else:
            with os.fdopen(os.open(keyfile, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600), "wb") as output:
                output.write(private)
        if not re.fullmatch(rb"-----BEGIN PRIVATE KEY-----\n[A-Za-z0-9+/=\n]+-----END PRIVATE KEY-----\n", private):
            raise ValueError("invalid publisher private key encoding")
        der = base64.b64decode(b"".join(private.splitlines()[1:-1]), validate=True)
        if len(der) != 48 or not der.startswith(bytes.fromhex("302e020100300506032b657004220420")):
            raise ValueError("publisher key must be Ed25519 PKCS8")
        result = subprocess.run([ED25519_TOOL, "pubkey", str(keyfile), "--der"], env=COMMAND_ENV, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
    if result.returncode or len(result.stdout) != 44 or not result.stdout.startswith(bytes.fromhex("302a300506032b6570032100")):
        raise ValueError("invalid publisher public key")
    public = "-----BEGIN PUBLIC KEY-----\n" + base64.b64encode(result.stdout).decode() + "\n-----END PUBLIC KEY-----\n"
    return private, public, der[-32:]


def native_runtime_values(base, ch, objects, key_values, seed):
    decoded = [base64.b64decode(value, validate=True) for value in key_values]
    if (len(decoded) != 4 or any(len(value) != 32 or base64.b64encode(value).decode() != key_values[index]
                                for index, value in enumerate(decoded)) or len(set(decoded)) != 4
            or any(value in (seed, base64.b64decode(base["OPENRESTY_SECURITY_SECRET_KEY_BASE64"])) for value in decoded)):
        raise ValueError("runtime keys must be canonical, independent 32-byte values")
    env = dict(FIXED_ENV, **ch, **dict(zip(SECRET_ENV_KEYS, key_values[:2])))
    cursor_id = "native-edge-cursor-v1"
    env.update({"EDGE_PUBLISH_CURSOR_ACTIVE_KEY_ID": cursor_id,
                "EDGE_PUBLISH_CURSOR_KEYS_JSON": json.dumps({cursor_id: key_values[2]}, separators=(",", ":")),
                "ANALYTICS_LOGS_CURSOR_ACTIVE_KEY_ID": "native-analytics-logs-cursor-v1",
                "ANALYTICS_LOGS_CURSOR_KEYS_JSON": json.dumps({"native-analytics-logs-cursor-v1": key_values[3]}, separators=(",", ":")),
                "EDGE_PUBLISH_SIGNING_KEY_ID": "native-edge-" + base["CONTROL_INSTALLATION_ID"] + "-v1",
                "EDGE_PUBLISH_SIGNING_PRIVATE_KEY_FILE": str(CONTROL / "runtime-keys" / "edge-publish.pem")})
    for prefix, user in (("BRAND_ASSET", "brand-assets"), ("ERROR_PAGE", "error-pages")):
        identity = objects["users"][user]
        values = (objects["endpoint"], objects["region"], objects["bucket"], identity["access_key"], identity["secret_key"], identity["prefix"])
        env.update({prefix + "_OBJECT_STORE_" + name: value for name, value in zip(OBJECT_FIELDS, values)})
    if set(env) != ENVIRONMENT_KEYS or len(env) != 51 or any("'" in value or "\n" in value or "\x00" in value for value in env.values()):
        raise ValueError("unexpected generated runtime environment")
    return env


def native_runtime_write(path, content, mode):
    native_runtime_directory(path.parent)
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode), "wb") as output:
        os.fchmod(output.fileno(), mode)
        output.write(content)
        output.flush()
        os.fsync(output.fileno())
    descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def native_control_runtime(action):
    if action not in ("install", "check"):
        raise ValueError("expected install or check")
    base, ch, objects, inputs = native_runtime_inputs()
    directory = CONTROL / "runtime-keys"
    paths = {"private_key": directory / "edge-publish.pem", "public_trust": CONTROL / "runtime-publisher-trust.json",
             "environment": CONTROL / "runtime-extra.env", "receipt": CONTROL / "runtime-receipt.json"}
    existing = any(path.exists() or path.is_symlink() for path in (directory, *paths.values()))
    if existing:
        native_runtime_directory(directory, 0o700)
        if set(directory.iterdir()) != {paths["private_key"]}:
            raise ValueError("unknown publisher key state")
        stored = {name: native_runtime_read(path, (0o400,) if name == "public_trust" else (0o600,)) for name, path in paths.items()}
        current = native_runtime_env(stored["environment"])
        if set(current) != ENVIRONMENT_KEYS:
            raise ValueError("existing runtime environment mismatch")
        cursor = json.loads(current["EDGE_PUBLISH_CURSOR_KEYS_JSON"], object_pairs_hook=native_runtime_pairs)
        if set(cursor) != {"native-edge-cursor-v1"}:
            raise ValueError("existing publisher cursor mismatch")
        logs_cursor = json.loads(current["ANALYTICS_LOGS_CURSOR_KEYS_JSON"], object_pairs_hook=native_runtime_pairs)
        if set(logs_cursor) != {"native-analytics-logs-cursor-v1"}:
            raise ValueError("existing analytics logs cursor mismatch")
        key_values = [current[name] for name in SECRET_ENV_KEYS] + [cursor["native-edge-cursor-v1"], logs_cursor["native-analytics-logs-cursor-v1"]]
        private, public, seed = native_runtime_keypair(stored["private_key"])
    else:
        if action == "check":
            raise ValueError("runtime environment has not been installed")
        private, public, seed = native_runtime_keypair()
        key_values = [base64.b64encode(secrets.token_bytes(32)).decode() for _ in range(4)]
    env = native_runtime_values(base, ch, objects, key_values, seed)
    contents = {"private_key": private,
                "public_trust": (json.dumps({"version": 1, "keys": [{"key_id": env["EDGE_PUBLISH_SIGNING_KEY_ID"], "public_key_pem": public}]}, indent=2) + "\n").encode(),
                "environment": "".join(f"{name}='{env[name]}'\n" for name in sorted(env)).encode()}
    receipt = {"schema": "cdnca.native-control-runtime/v1", "installation_id": base["CONTROL_INSTALLATION_ID"],
               "inputs_sha256": inputs, "outputs_sha256": {name: hashlib.sha256(content).hexdigest() for name, content in contents.items()}}
    contents["receipt"] = (json.dumps(receipt, indent=2, sort_keys=True) + "\n").encode()
    if existing:
        if stored != contents:
            raise ValueError("runtime state differs; recovery required, no keys or state were changed")
        return
    # Exclusive directory creation is the install claim. A failed/competing
    # installation leaves private partial state for recovery, never rotation.
    directory.mkdir(mode=0o700)
    for name in ("private_key", "public_trust", "receipt", "environment"):
        native_runtime_write(paths[name], contents[name], 0o400 if name == "public_trust" else 0o600)


def native_control_runtime_main():
    if len(sys.argv) != 2 or sys.argv[1] not in ("install", "check"):
        raise ValueError("usage: configure-control-runtime.py install|check")
    if os.geteuid() != 0 or platform.system() != "Linux" or platform.machine() != "x86_64":
        raise ValueError("native runtime configuration requires Linux amd64 root")
    os.umask(0o077)
    native_control_runtime(sys.argv[1])
    print(json.dumps({"status": "passed", "action": sys.argv[1], "environment_file": str(CONTROL / "runtime-extra.env"),
                      "publisher_trust_file": str(CONTROL / "runtime-publisher-trust.json")}))


if __name__ == "__main__":
    try:
        native_control_runtime_main()
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        print("native Control runtime configuration failed; existing state preserved", file=sys.stderr)
        sys.exit(1)
