#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C

# Install-only: the caller must authenticate both supplied SHA-256 values and
# verify the complete signed baseline. This is not a release/bootstrap verifier.
native_runner_installer_main() {
  python3 -I - "$@" <<'PY'
import argparse, base64, datetime, hashlib, ipaddress, json, os, pathlib, platform, re, stat, struct, subprocess, sys, tempfile, uuid

OWNER = 0
CONFIG = "/etc/cdnca-upgrade"
RELEASE = "/data/cdnca-native-root/cdnca"
STATE = "/var/lib/cdnca-upgrade"
STATUS = "/run/cdnca-upgrade"
MAINTENANCE = "/var/lib/cdnca-native-upgrade-maintenance"
LOCK = "/run/lock/cdnca-management-release.lock"
BINARY = "/usr/local/libexec/cdnca/native-control-upgrade-runner"
ENVIRONMENT = CONFIG + "/native-control-upgrade-runner.env"
UNIT = "cdnca-native-control-upgrade-runner.service"
UNIT_PATH = "/etc/systemd/system/" + UNIT
TMPFILES_NAME = "cdnca-native-control-upgrade-runner.conf"
TMPFILES_PATH = "/etc/tmpfiles.d/" + TMPFILES_NAME
created = []
phase = "arguments"

def native_runner_strip_newline(value):
    return value[:-1] if value.endswith(b"\n") else value


def native_runner_require(condition):
    if not condition:
        raise ValueError("static requirement failed")

def native_runner_directory(path):
    native_runner_require(path.startswith("/") and os.path.normpath(path) == path and os.path.realpath(path) == path)
    cursor = path
    while True:  # protected parent chain
        info = os.lstat(cursor)
        native_runner_require(stat.S_ISDIR(info.st_mode) and info.st_uid == OWNER and
                              (not info.st_mode & 0o022 or info.st_mode & stat.S_ISVTX))
        if cursor == "/":
            break
        cursor = os.path.dirname(cursor)
    return os.lstat(path)

def native_runner_file(path, maximum=1048576, secret=False, modes=None, empty=False):
    native_runner_require(os.path.isabs(path) and os.path.normpath(path) == path)
    native_runner_directory(os.path.dirname(path))
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), "rb") as source:
        info = os.fstat(source.fileno())
        native_runner_require(stat.S_ISREG(info.st_mode) and info.st_uid == OWNER and info.st_nlink == 1 and
                              not info.st_mode & 0o022 and (empty or info.st_size > 0) and info.st_size <= maximum)
        native_runner_require(not secret or not info.st_mode & 0o077)
        native_runner_require(modes is None or stat.S_IMODE(info.st_mode) in modes)
        data = source.read(maximum + 1)
        after = os.fstat(source.fileno())
        native_runner_require(len(data) == info.st_size and all(getattr(after, field) == getattr(info, field) for field in
                              ("st_dev", "st_ino", "st_mode", "st_uid", "st_gid", "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns")))
        return data

def native_runner_json(pairs):
    result = {}
    for key, value in pairs:
        native_runner_require(key not in result)
        result[key] = value
    return result

def native_runner_elf(data):
    native_runner_require(len(data) >= 64 and data[:7] == b"\x7fELF\x02\x01\x01" and
                          struct.unpack_from("<H", data, 16)[0] in (2, 3) and struct.unpack_from("<H", data, 18)[0] == 62)

def native_runner_digest(data, expected):
    native_runner_require(re.fullmatch(r"[0-9a-f]{64}", expected) and hashlib.sha256(data).hexdigest() == expected)

def native_runner_install(path, data, mode):
    descriptor, temporary = tempfile.mkstemp(prefix=".native-runner-install-", dir=os.path.dirname(path))
    try:
        with os.fdopen(descriptor, "wb") as target:
            os.fchmod(target.fileno(), mode)
            target.write(data)
            target.flush()
            os.fsync(target.fileno())
        os.link(temporary, path)  # Atomic no-replace publication, even after preflight.
        info = os.lstat(path)
        created.append((path, info.st_dev, info.st_ino))
    finally:
        os.unlink(temporary)
    descriptor = os.open(os.path.dirname(path), os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)

try:
    parser = argparse.ArgumentParser(description="Static native runner preflight/install only; never executes the runner")
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--check", action="store_true")
    action.add_argument("--install", action="store_true")
    for name in ("binary", "binary-sha256", "environment", "baseline-sha256"):
        parser.add_argument("--" + name, required=True)
    args = parser.parse_args()
    native_runner_require(re.fullmatch(r"[0-9a-f]{64}", args.baseline_sha256))
    phase = "platform"
    native_runner_require(os.geteuid() == OWNER and platform.system() == "Linux" and platform.machine() == "x86_64")
    release_info = pathlib.Path("/etc/os-release").read_text()
    # Hosts from docs/install/os-support-matrix.md; RHEL family compares the major.
    release_id = re.search(r'^ID=["\']?([a-z]+)["\']?$', release_info, re.M)
    release_version = re.search(r'^VERSION_ID=["\']?([0-9.]+)["\']?$', release_info, re.M)
    native_runner_require(release_id and release_version)
    release_key = (release_id.group(1), release_version.group(1).split(".", 1)[0]
                   if release_id.group(1) in ("rocky", "almalinux", "rhel") else release_version.group(1))
    native_runner_require(release_key in {("ubuntu", "24.04"), ("ubuntu", "22.04"), ("ubuntu", "20.04"), ("debian", "10"), ("debian", "11"), ("debian", "12"), ("debian", "13"),
                                          ("rocky", "8"), ("rocky", "9"), ("rocky", "10"), ("almalinux", "8"),
                                          ("almalinux", "9"), ("almalinux", "10"), ("rhel", "8"), ("rhel", "9"), ("rhel", "10")})
    phase = "runner_input"
    binary = native_runner_file(args.binary, 285229182, modes=(0o700, 0o755))
    native_runner_digest(binary, args.binary_sha256)
    native_runner_elf(binary)
    phase = "environment"
    encoded_environment = native_runner_file(args.environment, 16384, secret=True)
    environment = {}
    for line in encoded_environment.decode("ascii").splitlines():
        if not line or line.startswith("#"):
            continue
        native_runner_require(re.fullmatch(r"[A-Z0-9_]+=[A-Za-z0-9_./:@%?=+\[\]\-]+", line))
        key, value = line.split("=", 1)
        native_runner_require(key not in environment)
        environment[key] = value
    fixed = {
        "CONTROL_UPGRADE_TARGET": "native-standalone", "CONTROL_UPGRADE_ONESHOT": "false",
        "CONTROL_UPGRADE_STATE_DIR": STATE, "CONTROL_UPGRADE_RELEASE_ROOT": RELEASE,
        "CONTROL_UPGRADE_PLAN_LKG_FILE": STATE + "/last-known-plan.json",
        "CDNCA_NATIVE_UPGRADE_STATUS_FILE": STATUS + "/status.json",
        "CDNCA_NATIVE_UPGRADE_MAINTENANCE_FILE": MAINTENANCE + "/maintenance.json",
        "CDNCA_NATIVE_UPGRADE_RELEASE_LOCK_FILE": LOCK,
        "CDNCA_NATIVE_UPGRADE_SOURCE_GIT_DIR": STATE + "/source.git",
    }
    signed = "CDNCA_NATIVE_UPGRADE_ARTIFACT_TRUST_FILE" in environment
    if signed:
        del fixed["CDNCA_NATIVE_UPGRADE_SOURCE_GIT_DIR"]
        fixed["CDNCA_NATIVE_UPGRADE_ARTIFACT_TRUST_FILE"] = STATE + "/artifact-trust.json"
    # Optional operator HTTPS trust for the console index check only; the path is fixed.
    if "CDNCA_NATIVE_UPGRADE_WEB_CA_FILE" in environment:
        fixed["CDNCA_NATIVE_UPGRADE_WEB_CA_FILE"] = CONFIG + "/web-ca.pem"
    credentials = ["INSTALLATION_ID", "TRUST", "INTERNAL_TOKEN", "PLAN_SOURCE_CA", "PLAN_SOURCE_CERT", "PLAN_SOURCE_KEY"]
    durations = {"PLAN_SOURCE_TIMEOUT": 60000, "POLL_INTERVAL": 60000, "STEP_TIMEOUT": 1800000, "HEALTH_TIMEOUT": 600000}
    urls = ["CONTROL_HEALTH", "GATEWAY_HEALTH", "WEB_INDEX"]
    required = set(fixed) | {"CONTROL_UPGRADE_" + name + "_FILE" for name in credentials} | {
        "CONTROL_UPGRADE_" + name for name in durations} | {"CDNCA_NATIVE_UPGRADE_" + name + "_URL" for name in urls} | {
        "CONTROL_UPGRADE_PROTOCOL_VERSION", "CONTROL_UPGRADE_PLAN_SOURCE_MAX_BYTES", "CONTROL_UPGRADE_PLAN_SOURCE_URL",
        "CDNCA_NATIVE_UPGRADE_CONTROL_UNIT", "CDNCA_NATIVE_UPGRADE_GATEWAY_UNIT"}
    native_runner_require(set(environment) == required and all(environment[key] == value for key, value in fixed.items()))
    for name, maximum in durations.items():
        value = re.fullmatch(r"([1-9][0-9]{0,8})(ms|s|m)", environment["CONTROL_UPGRADE_" + name])
        native_runner_require(value and 1 <= int(value[1]) * {"ms": 1, "s": 1000, "m": 60000}[value[2]] <= maximum)
    for name, minimum, maximum in [("PROTOCOL_VERSION", 1, 2147483647), ("PLAN_SOURCE_MAX_BYTES", 1024, 2097152)]:
        value = environment["CONTROL_UPGRADE_" + name]
        native_runner_require(re.fullmatch(r"[1-9][0-9]{0,9}", value) and minimum <= int(value) <= maximum)
    from urllib.parse import urlsplit
    plan = urlsplit(environment["CONTROL_UPGRADE_PLAN_SOURCE_URL"])
    native_runner_require(plan.scheme == "https" and plan.hostname and not plan.username and not plan.password and
                          not plan.query and not plan.fragment and "%" not in plan.netloc + plan.path and
                          plan.path == "/v1/internal/control-upgrade/plan" and (plan.port is None or 1 <= plan.port <= 65535))
    try:
        address = ipaddress.ip_address(plan.hostname)
    except ValueError:
        address = None
    native_runner_require(address is None or (address.is_global and not address.is_multicast) or plan.hostname in ("127.0.0.1", "::1"))
    for name in urls:
        url = urlsplit(environment["CDNCA_NATIVE_UPGRADE_" + name + "_URL"])
        native_runner_require(url.hostname and not url.username and not url.password and not url.query and not url.fragment and
                              (url.port is None or 1 <= url.port <= 65535) and
                              (url.scheme == "https" or (url.scheme == "http" and url.hostname in ("localhost", "127.0.0.1", "::1"))))
    units = [environment["CDNCA_NATIVE_UPGRADE_" + name + "_UNIT"] for name in ("CONTROL", "GATEWAY")]
    native_runner_require(units[0] != units[1] and all(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.@-]{0,126}\.service", value) for value in units))
    phase = "credentials"
    material = {}
    for name in credentials:
        path = environment["CONTROL_UPGRADE_" + name + "_FILE"]
        native_runner_require(path.startswith(CONFIG + "/"))
        material[name] = native_runner_file(path, secret=name in ("INTERNAL_TOKEN", "PLAN_SOURCE_KEY"))
    installation = material["INSTALLATION_ID"].decode("ascii").strip()
    native_runner_require(str(uuid.UUID(installation)) == installation and uuid.UUID(installation).int != 0)
    token = material["INTERNAL_TOKEN"].decode("ascii").strip()
    native_runner_require(32 <= len(token) <= 256 and re.fullmatch(r"[!-~]+", token))
    trust = json.loads(material["TRUST"], object_pairs_hook=native_runner_json)
    native_runner_require(set(trust) == {"keys"} and isinstance(trust["keys"], list) and trust["keys"])
    seen = set()
    for key in trust["keys"]:
        native_runner_require(set(key) == {"key_id", "public_key"} and isinstance(key["key_id"], str) and
                              re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", key["key_id"]) and key["key_id"] not in seen and
                              isinstance(key["public_key"], str) and re.fullmatch(r"[A-Za-z0-9_-]{43}", key["public_key"]))
        public = base64.urlsafe_b64decode(key["public_key"] + "=")
        native_runner_require(len(public) == 32 and base64.urlsafe_b64encode(public).decode().rstrip("=") == key["public_key"])
        seen.add(key["key_id"])
    phase = "certificates"
    certificate_paths = [environment["CONTROL_UPGRADE_PLAN_SOURCE_" + part + "_FILE"] for part in ("CA", "CERT", "KEY")]
    for path, extension, expected in [(certificate_paths[0], "basicConstraints", b"CA:TRUE"),
                                      (certificate_paths[1], "extendedKeyUsage", b"TLS Web Client Authentication")]:
        extension_value = subprocess.check_output(["openssl", "x509", "-in", path, "-noout", "-ext", extension], stderr=subprocess.DEVNULL, timeout=15)
        native_runner_require(expected in extension_value)
        dates = subprocess.check_output(["openssl", "x509", "-in", path, "-noout", "-dates"], stderr=subprocess.DEVNULL, timeout=15)
        window = [datetime.datetime.strptime(line.split("=", 1)[1], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=datetime.timezone.utc)
                  for line in dates.decode("ascii").splitlines()]
        native_runner_require(len(window) == 2 and window[0] <= datetime.datetime.now(datetime.timezone.utc) < window[1])
    if "CDNCA_NATIVE_UPGRADE_WEB_CA_FILE" in fixed:
        web_ca = native_runner_file(fixed["CDNCA_NATIVE_UPGRADE_WEB_CA_FILE"], 1048576, modes=(0o444,))
        blocks = re.findall(rb"-----BEGIN CERTIFICATE-----\n[A-Za-z0-9+/=\n]+-----END CERTIFICATE-----\n?", web_ca)
        native_runner_require(blocks and b"".join(blocks).strip() == web_ca.strip() and len(blocks) <= 16)
        subprocess.check_output(["openssl", "x509", "-in", fixed["CDNCA_NATIVE_UPGRADE_WEB_CA_FILE"], "-noout"],
                                stderr=subprocess.DEVNULL, timeout=15)
    cert_public = subprocess.check_output(["openssl", "x509", "-in", certificate_paths[1], "-pubkey", "-noout"], stderr=subprocess.DEVNULL, timeout=15)
    key_public = subprocess.check_output(["openssl", "pkey", "-in", certificate_paths[2], "-passin", "pass:", "-pubout"], stderr=subprocess.DEVNULL, timeout=15)
    native_runner_require(cert_public == key_public)
    # Full archive and file inventory verification remains the baseline helper's job.
    phase = "baseline_presence"
    native_runner_directory(RELEASE + "/releases")
    native_runner_directory(RELEASE + "/artifacts")
    current = os.lstat(RELEASE + "/current")
    target = RELEASE + "/releases/" + args.baseline_sha256
    native_runner_require(stat.S_ISLNK(current.st_mode) and current.st_uid == OWNER and os.readlink(RELEASE + "/current") == target)
    native_runner_directory(target)
    native_runner_digest(native_runner_file(RELEASE + "/artifacts/" + args.baseline_sha256 + ".tar", 285229182), args.baseline_sha256)
    encoded_manifest = native_runner_file(target + "/release.manifest.json", 8388608, modes=(0o644,))
    manifest = json.loads(encoded_manifest, object_pairs_hook=native_runner_json)
    native_runner_require(isinstance(manifest, dict) and manifest.get("schema") ==
                          ("cdnca.native-management.release/v2" if signed else "cdnca.native-management.release/v1"))
    native_runner_file(target + "/static/web/index.html", modes=(0o644,))
    for name in ("control-api", "agent-gateway"):
        native_runner_elf(native_runner_file(target + "/bin/" + name, 285229182, modes=(0o755,)))
    phase = "runtime_paths"
    native_runner_require(stat.S_IMODE(native_runner_directory(STATE).st_mode) == 0o700)
    proof_path = STATE + ("/artifact-trust.json" if signed else "/source.git")
    if signed:
        trust = json.loads(native_runner_file(proof_path, 65536, modes=(0o600,)), object_pairs_hook=native_runner_json)
        native_runner_require(isinstance(trust, dict) and set(trust) == {"version", "keys"} and type(trust["version"]) is int and
                              trust["version"] == 1 and isinstance(trust["keys"], list) and 1 <= len(trust["keys"]) <= 32)
        keys = {}
        for key in trust["keys"]:
            native_runner_require(isinstance(key, dict) and set(key) == {"key_id", "public_key_pem"} and
                                  isinstance(key["key_id"], str) and re.fullmatch(r"[A-Za-z0-9._-]{1,128}", key["key_id"]) and
                                  key["key_id"] not in keys and isinstance(key["public_key_pem"], str) and 0 < len(key["public_key_pem"]) <= 4096)
            match = re.fullmatch(r"-----BEGIN PUBLIC KEY-----\n([A-Za-z0-9+/=\n]+)-----END PUBLIC KEY-----\n?", key["public_key_pem"])
            native_runner_require(match is not None)
            public = base64.b64decode(match[1].replace("\n", ""), validate=True)
            native_runner_require(len(public) == 44 and public[:12] == bytes.fromhex("302a300506032b6570032100"))
            keys[key["key_id"]] = key["public_key_pem"]
        key_id = manifest.get("key_id")
        native_runner_require(isinstance(key_id, str) and key_id in keys)
        encoded_signature = native_runner_strip_newline(native_runner_file(target + "/release.manifest.sig", 128, modes=(0o644,)))
        signature = base64.b64decode(encoded_signature, validate=True)
        native_runner_require(len(signature) == 64 and base64.b64encode(signature) == encoded_signature)
        with tempfile.TemporaryDirectory(prefix=".native-runner-proof-", dir=STATE) as temporary:
            keyfile, sigfile, message = (pathlib.Path(temporary) / name for name in ("public.pem", "signature", "message"))
            keyfile.write_text(keys[key_id], encoding="ascii")
            sigfile.write_bytes(signature)
            message.write_bytes(b"cdnca.native-management.release/v2\n" + encoded_manifest)
            subprocess.run(["openssl", "pkeyutl", "-verify", "-pubin", "-inkey", str(keyfile), "-rawin", "-in", str(message),
                            "-sigfile", str(sigfile)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15)
    else:
        native_runner_directory(proof_path)
    native_runner_require(not os.path.lexists(STATE + "/state.json") and not os.path.lexists(STATE + "/last-known-plan.json"))
    status, maintenance = native_runner_directory(STATUS), native_runner_directory(MAINTENANCE)
    native_runner_require(stat.S_IMODE(status.st_mode) == stat.S_IMODE(maintenance.st_mode) == 0o2750 and status.st_gid == maintenance.st_gid)
    active = json.loads(native_runner_file(MAINTENANCE + "/maintenance.json", 4096, modes=(0o600, 0o640)), object_pairs_hook=native_runner_json)
    native_runner_require(set(active) == {"schema", "installation_id", "phase", "plan_id", "observed_at"} and
                          active["schema"] == "cdnca.native-management.maintenance/v1" and active["installation_id"] == installation and
                          active["phase"] == "active" and isinstance(active["plan_id"], str) and isinstance(active["observed_at"], str))
    # RFC 3339 with an explicit offset; fromisoformat is 3.7+ and rejects Go's
    # nanosecond fractions before 3.11, so the fields are checked directly.
    stamp = re.fullmatch(r"(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(\.\d{1,9})?(Z|[+-]\d{2}:\d{2})", active["observed_at"])
    native_runner_require(stamp)
    observed = datetime.datetime(*map(int, stamp.groups()[:6]))
    native_runner_require(observed.year > 1)
    for path in (LOCK, MAINTENANCE + "/maintenance.json.lock"):
        native_runner_file(path, 4096, modes=(0o600, 0o640), empty=True)
    phase = "target_collision"
    for path in (BINARY, ENVIRONMENT, UNIT_PATH, TMPFILES_PATH):
        native_runner_directory(os.path.dirname(path))
        native_runner_require(not os.path.lexists(path))
    for directory in ("/etc/tmpfiles.d", "/run/tmpfiles.d", "/usr/lib/tmpfiles.d", "/lib/tmpfiles.d"):
        native_runner_require(not os.path.lexists(directory + "/" + TMPFILES_NAME))
    for directory in ("/etc/systemd/system", "/run/systemd/system", "/usr/lib/systemd/system", "/lib/systemd/system"):
        for name in (UNIT, "cdnca-control-upgrade-runner.service"):
            native_runner_require(not os.path.lexists(directory + "/" + name) and not os.path.lexists(directory + "/" + name + ".d"))
            native_runner_require(not any(pathlib.Path(directory).glob("*.wants/" + name)) and
                                  not any(pathlib.Path(directory).glob("*.requires/" + name)))
    # ':' changes ownership/mode only for newly created inodes; '!' is boot-only.
    # Existing links, insecure modes or extra links are rejected by the read-only
    # service precheck, never repaired or unlinked while a writer may hold a lock.
    tmpfiles = ("# Create only at boot; never replace, truncate, or repair an existing inode.\n"
                f"d! {STATUS} :2750 :{OWNER:d} :{status.st_gid:d} - -\n"
                f"f! {LOCK} :0600 :{OWNER:d} :{status.st_gid:d} - -\n")
    boot_check = (
        "import os,stat; "
        f"paths=({LOCK!r},{STATUS!r},{MAINTENANCE!r}); "
        "assert all(os.path.realpath(p)==p for p in paths); "
        "dirs=[os.lstat(p) for p in paths[1:]]; "
        f"assert all(stat.S_ISDIR(s.st_mode) and s.st_uid=={OWNER:d} and s.st_gid=={status.st_gid:d} "
        "and stat.S_IMODE(s.st_mode)==0o2750 for s in dirs); "
        f"fd=os.open({LOCK!r},os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK); s=os.fstat(fd); "
        f"assert stat.S_ISREG(s.st_mode) and s.st_uid=={OWNER:d} and s.st_gid=={status.st_gid:d} "
        "and s.st_nlink==1 and stat.S_IMODE(s.st_mode) in (0o600,0o640); os.close(fd)")
    unit = f"""[Unit]
Description=CDNCA signed native management upgrade runner
After=network-online.target systemd-tmpfiles-setup.service {units[0]} {units[1]}
Requires=systemd-tmpfiles-setup.service
Wants=network-online.target
StartLimitIntervalSec=300
StartLimitBurst=3

[Service]
Type=simple
User=root
Group={status.st_gid:d}
EnvironmentFile={ENVIRONMENT}
ExecStartPre=/usr/bin/python3 -I -c "{boot_check}"
ExecStart={BINARY}
RuntimeDirectory=cdnca-upgrade
RuntimeDirectoryMode=2750
RuntimeDirectoryPreserve=yes
Restart=on-failure
RestartSec=5s
TimeoutStopSec=30s
UMask=0077
NoNewPrivileges=true
CapabilityBoundingSet=
AmbientCapabilities=
PrivateTmp=true
PrivateDevices=true
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectKernelLogs=true
ProtectControlGroups=true
ProtectProc=invisible
ProcSubset=all
RestrictSUIDSGID=true
RestrictRealtime=true
RestrictNamespaces=true
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
LockPersonality=true
MemoryDenyWriteExecute=true
SystemCallFilter=@system-service
SystemCallErrorNumber=EPERM
ReadWritePaths={RELEASE} {STATE} {STATUS} {MAINTENANCE} {LOCK}
ReadOnlyPaths={CONFIG} {proof_path} {BINARY}

[Install]
WantedBy=multi-user.target
"""
    if args.install:
        phase = "publication"
        native_runner_install(BINARY, binary, 0o755)
        native_runner_install(ENVIRONMENT, encoded_environment, 0o600)
        native_runner_install(TMPFILES_PATH, tmpfiles.encode("ascii"), 0o644)
        native_runner_install(UNIT_PATH, unit.encode("ascii"), 0o644)
        subprocess.run(["systemctl", "daemon-reload"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)
    print(json.dumps({"status": "installed_not_started" if args.install else "static_preflight_passed",
                      "remaining_verification": ["signed_artifact_provenance", "complete_baseline", "server_mtls", "live_runner_probe"]}))
except Exception:
    for path, device, inode in reversed(created):
        if os.path.lexists(path) and (os.lstat(path).st_dev, os.lstat(path).st_ino) == (device, inode):
            os.unlink(path)
    print("native runner install rejected: " + phase, file=sys.stderr)
    sys.exit(1)
PY
}

native_runner_installer_main "$@"
