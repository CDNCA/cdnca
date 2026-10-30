#!/usr/bin/env python3
"""Fresh supported amd64 hosts (os-support-matrix) native-upgrade PKI/configuration, never activation.

prepare requires an absent /etc/cdnca-upgrade; failures preserve partial files.
check is read-only and requires certificates valid for at least another day.
This does not install a global CA, alter nginx, start services, create baseline
or runner state, or prove live mTLS. The caller must separately deny the internal
plan route on public listeners and verify the actual nginx/runner endpoints.
"""

import argparse
import base64
import ipaddress
import json
import os
from pathlib import Path
import platform
import re
import secrets
import stat
import subprocess
import sys
import tempfile
from urllib.parse import urlsplit
import uuid

OWNER = 0
CONFIG = Path("/etc/cdnca-upgrade")
TRUST_SOURCE = Path("/etc/cdnca-control/entitlement-trusted-keys.json")
OPENSSL = "/usr/bin/openssl"


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


def secure_directory(path):
    require(path.is_absolute() and str(path) == os.path.normpath(path), "invalid directory")
    for parent in reversed((path, *path.parents)):
        info = parent.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid in (0, OWNER) and not info.st_mode & 0o022,
                "unsafe directory")


def read_file(path, private=True):
    secure_directory(path.parent)
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), "rb") as source:
        before = os.fstat(source.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_uid == OWNER and before.st_nlink == 1 and
                not before.st_mode & 0o7022 and 0 < before.st_size <= 1 << 20 and
                (not private or stat.S_IMODE(before.st_mode) == 0o600), "unsafe configuration file")
        data = source.read((1 << 20) + 1)
        after = os.fstat(source.fileno())
        require(len(data) == before.st_size and all(getattr(before, key) == getattr(after, key) for key in
                ("st_dev", "st_ino", "st_uid", "st_gid", "st_mode", "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns")),
                "configuration changed during read")
        return data


def write_file(path, data, mode=0o600):
    secure_directory(path.parent)
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600), "wb") as target:
        os.fchmod(target.fileno(), mode)
        target.write(data)
        target.flush()
        os.fsync(target.fileno())
    descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def openssl(*arguments):
    # SSL_CERT_DIR/FILE point nowhere: OpenSSL 1.0.2 has no -no-CApath and would
    # otherwise add the system store to every verify.
    result = subprocess.run([OPENSSL, *map(str, arguments)], stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=30,
                            env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C", "OPENSSL_CONF": "/dev/null",
                                 "SSL_CERT_DIR": "/nonexistent", "SSL_CERT_FILE": "/nonexistent"})
    require(result.returncode == 0, "OpenSSL validation failed")
    return result.stdout


def openssl_version():
    """(major, minor, patch) of the system OpenSSL; LibreSSL and others are rejected."""
    match = re.match(rb"OpenSSL ([0-9]+)\.([0-9]+)\.([0-9]+)", openssl("version"))
    require(match, "OpenSSL is required")
    return tuple(int(part) for part in match.groups())


# x509 -ext exists only in OpenSSL 1.1.1+; parse the stable -text layout instead.
EXTENSION_LABELS = {"basicConstraints": "X509v3 Basic Constraints", "keyUsage": "X509v3 Key Usage",
                    "extendedKeyUsage": "X509v3 Extended Key Usage", "subjectAltName": "X509v3 Subject Alternative Name"}


def certificate_extension(certificate, name):
    lines = openssl("x509", "-in", certificate, "-noout", "-text").decode("ascii").splitlines()
    label = EXTENSION_LABELS[name]
    for index, line in enumerate(lines):
        header = line.strip()
        if header in (label + ": critical", label + ":"):
            indent = len(line) - len(line.lstrip())
            values = []
            for value in lines[index + 1:]:
                if len(value) - len(value.lstrip()) <= indent:
                    break
                values.append(value.strip())
            return (header,) + tuple(values)
    return ()


def validate_options(installation_id, web_index_url):
    require(os.geteuid() == OWNER and platform.system() == "Linux" and platform.machine() == "x86_64" and
            supported_host(os_release()),
            "requires root amd64 Ubuntu 24.04/22.04/20.04, Debian 10-13 or Rocky/AlmaLinux/RHEL 8/9/10")
    require(str(uuid.UUID(installation_id)) == installation_id and uuid.UUID(installation_id).int != 0, "invalid installation ID")
    require(re.fullmatch(r"https://[A-Za-z0-9./:\[\]_-]+", web_index_url), "invalid HTTPS index URL")
    parsed = urlsplit(web_index_url)
    require(parsed.scheme == "https" and parsed.hostname and not parsed.netloc.endswith(":") and not parsed.username and not parsed.password and
            not parsed.query and not parsed.fragment and (parsed.port is None or 1 <= parsed.port <= 65535) and
            all(part not in (".", "..") for part in parsed.path.split("/")) and "//" not in parsed.path,
            "invalid HTTPS index URL")
    try:
        ipaddress.ip_address(parsed.hostname)
    except ValueError:
        require(len(parsed.hostname) <= 253 and all(re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", label)
                                                  for label in parsed.hostname.split(".")), "invalid index host")
    secure_directory(CONFIG.parent)
    require(openssl_version() >= (1, 0, 2), "OpenSSL 1.0.2 or newer is required")


def decode_trust(data):
    def unique(pairs):
        value = {}
        for key, member in pairs:
            require(key not in value, "duplicate trusted-key JSON member")
            value[key] = member
        return value
    value = json.loads(data, object_pairs_hook=unique)
    require(isinstance(value, dict) and set(value) == {"keys"} and isinstance(value["keys"], list) and
            1 <= len(value["keys"]) <= 1024, "invalid trusted-key document")
    seen = set()
    for key in value["keys"]:
        require(isinstance(key, dict) and set(key) == {"key_id", "public_key"} and isinstance(key["key_id"], str) and
                re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", key["key_id"]) and key["key_id"] not in seen and
                isinstance(key["public_key"], str) and re.fullmatch(r"[A-Za-z0-9_-]{43}", key["public_key"]), "invalid trusted key")
        public = base64.b64decode(key["public_key"] + "=", altchars=b"-_", validate=True)
        require(len(public) == 32 and base64.urlsafe_b64encode(public).decode().rstrip("=") == key["public_key"], "noncanonical public key")
        seen.add(key["key_id"])
    return (json.dumps(value, separators=(",", ":")) + "\n").encode("ascii")


def decode_artifact_trust(data):
    def unique(pairs):
        value = {}
        for key, member in pairs:
            require(key not in value, "duplicate artifact-trust JSON member")
            value[key] = member
        return value
    value = json.loads(data, object_pairs_hook=unique)
    require(isinstance(value, dict) and set(value) == {"version", "keys"} and type(value["version"]) is int and
            value["version"] == 1 and isinstance(value["keys"], list) and 1 <= len(value["keys"]) <= 32, "invalid artifact trust")
    seen = set()
    for key in value["keys"]:
        require(isinstance(key, dict) and set(key) == {"key_id", "public_key_pem"} and isinstance(key["key_id"], str) and
                re.fullmatch(r"[A-Za-z0-9._-]{1,128}", key["key_id"]) and key["key_id"] not in seen and
                isinstance(key["public_key_pem"], str) and 0 < len(key["public_key_pem"]) <= 4096, "invalid artifact trust key")
        match = re.fullmatch(r"-----BEGIN PUBLIC KEY-----\n([A-Za-z0-9+/=\n]+)-----END PUBLIC KEY-----\n?", key["public_key_pem"])
        require(match is not None, "invalid artifact public key")
        public = base64.b64decode(match[1].replace("\n", ""), validate=True)
        require(len(public) == 44 and public[:12] == bytes.fromhex("302a300506032b6570032100"), "artifact key must be Ed25519")
        seen.add(key["key_id"])
    return value


WEB_CA = "web-ca.pem"


def decode_web_ca(data):
    """Operator HTTPS trust anchors for the console index check: PEM certificates only."""
    blocks = re.findall(rb"-----BEGIN CERTIFICATE-----\n[A-Za-z0-9+/=\n]+-----END CERTIFICATE-----\n?", data)
    require(blocks and b"".join(blocks).strip() == data.strip() and len(blocks) <= 16, "invalid web CA file")
    for block in blocks:
        with tempfile.NamedTemporaryFile(prefix="cdnca-web-ca-") as scratch:
            scratch.write(block)
            scratch.flush()
            openssl("x509", "-in", scratch.name, "-noout")
    return data


def configurations(web_index_url, artifact_trust_file=None, web_ca_file=None):
    runner = {
        "CONTROL_UPGRADE_TARGET": "native-standalone", "CONTROL_UPGRADE_ONESHOT": "false",
        "CONTROL_UPGRADE_STATE_DIR": "/var/lib/cdnca-upgrade", "CONTROL_UPGRADE_RELEASE_ROOT": "/data/cdnca-native-root/cdnca",
        "CONTROL_UPGRADE_PLAN_LKG_FILE": "/var/lib/cdnca-upgrade/last-known-plan.json",
        "CDNCA_NATIVE_UPGRADE_STATUS_FILE": "/run/cdnca-upgrade/status.json",
        "CDNCA_NATIVE_UPGRADE_MAINTENANCE_FILE": "/var/lib/cdnca-native-upgrade-maintenance/maintenance.json",
        "CDNCA_NATIVE_UPGRADE_RELEASE_LOCK_FILE": "/run/lock/cdnca-management-release.lock",
        "CDNCA_NATIVE_UPGRADE_SOURCE_GIT_DIR": "/var/lib/cdnca-upgrade/source.git",
        "CONTROL_UPGRADE_PROTOCOL_VERSION": "1", "CONTROL_UPGRADE_PLAN_SOURCE_MAX_BYTES": "1048576",
        "CONTROL_UPGRADE_PLAN_SOURCE_URL": "https://127.0.0.1:9445/v1/internal/control-upgrade/plan",
        "CONTROL_UPGRADE_PLAN_SOURCE_TIMEOUT": "10s", "CONTROL_UPGRADE_POLL_INTERVAL": "5s",
        "CONTROL_UPGRADE_STEP_TIMEOUT": "3m", "CONTROL_UPGRADE_HEALTH_TIMEOUT": "2m",
        "CDNCA_NATIVE_UPGRADE_CONTROL_UNIT": "cdnca-control-api.service",
        "CDNCA_NATIVE_UPGRADE_GATEWAY_UNIT": "cdnca-agent-gateway.service",
        "CDNCA_NATIVE_UPGRADE_CONTROL_HEALTH_URL": "http://127.0.0.1:8080/health/ready",
        "CDNCA_NATIVE_UPGRADE_GATEWAY_HEALTH_URL": "http://127.0.0.1:8082/health/ready",
        "CDNCA_NATIVE_UPGRADE_WEB_INDEX_URL": web_index_url,
    }
    for name, filename in {"INSTALLATION_ID": "installation-id", "TRUST": "trusted-keys.json", "INTERNAL_TOKEN": "plan-source-token",
                           "PLAN_SOURCE_CA": "plan-source-ca.pem", "PLAN_SOURCE_CERT": "plan-source-client.pem",
                           "PLAN_SOURCE_KEY": "plan-source-client-key.pem"}.items():
        runner["CONTROL_UPGRADE_" + name + "_FILE"] = str(CONFIG / filename)
    if artifact_trust_file is not None:
        decode_artifact_trust(read_file(artifact_trust_file, private=False))
        del runner["CDNCA_NATIVE_UPGRADE_SOURCE_GIT_DIR"]
        runner["CDNCA_NATIVE_UPGRADE_ARTIFACT_TRUST_FILE"] = "/var/lib/cdnca-upgrade/artifact-trust.json"
    if web_ca_file is not None:
        decode_web_ca(read_file(web_ca_file, private=False))
        runner["CDNCA_NATIVE_UPGRADE_WEB_CA_FILE"] = str(CONFIG / WEB_CA)
    api = {"CDNCA_NATIVE_UPGRADE_ENABLED": "true", "CDNCA_NATIVE_UPGRADE_STATUS_FILE": runner["CDNCA_NATIVE_UPGRADE_STATUS_FILE"],
           "CDNCA_NATIVE_UPGRADE_STATE_FILE": runner["CDNCA_NATIVE_UPGRADE_STATUS_FILE"] + ".state.json",
           "CDNCA_NATIVE_UPGRADE_MAINTENANCE_FILE": runner["CDNCA_NATIVE_UPGRADE_MAINTENANCE_FILE"],
           "CONTROL_UPGRADE_PLAN_WRITER_ENABLED": "false", "CONTROL_UPGRADE_SYSTEMD_PLAN_SOURCE_ENABLED": "true",
           "CONTROL_UPGRADE_PROTOCOL_VERSION": "1", "CONTROL_UPGRADE_INTERNAL_TOKEN_FILE": str(CONFIG / "plan-source-token")}
    result = {name: "".join(key + "=" + value + "\n" for key, value in values.items()).encode("ascii")
              for name, values in (("runner-input.env", runner), ("api.env", api))}
    result["plan-source-nginx.conf"] = f"""# Include inside http; public listeners must separately deny /v1/internal.
server {{
    listen 127.0.0.1:9445 ssl;
    server_name 127.0.0.1;
    ssl_protocols TLSv1.3;
    ssl_certificate {CONFIG}/plan-source-server.pem;
    ssl_certificate_key {CONFIG}/plan-source-server-key.pem;
    ssl_client_certificate {CONFIG}/plan-source-ca.pem;
    ssl_verify_client on;
    ssl_verify_depth 1;
    ssl_session_cache off;
    ssl_session_tickets off;
    access_log off;
    error_log stderr warn;
    location = /v1/internal/control-upgrade/plan {{
        if ($request_method != GET) {{ return 405; }}
        if ($request_uri != "/v1/internal/control-upgrade/plan") {{ return 404; }}
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header Host 127.0.0.1;
        proxy_set_header Authorization $http_authorization;
        proxy_set_header Connection "";
        proxy_pass_request_body off;
        proxy_set_header Content-Length "";
        proxy_connect_timeout 3s;
        proxy_read_timeout 10s;
        proxy_redirect off;
    }}
    location / {{ return 404; }}
}}
""".encode("ascii")
    return result


def validate_certificates():
    public_keys = set()
    ca = CONFIG / "plan-source-ca.pem"
    for role in ("ca", "server", "client"):
        certificate, key = CONFIG / ("plan-source-" + role + ".pem"), CONFIG / ("plan-source-" + role + "-key.pem")
        for path in (certificate, key):
            read_file(path)
        public = openssl("pkey", "-in", key, "-passin", "pass:", "-pubout")
        require(public == openssl("x509", "-in", certificate, "-pubkey", "-noout") and public not in public_keys,
                "certificate key mismatch or reuse")
        require(b"ASN1 OID: prime256v1" in openssl("pkey", "-in", key, "-passin", "pass:", "-text_pub", "-noout"), "unexpected key curve")
        public_keys.add(public)
        openssl("x509", "-in", certificate, "-noout", "-checkend", "86400")
        extensions = {"basicConstraints": ("X509v3 Basic Constraints: critical", "CA:TRUE, pathlen:0" if role == "ca" else "CA:FALSE"),
                      "keyUsage": ("X509v3 Key Usage: critical", "Certificate Sign, CRL Sign" if role == "ca" else "Digital Signature")}
        if role != "ca":
            extensions["extendedKeyUsage"] = ("X509v3 Extended Key Usage:", "TLS Web Server Authentication" if role == "server" else "TLS Web Client Authentication")
        if role == "server":
            extensions["subjectAltName"] = ("X509v3 Subject Alternative Name:", "IP Address:127.0.0.1")
        for name, expected in extensions.items():
            require(certificate_extension(certificate, name) == expected, "unexpected certificate extensions")
        arguments = ["verify", "-CAfile", ca, "-x509_strict", "-check_ss_sig"]
        version = openssl_version()
        if version >= (1, 1, 0):
            arguments.append("-no-CApath")
        if version >= (3, 0, 0):
            arguments.append("-no-CAstore")
        if role != "ca":
            arguments += ["-purpose", "sslserver" if role == "server" else "sslclient"]
        if role == "server":
            arguments += ["-verify_ip", "127.0.0.1"]
        openssl(*arguments, certificate)


def check(installation_id, web_index_url, artifact_trust_file=None, web_ca_file=None):
    validate_options(installation_id, web_index_url)
    secure_directory(CONFIG)
    require(stat.S_IMODE(CONFIG.stat().st_mode) == 0o700, "configuration directory must be private")
    require(read_file(CONFIG / "installation-id") == (installation_id + "\n").encode("ascii"), "installation binding mismatch")
    require(decode_trust(read_file(CONFIG / "trusted-keys.json")) == decode_trust(read_file(TRUST_SOURCE, private=False)), "trusted keys changed")
    require(re.fullmatch(rb"[0-9a-f]{64}\n", read_file(CONFIG / "plan-source-token")), "invalid plan source token")
    for name, expected in configurations(web_index_url, artifact_trust_file, web_ca_file).items():
        require(read_file(CONFIG / name) == expected, "configuration binding mismatch")
    if web_ca_file is not None:
        copied = read_file(CONFIG / WEB_CA, private=False)
        require(stat.S_IMODE((CONFIG / WEB_CA).lstat().st_mode) == 0o444 and copied == read_file(web_ca_file, private=False),
                "web CA binding mismatch")
    else:
        require(not os.path.lexists(CONFIG / WEB_CA), "unexpected web CA file")
    validate_certificates()
    return {"status": "configuration_checked"}


def prepare(installation_id, web_index_url, artifact_trust_file=None, web_ca_file=None):
    validate_options(installation_id, web_index_url)
    require(not os.path.lexists(CONFIG), "existing configuration; fresh prepare refused")
    trust = decode_trust(read_file(TRUST_SOURCE, private=False))
    prepared = configurations(web_index_url, artifact_trust_file, web_ca_file)
    web_ca = None if web_ca_file is None else read_file(web_ca_file, private=False)
    CONFIG.mkdir(mode=0o700)
    os.chmod(CONFIG, 0o700)
    write_file(CONFIG / "installation-id", (installation_id + "\n").encode("ascii"))
    write_file(CONFIG / "trusted-keys.json", trust)
    write_file(CONFIG / "plan-source-token", (secrets.token_hex(32) + "\n").encode("ascii"))
    # CSR + "x509 -req -extfile" works on OpenSSL 1.0.2 through 3.x; "-addext"
    # (1.1.1+) and "req -x509 -CA" (3.0+) do not. The scratch files hold only
    # public requests and extension text, never key material. OpenSSL 1.0.2
    # rejects an empty [dn] and ignores -subj under prompt=no, hence -batch.
    with tempfile.TemporaryDirectory(prefix="cdnca-plan-source-") as scratch:
        scratch = Path(scratch)
        (scratch / "req.cnf").write_text("[req]\ndistinguished_name = dn\n[dn]\nCN = Common Name\n", encoding="ascii")
        for role in ("ca", "server", "client"):
            key = CONFIG / ("plan-source-" + role + "-key.pem")
            write_file(key, openssl("genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:prime256v1",
                                    "-pkeyopt", "ec_param_enc:named_curve"))
            request = scratch / (role + ".csr")
            request.write_bytes(openssl("req", "-new", "-batch", "-config", scratch / "req.cnf", "-key", key, "-sha256",
                                        "-subj", "/CN=CDNCA Native Plan Source " + role))
            extensions = ["subjectKeyIdentifier=hash", "authorityKeyIdentifier=keyid:always"]
            arguments = ["x509", "-req", "-in", request, "-sha256", "-days", "365", "-set_serial", "0x" + secrets.token_hex(16)]
            if role == "ca":
                extensions += ["basicConstraints=critical,CA:TRUE,pathlen:0", "keyUsage=critical,keyCertSign,cRLSign"]
                arguments += ["-signkey", key]
            else:
                arguments += ["-CA", CONFIG / "plan-source-ca.pem", "-CAkey", CONFIG / "plan-source-ca-key.pem"]
                extensions += ["basicConstraints=critical,CA:FALSE", "keyUsage=critical,digitalSignature",
                               "extendedKeyUsage=" + ("serverAuth" if role == "server" else "clientAuth")]
                if role == "server":
                    extensions += ["subjectAltName=IP:127.0.0.1"]
            (scratch / (role + ".ext")).write_text("".join(line + "\n" for line in extensions), encoding="ascii")
            arguments += ["-extfile", scratch / (role + ".ext")]
            write_file(CONFIG / ("plan-source-" + role + ".pem"), openssl(*arguments))
    for name, body in prepared.items():
        write_file(CONFIG / name, body)
    if web_ca is not None:
        write_file(CONFIG / WEB_CA, web_ca, 0o444)
    check(installation_id, web_index_url, artifact_trust_file, web_ca_file)
    descriptor = os.open(CONFIG.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    return {"status": "prepared_not_started"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("prepare", "check"))
    parser.add_argument("--installation-id", required=True)
    parser.add_argument("--web-index-url", required=True)
    parser.add_argument("--artifact-trust-file", type=Path)
    parser.add_argument("--web-ca-file", type=Path)
    arguments = parser.parse_args()
    try:
        result = (prepare if arguments.action == "prepare" else check)(arguments.installation_id, arguments.web_index_url, arguments.artifact_trust_file,
                                                                  arguments.web_ca_file)
        print(json.dumps(result))
    except Exception:
        print("native upgrade configuration rejected; no service was started; preserve any partial preparation", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
